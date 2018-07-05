/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2017 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package govpn

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"chacha20"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/poly1305"
)

const (
	NonceSize       = 8
	NonceBucketSize = 256
	TagSize         = poly1305.TagSize
	// S20BS is ChaCha20's internal blocksize in bytes
	S20BS = 64
	// Maximal amount of bytes transfered with single key (4 GiB)
	MaxBytesPerKey uint64 = 1 << 32
	// Heartbeat rate, relative to Timeout
	TimeoutHeartbeat = 4
	// Minimal valid packet length
	MinPktLength = 1 + 16 + 8
	// Padding byte
	PadByte = byte(0x80)
)

func newNonces(key *[32]byte, i uint64) chan *[NonceSize]byte {
	macKey := make([]byte, 32)
	chacha20.XORKeyStream(macKey, make([]byte, 32), new([16]byte), key)
	mac, err := blake2b.New256(macKey)
	if err != nil {
		panic(err)
	}
	sum := make([]byte, mac.Size())
	nonces := make(chan *[NonceSize]byte, NonceBucketSize*3)
	go func() {
		for {
			buf := new([NonceSize]byte)
			binary.BigEndian.PutUint64(buf[:], i)
			mac.Write(buf[:])
			mac.Sum(sum[:0])
			copy(buf[:], sum)
			nonces <- buf
			mac.Reset()
			i += 2
		}
	}()
	return nonces
}

type Peer struct {
	// Statistics (they are at the beginning for correct int64 alignment)
	BytesIn         uint64
	BytesOut        uint64
	BytesPayloadIn  uint64
	BytesPayloadOut uint64
	FramesIn        uint64
	FramesOut       uint64
	FramesUnauth    uint64
	FramesDup       uint64
	HeartbeatRecv   uint64
	HeartbeatSent   uint64

	// Basic
	Addr string
	ID   *PeerID
	Conn io.Writer `json:"-"`

	// Traffic behaviour
	NoiseEnable bool
	CPR         int
	CPRCycle    time.Duration `json:"-"`
	Encless     bool
	MTU         int

	key *[SSize]byte

	// Timers
	Timeout     time.Duration `json:"-"`
	Established time.Time
	LastPing    time.Time

	// Receiver
	BusyR    sync.Mutex `json:"-"`
	bufR     []byte
	tagR     *[TagSize]byte
	keyAuthR *[SSize]byte
	nonceR   *[16]byte
	pktSizeR int

	// UDP-related
	noncesR      chan *[NonceSize]byte
	nonceRecv    [NonceSize]byte
	nonceBucketL map[[NonceSize]byte]struct{}
	nonceBucketM map[[NonceSize]byte]struct{}
	nonceBucketH map[[NonceSize]byte]struct{}

	// TCP-related
	NonceExpect  []byte `json:"-"`
	noncesExpect chan *[NonceSize]byte

	// Transmitter
	BusyT    sync.Mutex `json:"-"`
	bufT     []byte
	tagT     *[TagSize]byte
	keyAuthT *[SSize]byte
	nonceT   *[16]byte
	frameT   []byte
	noncesT  chan *[NonceSize]byte
}

func (p *Peer) String() string {
	return p.ID.String() + ":" + p.Addr
}

// Zero peer's memory state.
func (p *Peer) Zero() {
	p.BusyT.Lock()
	p.BusyR.Lock()
	SliceZero(p.key[:])
	SliceZero(p.bufR)
	SliceZero(p.bufT)
	SliceZero(p.keyAuthR[:])
	SliceZero(p.keyAuthT[:])
	p.BusyT.Unlock()
	p.BusyR.Unlock()
}

func cprCycleCalculate(conf *PeerConf) time.Duration {
	if conf.CPR == 0 {
		return time.Duration(0)
	}
	rate := conf.CPR * 1 << 10
	if conf.Encless {
		rate /= EnclessEnlargeSize + conf.MTU
	} else {
		rate /= conf.MTU
	}
	return time.Second / time.Duration(rate)
}

func newPeer(isClient bool, addr string, conn io.Writer, conf *PeerConf, key *[SSize]byte) *Peer {
	now := time.Now()
	timeout := conf.Timeout

	cprCycle := cprCycleCalculate(conf)
	noiseEnable := conf.Noise
	if conf.CPR > 0 {
		noiseEnable = true
		timeout = cprCycle
	} else {
		timeout = timeout / TimeoutHeartbeat
	}

	bufSize := S20BS + 2*conf.MTU
	if conf.Encless {
		bufSize += EnclessEnlargeSize
		noiseEnable = true
	}

	peer := Peer{
		Addr: addr,
		ID:   conf.ID,
		Conn: conn,

		NoiseEnable: noiseEnable,
		CPR:         conf.CPR,
		CPRCycle:    cprCycle,
		Encless:     conf.Encless,
		MTU:         conf.MTU,

		key: key,

		Timeout:     timeout,
		Established: now,
		LastPing:    now,

		bufR:     make([]byte, bufSize),
		bufT:     make([]byte, bufSize),
		tagR:     new([TagSize]byte),
		tagT:     new([TagSize]byte),
		keyAuthR: new([SSize]byte),
		nonceR:   new([16]byte),
		keyAuthT: new([SSize]byte),
		nonceT:   new([16]byte),
	}

	if isClient {
		peer.noncesT = newNonces(peer.key, 1+2)
		peer.noncesR = newNonces(peer.key, 0+2)
		peer.noncesExpect = newNonces(peer.key, 0+2)
	} else {
		peer.noncesT = newNonces(peer.key, 0+2)
		peer.noncesR = newNonces(peer.key, 1+2)
		peer.noncesExpect = newNonces(peer.key, 1+2)
	}

	peer.NonceExpect = make([]byte, NonceSize)
	nonce := <-peer.noncesExpect
	copy(peer.NonceExpect, nonce[:])

	var i int
	peer.nonceBucketL = make(map[[NonceSize]byte]struct{}, NonceBucketSize)
	for i = 0; i < NonceBucketSize; i++ {
		nonce = <-peer.noncesR
		peer.nonceBucketL[*nonce] = struct{}{}
	}
	peer.nonceBucketM = make(map[[NonceSize]byte]struct{}, NonceBucketSize)
	for i = 0; i < NonceBucketSize; i++ {
		nonce = <-peer.noncesR
		peer.nonceBucketM[*nonce] = struct{}{}
	}
	peer.nonceBucketH = make(map[[NonceSize]byte]struct{}, NonceBucketSize)
	for i = 0; i < NonceBucketSize; i++ {
		nonce = <-peer.noncesR
		peer.nonceBucketH[*nonce] = struct{}{}
	}

	return &peer
}

// Process incoming Ethernet packet.
// ready channel is TAPListen's synchronization channel used to tell him
// that he is free to receive new packets. Encrypted and authenticated
// packets will be sent to remote Peer side immediately.
func (p *Peer) EthProcess(data []byte) {
	if len(data) > p.MTU-1 { // 1 is for padding byte
		log.Println("Padded data packet size", len(data)+1, "is bigger than MTU", p.MTU, p)
		return
	}
	p.BusyT.Lock()

	// Zero size is a heartbeat packet
	SliceZero(p.bufT)
	if len(data) == 0 {
		p.bufT[S20BS+0] = PadByte
		p.HeartbeatSent++
	} else {
		// Copy payload to our internal buffer and we are ready to
		// accept the next one
		copy(p.bufT[S20BS:], data)
		p.bufT[S20BS+len(data)] = PadByte
		p.BytesPayloadOut += uint64(len(data))
	}

	if p.NoiseEnable && !p.Encless {
		p.frameT = p.bufT[S20BS : S20BS+p.MTU-TagSize]
	} else if p.Encless {
		p.frameT = p.bufT[S20BS : S20BS+p.MTU]
	} else {
		p.frameT = p.bufT[S20BS : S20BS+len(data)+1+NonceSize]
	}
	copy(p.frameT[len(p.frameT)-NonceSize:], (<-p.noncesT)[:])
	var out []byte
	copy(p.nonceT[8:], p.frameT[len(p.frameT)-NonceSize:])
	if p.Encless {
		var err error
		out, err = EnclessEncode(p.key, p.nonceT, p.frameT[:len(p.frameT)-NonceSize])
		if err != nil {
			panic(err)
		}
		out = append(out, p.frameT[len(p.frameT)-NonceSize:]...)
	} else {
		chacha20.XORKeyStream(
			p.bufT[:S20BS+len(p.frameT)-NonceSize],
			p.bufT[:S20BS+len(p.frameT)-NonceSize],
			p.nonceT,
			p.key,
		)
		copy(p.keyAuthT[:], p.bufT[:SSize])
		poly1305.Sum(p.tagT, p.frameT, p.keyAuthT)
		atomic.AddUint64(&p.BytesOut, uint64(len(p.frameT)+TagSize))
		out = append(p.tagT[:], p.frameT...)
	}
	p.FramesOut++
	p.Conn.Write(out)
	p.BusyT.Unlock()
}

func (p *Peer) PktProcess(data []byte, tap io.Writer, reorderable bool) bool {
	if len(data) < MinPktLength {
		return false
	}
	if !p.Encless && len(data) > len(p.bufR)-S20BS {
		return false
	}
	var out []byte
	p.BusyR.Lock()
	copy(p.nonceR[8:], data[len(data)-NonceSize:])
	if p.Encless {
		var err error
		out, err = EnclessDecode(p.key, p.nonceR, data[:len(data)-NonceSize])
		if err != nil {
			p.FramesUnauth++
			p.BusyR.Unlock()
			return false
		}
	} else {
		for i := 0; i < SSize; i++ {
			p.bufR[i] = 0
		}
		copy(p.bufR[S20BS:], data[TagSize:])
		chacha20.XORKeyStream(
			p.bufR[:S20BS+len(data)-TagSize-NonceSize],
			p.bufR[:S20BS+len(data)-TagSize-NonceSize],
			p.nonceR,
			p.key,
		)
		copy(p.keyAuthR[:], p.bufR[:SSize])
		copy(p.tagR[:], data[:TagSize])
		if !poly1305.Verify(p.tagR, data[TagSize:], p.keyAuthR) {
			p.FramesUnauth++
			p.BusyR.Unlock()
			return false
		}
		out = p.bufR[S20BS : S20BS+len(data)-TagSize-NonceSize]
	}

	if reorderable {
		copy(p.nonceRecv[:], data[len(data)-NonceSize:])
		_, foundL := p.nonceBucketL[p.nonceRecv]
		_, foundM := p.nonceBucketM[p.nonceRecv]
		_, foundH := p.nonceBucketH[p.nonceRecv]
		// If found is none of buckets: either it is too old,
		// or too new (many packets were lost)
		if !(foundL || foundM || foundH) {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
		// Delete seen nonce
		if foundL {
			delete(p.nonceBucketL, p.nonceRecv)
		}
		if foundM {
			delete(p.nonceBucketM, p.nonceRecv)
		}
		if foundH {
			delete(p.nonceBucketH, p.nonceRecv)
		}
		// If we are dealing with the latest bucket, create the new one
		if foundH {
			p.nonceBucketL, p.nonceBucketM = p.nonceBucketM, p.nonceBucketH
			p.nonceBucketH = make(map[[NonceSize]byte]struct{})
			var nonce *[NonceSize]byte
			for i := 0; i < NonceBucketSize; i++ {
				nonce = <-p.noncesR
				p.nonceBucketH[*nonce] = struct{}{}
			}
		}
	} else {
		if subtle.ConstantTimeCompare(data[len(data)-NonceSize:], p.NonceExpect) != 1 {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
		copy(p.NonceExpect, (<-p.noncesExpect)[:])
	}

	p.FramesIn++
	atomic.AddUint64(&p.BytesIn, uint64(len(data)))
	p.LastPing = time.Now()
	p.pktSizeR = bytes.LastIndexByte(out, PadByte)
	if p.pktSizeR == -1 {
		p.BusyR.Unlock()
		return false
	}
	// Validate the pad
	for i := p.pktSizeR + 1; i < len(out); i++ {
		if out[i] != 0 {
			p.BusyR.Unlock()
			return false
		}
	}

	if p.pktSizeR == 0 {
		p.HeartbeatRecv++
		p.BusyR.Unlock()
		return true
	}
	p.BytesPayloadIn += uint64(p.pktSizeR)
	tap.Write(out[:p.pktSizeR])
	p.BusyR.Unlock()
	return true
}

func PeerTapProcessor(peer *Peer, tap *TAP, terminator chan struct{}) {
	var data []byte
	var now time.Time
	lastSent := time.Now()
	heartbeat := time.NewTicker(peer.Timeout)
	if peer.CPRCycle == time.Duration(0) {
	RawProcessor:
		for {
			select {
			case <-terminator:
				break RawProcessor
			case <-heartbeat.C:
				now = time.Now()
				if lastSent.Add(peer.Timeout).Before(now) {
					peer.EthProcess(nil)
					lastSent = now
				}
			case data = <-tap.Sink:
				peer.EthProcess(data)
				lastSent = time.Now()
			}
		}
	} else {
	CPRProcessor:
		for {
			data = nil
			select {
			case <-terminator:
				break CPRProcessor
			case data = <-tap.Sink:
				peer.EthProcess(data)
			default:
			}
			if data == nil {
				peer.EthProcess(nil)
			}
			time.Sleep(peer.CPRCycle)
		}
	}
	close(terminator)
	peer.Zero()
	heartbeat.Stop()
}
