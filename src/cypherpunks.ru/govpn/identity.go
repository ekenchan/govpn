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
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
)

const (
	IDSize = 128 / 8
)

type PeerID [IDSize]byte

func (id PeerID) String() string {
	return base64.RawStdEncoding.EncodeToString(id[:])
}

func (id PeerID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + id.String() + `"`), nil
}

type MACAndTimeSync struct {
	mac hash.Hash
	ts  int
	l   sync.Mutex
}

type MACCache struct {
	cache map[PeerID]*MACAndTimeSync
	l     sync.RWMutex
}

func NewMACCache() *MACCache {
	return &MACCache{cache: make(map[PeerID]*MACAndTimeSync)}
}

// Remove disappeared keys, add missing ones with initialized MACs.
func (mc *MACCache) Update(peers *map[PeerID]*PeerConf) {
	mc.l.Lock()
	for pid := range mc.cache {
		if _, exists := (*peers)[pid]; !exists {
			log.Println("Cleaning key:", pid)
			delete(mc.cache, pid)
		}
	}
	for pid, pc := range *peers {
		if _, exists := mc.cache[pid]; exists {
			mc.cache[pid].ts = pc.TimeSync
		} else {
			log.Println("Adding key", pid)
			mac, err := blake2b.New256(pid[:])
			if err != nil {
				panic(err)
			}
			mc.cache[pid] = &MACAndTimeSync{
				mac: mac,
				ts:  pc.TimeSync,
			}
		}
	}
	mc.l.Unlock()
}

// If timeSync > 0, then XOR timestamp with the data.
func AddTimeSync(ts int, data []byte) {
	if ts == 0 {
		return
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().Unix()/int64(ts)*int64(ts)))
	for i := 0; i < 8; i++ {
		data[i] ^= buf[i]
	}
}

// Try to find peer's identity (that equals to MAC)
// by taking first blocksize sized bytes from data at the beginning
// as plaintext and last bytes as cyphertext.
func (mc *MACCache) Find(data []byte) *PeerID {
	if len(data) < 8*2 {
		return nil
	}
	buf := make([]byte, 8)
	sum := make([]byte, 32)
	mc.l.RLock()
	for pid, mt := range mc.cache {
		copy(buf, data)
		AddTimeSync(mt.ts, buf)
		mt.l.Lock()
		mt.mac.Reset()
		mt.mac.Write(buf)
		mt.mac.Sum(sum[:0])
		mt.l.Unlock()
		if subtle.ConstantTimeCompare(sum[len(sum)-8:], data[len(data)-8:]) == 1 {
			ppid := PeerID(pid)
			mc.l.RUnlock()
			return &ppid
		}
	}
	mc.l.RUnlock()
	return nil
}
