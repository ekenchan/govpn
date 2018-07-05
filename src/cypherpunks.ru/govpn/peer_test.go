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
	"testing"
	"testing/quick"
	"time"
)

var (
	testPeer   *Peer
	testPt     []byte
	testCt     []byte
	testPeerID PeerID
	testConf   *PeerConf
)

type Dummy struct {
	dst *[]byte
}

func (d Dummy) Write(b []byte) (int, error) {
	if d.dst != nil {
		*d.dst = b
	}
	return len(b), nil
}

func init() {
	id := new([IDSize]byte)
	testPeerID = PeerID(*id)
	testConf = &PeerConf{
		ID:      &testPeerID,
		MTU:     MTUDefault,
		Timeout: time.Second * time.Duration(TimeoutDefault),
	}
	testPt = make([]byte, 789)
}

func testPeerNew() {
	testPeer = newPeer(true, "foo", Dummy{&testCt}, testConf, new([SSize]byte))
}

func TestTransportSymmetric(t *testing.T) {
	testPeerNew()
	peerd := newPeer(false, "foo", Dummy{nil}, testConf, new([SSize]byte))
	f := func(payload []byte) bool {
		if len(payload) == 0 {
			return true
		}
		testPeer.EthProcess(payload)
		return peerd.PktProcess(testCt, Dummy{nil}, true)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestTransportSymmetricNoise(t *testing.T) {
	testPeerNew()
	peerd := newPeer(false, "foo", Dummy{nil}, testConf, new([SSize]byte))
	testPeer.NoiseEnable = true
	peerd.NoiseEnable = true
	f := func(payload []byte) bool {
		if len(payload) == 0 {
			return true
		}
		testPeer.EthProcess(payload)
		return peerd.PktProcess(testCt, Dummy{nil}, true)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
	testPeer.NoiseEnable = true
}

func TestTransportSymmetricEncless(t *testing.T) {
	testPeerNew()
	peerd := newPeer(false, "foo", Dummy{nil}, testConf, new([SSize]byte))
	testPeer.Encless = true
	testPeer.NoiseEnable = true
	peerd.Encless = true
	peerd.NoiseEnable = true
	f := func(payload []byte) bool {
		if len(payload) == 0 {
			return true
		}
		testPeer.EthProcess(payload)
		return peerd.PktProcess(testCt, Dummy{nil}, true)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
	testPeer.NoiseEnable = false
	testPeer.Encless = false
}

func BenchmarkEnc(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testPeer.EthProcess(testPt)
	}
}

func BenchmarkDec(b *testing.B) {
	testPeer = newPeer(true, "foo", Dummy{&testCt}, testConf, new([SSize]byte))
	testPeer.EthProcess(testPt)
	testPeer = newPeer(true, "foo", Dummy{nil}, testConf, new([SSize]byte))
	orig := make([]byte, len(testCt))
	copy(orig, testCt)
	nonce := new([NonceSize]byte)
	copy(nonce[:], testCt[len(testCt)-NonceSize:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testPeer.nonceBucketL = make(map[[NonceSize]byte]struct{}, 1)
		testPeer.nonceBucketM = make(map[[NonceSize]byte]struct{}, 1)
		testPeer.nonceBucketH = make(map[[NonceSize]byte]struct{}, 1)
		testPeer.nonceBucketL[*nonce] = struct{}{}
		copy(testCt, orig)
		if !testPeer.PktProcess(testCt, Dummy{nil}, true) {
			b.Fail()
		}
	}
}

func TestTransportBigger(t *testing.T) {
	tmp := make([]byte, MTUMax*4)
	Rand.Read(tmp)
	testPeer.PktProcess(tmp, Dummy{nil}, true)
}
