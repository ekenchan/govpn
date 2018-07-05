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
	"encoding/binary"
	"io"
	"testing"
	"testing/quick"
)

var (
	testKey = new([32]byte)
)

func init() {
	io.ReadFull(Rand, testKey[:])
}

func TestEnclessSymmetric(t *testing.T) {
	nonce := new([16]byte)
	f := func(pktNum uint64, in []byte) bool {
		binary.BigEndian.PutUint64(nonce[8:], pktNum)
		encoded, err := EnclessEncode(testKey, nonce, in)
		if err != nil {
			return false
		}
		decoded, err := EnclessDecode(testKey, nonce, encoded)
		if err != nil {
			return false
		}
		return bytes.Compare(decoded, in) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func BenchmarkEnclessEncode(b *testing.B) {
	nonce := new([16]byte)
	data := make([]byte, 128)
	io.ReadFull(Rand, nonce[8:])
	io.ReadFull(Rand, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EnclessEncode(testKey, nonce, data)
	}
}

func BenchmarkEnclessDecode(b *testing.B) {
	nonce := new([16]byte)
	data := make([]byte, 128)
	io.ReadFull(Rand, nonce[8:])
	io.ReadFull(Rand, data)
	encoded, _ := EnclessEncode(testKey, nonce, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EnclessDecode(testKey, nonce, encoded)
	}
}
