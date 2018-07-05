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

package aont

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"testing/quick"
)

var (
	testKey = new([16]byte)
)

func init() {
	io.ReadFull(rand.Reader, testKey[:])
}

func TestSymmetric(t *testing.T) {
	f := func(data []byte) bool {
		encoded, err := Encode(testKey, data)
		if err != nil {
			return false
		}
		if len(encoded) != len(data)+16+32 {
			return false
		}
		decoded, err := Decode(encoded)
		if err != nil {
			return false
		}
		return bytes.Compare(decoded, data) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestSmallSize(t *testing.T) {
	_, err := Decode([]byte("foobar"))
	if err == nil {
		t.Fail()
	}
}

func TestTampered(t *testing.T) {
	f := func(data []byte, index int) bool {
		if len(data) == 0 {
			return true
		}
		encoded, _ := Encode(testKey, data)
		encoded[len(data)%index] ^= byte('a')
		_, err := Decode(encoded)
		if err == nil {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func BenchmarkEncode(b *testing.B) {
	data := make([]byte, 128)
	io.ReadFull(rand.Reader, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encode(testKey, data)
	}
}

func BenchmarkDecode(b *testing.B) {
	data := make([]byte, 128)
	io.ReadFull(rand.Reader, data)
	encoded, _ := Encode(testKey, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decode(encoded)
	}
}
