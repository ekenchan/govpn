/*
balloon -- Balloon password hashing function
Copyright (C) 2016-2017 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this program.  If not, see
<http://www.gnu.org/licenses/>.
*/

package balloon

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"testing/quick"
)

func TestB(t *testing.T) {
	f := func(passwd, salt []byte, s, t uint8) bool {
		if len(passwd) == 0 || len(salt) == 0 {
			return true
		}
		B(sha256.New(), passwd, salt, int(s)%16+1, int(t)%16+1)
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestH(t *testing.T) {
	f := func(passwd, salt []byte, s, t, p uint8) bool {
		if len(passwd) == 0 || len(salt) == 0 {
			return true
		}
		H(sha256.New, passwd, salt, int(s)%16+1, int(t)%16+1, int(p)%8+1)
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func BenchmarkB(b *testing.B) {
	passwd := make([]byte, 8)
	rand.Read(passwd)
	salt := make([]byte, 8)
	rand.Read(salt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		B(sha256.New(), passwd, salt, 1<<10/sha256.New().Size(), 4)
	}
}

func BenchmarkH(b *testing.B) {
	passwd := make([]byte, 8)
	rand.Read(passwd)
	salt := make([]byte, 8)
	rand.Read(salt)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		H(sha256.New, passwd, salt, 1<<10/sha256.New().Size(), 4, 4)
	}
}
