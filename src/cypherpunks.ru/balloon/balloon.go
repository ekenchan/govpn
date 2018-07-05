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

// Balloon password hashing.
//
// Look https://crypto.stanford.edu/balloon/ for more description.
package balloon

import (
	"encoding/binary"
	"hash"
	"math/big"
)

const (
	delta = 3
)

// This function takes hash, password, salt, space cost (buffer size,
// number of hash-output sized blocks), time cost (number of rounds) and
// performs the following:
//
//    # Expand input into buffer.
//    buf[0] = hash(cnt++ || passwd || salt)
//    for m from 1 to sCost-1:
//        buf[m] = hash(cnt++ || buf[m-1])
//    # Mix buffer contents.
//    for t from 0 to tCost-1:
//        for m from 0 to sCost-1:
//            # Hash last and current blocks.
//            prev = buf[(m-1) mod sCost]
//            buf[m] = hash(cnt++ || prev || buf[m])
//            # Hash in pseudorandomly chosen blocks.
//            for i from 0 to delta-1:
//                other = to_int(hash(cnt++ || salt || t || m || i)) mod sCost
//                buf[m] = hash(cnt++ || buf[m] || buf[other])
//    # Extract output from buffer.
//    return buf[sCost-1]
func B(h hash.Hash, passwd, salt []byte, sCost, tCost int) []byte {
	var cnt uint64
	intBuf := make([]byte, 8)
	buf := make([][]byte, sCost)
	// Expand input into buffer
	binary.BigEndian.PutUint64(intBuf, cnt)
	cnt++
	h.Write(intBuf)
	h.Write(passwd)
	h.Write(salt)
	buf[0] = h.Sum(nil)
	var m int
	for m = 1; m < sCost; m++ {
		binary.BigEndian.PutUint64(intBuf, cnt)
		cnt++
		h.Reset()
		h.Write(intBuf)
		h.Write(buf[m-1])
		buf[m] = h.Sum(nil)
	}
	// Mix buffer contents
	var prev []byte
	var i int
	bi := big.NewInt(0)
	bs := big.NewInt(int64(sCost))
	biBuf := make([]byte, 0, h.Size())
	var other int
	for t := 0; t < tCost; t++ {
		for m = 0; m < sCost; m++ {
			// Hash last and current blocks
			if m == 0 {
				prev = buf[len(buf)-1]
			} else {
				prev = buf[m-1]
			}
			binary.BigEndian.PutUint64(intBuf, cnt)
			cnt++
			h.Reset()
			h.Write(intBuf)
			h.Write(prev)
			h.Write(buf[m])
			buf[m] = h.Sum(buf[m][:0])

			// Hash in pseudorandomly chosen blocks
			for i = 0; i < delta; i++ {
				binary.BigEndian.PutUint64(intBuf, cnt)
				cnt++
				h.Reset()
				h.Write(intBuf)
				h.Write(salt)
				binary.BigEndian.PutUint64(intBuf, uint64(t))
				h.Write(intBuf)
				binary.BigEndian.PutUint64(intBuf, uint64(m))
				h.Write(intBuf)
				binary.BigEndian.PutUint64(intBuf, uint64(i))
				h.Write(intBuf)
				biBuf = h.Sum(biBuf[:0])
				bi.SetBytes(biBuf)
				bi.Mod(bi, bs)
				other = int(bi.Uint64())
				binary.BigEndian.PutUint64(intBuf, cnt)
				cnt++
				h.Reset()
				h.Write(intBuf)
				h.Write(buf[m])
				h.Write(buf[other])
				buf[m] = h.Sum(buf[m][:0])
			}
		}
	}
	// Extract output from buffer
	return buf[sCost-1]
}

// This function adds additional functionality over pure B(): ability to
// run several hashers (jobs) simultaneously and second-preimage resistant
// password double hashing.
//
//     H(p, s, jobs) = hash(p || s || (
//         B(p, s || "1") XOR
//         B(p, s || "2") XOR
//         B(p, s || jobs)
//     ))
func H(hasher func() hash.Hash, passwd, salt []byte, sCost, tCost int, jobs int) []byte {
	var i int
	results := make(chan []byte)
	for ; i < jobs; i++ {
		go func(i int) {
			saltBuf := make([]byte, 8)
			binary.BigEndian.PutUint64(saltBuf, uint64(i))
			results <- B(hasher(), passwd, append(salt, saltBuf...), sCost, tCost)
		}(i)
	}
	h := hasher()
	h.Write(passwd)
	h.Write(salt)
	result := make([]byte, h.Size())
	for i = 0; i < jobs; i++ {
		for n, e := range <-results {
			result[n] ^= e
		}
	}
	close(results)
	h.Write(result)
	return h.Sum(result[:0])
}
