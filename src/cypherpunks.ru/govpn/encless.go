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
	"io"

	"cypherpunks.ru/govpn/aont"
	"cypherpunks.ru/govpn/cnw"
)

const (
	EnclessEnlargeSize = aont.HSize + aont.RSize*cnw.EnlargeFactor
)

// Confidentiality preserving (but encryptionless) encoding.
//
// It uses Chaffing-and-Winnowing technology (it is neither
// encryption nor steganography) over All-Or-Nothing-Transformed data.
// nonce is 64-bit nonce. Output data will be EnclessEnlargeSize larger.
// It also consumes 64-bits of entropy.
func EnclessEncode(authKey *[32]byte, nonce *[16]byte, in []byte) ([]byte, error) {
	r := new([aont.RSize]byte)
	var err error
	if _, err = io.ReadFull(Rand, r[:]); err != nil {
		return nil, err
	}
	aonted, err := aont.Encode(r, in)
	if err != nil {
		return nil, err
	}
	out := append(
		cnw.Chaff(authKey, nonce[8:], aonted[:aont.RSize]),
		aonted[aont.RSize:]...,
	)
	SliceZero(aonted[:aont.RSize])
	return out, nil
}

// Decode EnclessEncode-ed data.
func EnclessDecode(authKey *[32]byte, nonce *[16]byte, in []byte) ([]byte, error) {
	var err error
	winnowed, err := cnw.Winnow(
		authKey, nonce[8:], in[:aont.RSize*cnw.EnlargeFactor],
	)
	if err != nil {
		return nil, err
	}
	out, err := aont.Decode(append(
		winnowed, in[aont.RSize*cnw.EnlargeFactor:]...,
	))
	SliceZero(winnowed)
	if err != nil {
		return nil, err
	}
	return out, nil
}
