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
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"cypherpunks.ru/balloon"
	"github.com/agl/ed25519"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	DefaultS = 1 << 20 / 32
	DefaultT = 1 << 4
	DefaultP = 2
)

type Verifier struct {
	S   int
	T   int
	P   int
	ID  *PeerID
	Pub *[ed25519.PublicKeySize]byte
}

// Generate new verifier for given peer, with specified password and
// hashing parameters.
func VerifierNew(s, t, p int, id *PeerID) *Verifier {
	return &Verifier{S: s, T: t, P: p, ID: id}
}

func blake2bKeyless() hash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// Apply the password: create Ed25519 keypair based on it, save public
// key in verifier.
func (v *Verifier) PasswordApply(password string) *[ed25519.PrivateKeySize]byte {
	r := balloon.H(blake2bKeyless, []byte(password), v.ID[:], v.S, v.T, v.P)
	defer SliceZero(r)
	src := bytes.NewBuffer(r)
	pub, prv, err := ed25519.GenerateKey(src)
	if err != nil {
		log.Fatalln("Unable to generate Ed25519 keypair", err)
	}
	v.Pub = pub
	return prv
}

// Parse either short or long verifier form.
func VerifierFromString(input string) (*Verifier, error) {
	ss := strings.Split(input, "$")
	if len(ss) < 4 || ss[1] != "balloon" {
		return nil, errors.New("Invalid verifier structure")
	}
	var s, t, p int
	n, err := fmt.Sscanf(ss[2], "s=%d,t=%d,p=%d", &s, &t, &p)
	if n != 3 || err != nil {
		return nil, errors.New("Invalid verifier parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(ss[3])
	if err != nil {
		return nil, err
	}
	v := Verifier{S: s, T: t, P: p}
	id := new([IDSize]byte)
	copy(id[:], salt)
	pid := PeerID(*id)
	v.ID = &pid
	if len(ss) == 5 {
		pub, err := base64.RawStdEncoding.DecodeString(ss[4])
		if err != nil {
			return nil, err
		}
		v.Pub = new([ed25519.PublicKeySize]byte)
		copy(v.Pub[:], pub)
	}
	return &v, nil
}

// Short verifier string form -- it is useful for the client.
// Does not include public key.
func (v *Verifier) ShortForm() string {
	return fmt.Sprintf(
		"$balloon$s=%d,t=%d,p=%d$%s",
		v.S, v.T, v.P, base64.RawStdEncoding.EncodeToString(v.ID[:]),
	)
}

// Long verifier string form -- it is useful for the server.
// Includes public key.
func (v *Verifier) LongForm() string {
	return fmt.Sprintf(
		"%s$%s", v.ShortForm(),
		base64.RawStdEncoding.EncodeToString(v.Pub[:]),
	)
}

// Read the key either from text file (if path is specified), or
// from the terminal.
func KeyRead(path string) (string, error) {
	var p []byte
	var err error
	var pass string
	if path == "" {
		os.Stderr.WriteString("Passphrase:")
		p, err = terminal.ReadPassword(0)
		os.Stderr.WriteString("\n")
		pass = string(p)
	} else {
		p, err = ioutil.ReadFile(path)
		pass = strings.TrimRight(string(p), "\n")
	}
	if err != nil {
		return "", err
	}
	if len(pass) == 0 {
		return "", errors.New("Empty passphrase submitted")
	}
	return pass, err
}
