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

package main

import (
	"bytes"
	"sync"

	"cypherpunks.ru/govpn"
)

type PeerState struct {
	peer       *govpn.Peer
	terminator chan struct{}
	tap        *govpn.TAP
}

var (
	handshakes sync.Map
	peers      sync.Map
	peersByID  sync.Map
	knownPeers sync.Map
)

func callUp(peerID *govpn.PeerID, remoteAddr string) (string, error) {
	ifaceName := confs[*peerID].Iface
	if confs[*peerID].Up != "" {
		result, err := govpn.ScriptCall(confs[*peerID].Up, ifaceName, remoteAddr)
		if err != nil {
			govpn.Printf(
				`[script-failed bind="%s" path="%s" err="%s"]`,
				*bindAddr,
				confs[*peerID].Up,
				err,
			)
			return "", err
		}
		if ifaceName == "" {
			sepIndex := bytes.Index(result, []byte{'\n'})
			if sepIndex < 0 {
				sepIndex = len(result)
			}
			ifaceName = string(result[:sepIndex])
		}
	}
	if ifaceName == "" {
		govpn.Printf(`[tap-failed bind="%s" peer="%s"]`, *bindAddr, *peerID)
	}
	return ifaceName, nil
}
