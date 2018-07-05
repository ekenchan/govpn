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
	"log"
	"net"
	"time"

	"cypherpunks.ru/govpn"
)

func startTCP() {
	bind, err := net.ResolveTCPAddr("tcp", *bindAddr)
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	listener, err := net.ListenTCP("tcp", bind)
	if err != nil {
		log.Fatalln("Can not listen on TCP:", err)
	}
	govpn.BothPrintf(`[tcp-listen bind="%s"]`, *bindAddr)
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				govpn.Printf(`[tcp-accept-failed bind="%s" err="%s"]`, *bindAddr, err)
				continue
			}
			go handleTCP(conn)
		}
	}()
}

func handleTCP(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	buf := make([]byte, govpn.EnclessEnlargeSize+2*govpn.MTUMax)
	var n int
	var err error
	var prev int
	var hs *govpn.Handshake
	var ps *PeerState
	var peer *govpn.Peer
	var tap *govpn.TAP
	var conf *govpn.PeerConf
	var addrPrev string
	var peerPrevI interface{}
	var peerPrev *PeerState
	for {
		if prev == len(buf) {
			break
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(govpn.TimeoutDefault) * time.Second))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			// Either EOFed or timeouted
			break
		}
		prev += n
		peerID := idsCache.Find(buf[:prev])
		if peerID == nil {
			continue
		}
		if hs == nil {
			conf = confs[*peerID]
			if conf == nil {
				govpn.Printf(
					`[conf-get-failed bind="%s" peer="%s"]`,
					*bindAddr, peerID.String(),
				)
				break
			}
			hs = govpn.NewHandshake(addr, conn, conf)
		}
		peer = hs.Server(buf[:prev])
		prev = 0
		if peer == nil {
			continue
		}
		hs.Zero()
		govpn.Printf(
			`[handshake-completed bind="%s" addr="%s" peer="%s"]`,
			*bindAddr, addr, peerID.String(),
		)
		addrPrevI, exists := peersByID.Load(*peer.ID)
		if exists {
			addrPrev = addrPrevI.(string)
			peerPrevI, exists = peers.Load(addrPrev)
			if exists {
				peerPrev = peerPrevI.(*PeerState)
				exists = peerPrev == nil
			}
		}
		if exists {
			peerPrev.terminator <- struct{}{}
			tap = peerPrev.tap
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: make(chan struct{}),
			}
			go govpn.PeerTapProcessor(ps.peer, ps.tap, ps.terminator)
			peers.Delete(addrPrev)
			peers.Store(addr, ps)
			knownPeers.Delete(addrPrev)
			knownPeers.Store(addr, &peer)
			peersByID.Store(*peer.ID, addr)
			govpn.Printf(
				`[rehandshake-completed bind="%s" peer="%s"]`,
				*bindAddr, peerID.String(),
			)
		} else {
			ifaceName, err := callUp(peer.ID, peer.Addr)
			if err != nil {
				peer = nil
				break
			}
			tap, err = govpn.TAPListen(ifaceName, peer.MTU)
			if err != nil {
				govpn.Printf(
					`[tap-failed bind="%s" peer="%s" err="%s"]`,
					*bindAddr, peerID.String(), err,
				)
				peer = nil
				break
			}
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: make(chan struct{}, 1),
			}
			go govpn.PeerTapProcessor(ps.peer, ps.tap, ps.terminator)
                        peers.Range(func(addrI, psI interface{}) bool {
                                addr2 := addrI.(string)
                                ps := psI.(*PeerState)
                                if ps.peer.ID.String() == peer.ID.String() {
                                        govpn.Printf(
                                                `[peer-delete bind="%s" peer="%s"]`,
                                                *bindAddr,
                                                ps.peer.ID.String(),
                                        )
                                        peers.Delete(addr2)
                                        knownPeers.Delete(addr2)
                                        peersByID.Delete(*ps.peer.ID)
                                        go govpn.ScriptCall(
                                                confs[*ps.peer.ID].Down,
                                                ps.tap.Name,
                                                ps.peer.Addr,
                                        )
                                        ps.terminator <- struct{}{}
                                }
                                return true
                        })

			peers.Store(addr, ps)
			peersByID.Store(*peer.ID, addr)
			knownPeers.Store(addr, &peer)
			govpn.Printf(`[peer-created bind="%s" peer="%s"]`, *bindAddr, peerID.String())
		}
		break
	}
	if hs != nil {
		hs.Zero()
	}
	if peer == nil {
		return
	}

	prev = 0
	var i int
	for {
		if prev == len(buf) {
			break
		}
		conn.SetReadDeadline(time.Now().Add(conf.Timeout))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			// Either EOFed or timeouted
			break
		}
		prev += n
	CheckMore:
		if prev < govpn.MinPktLength {
			continue
		}
		i = bytes.Index(buf[:prev], peer.NonceExpect)
		if i == -1 {
			continue
		}
		if !peer.PktProcess(buf[:i+govpn.NonceSize], tap, false) {
			govpn.Printf(
				`[packet-unauthenticated bind="%s" addr="%s" peer="%s"]`,
				*bindAddr, addr, peer.ID.String(),
			)
			break
		}
		copy(buf, buf[i+govpn.NonceSize:prev])
		prev = prev - i - govpn.NonceSize
		goto CheckMore
	}
	peer.Zero()
}
