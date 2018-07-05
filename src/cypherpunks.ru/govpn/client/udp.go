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

package client

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"cypherpunks.ru/govpn"
)

func (c *Client) startUDP() {
	remote, err := net.ResolveUDPAddr("udp", c.config.RemoteAddress)
	if err != nil {
		c.Error <- fmt.Errorf("Can not resolve remote address: %s", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		c.Error <- fmt.Errorf("Can not connect remote address: %s", err)
		return
	}
	govpn.Printf(`[connected remote="%s"]`, c.config.RemoteAddress)

	hs := govpn.HandshakeStart(c.config.RemoteAddress, conn, c.config.Peer)
	buf := make([]byte, c.config.MTU*2)
	var n int
	var timeouts int
	var peer *govpn.Peer
	var terminator chan struct{}
	timeout := int(c.config.Peer.Timeout.Seconds())
MainCycle:
	for {
		select {
		case <-c.termination:
			break MainCycle
		default:
		}

		if err = conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			c.Error <- err
			break MainCycle
		}
		n, err = conn.Read(buf)
		if timeouts == timeout {
			govpn.Printf(`[connection-timeouted remote="%s"]`, c.config.RemoteAddress)
			c.timeouted <- struct{}{}
			break
		}
		if err != nil {
			timeouts++
			continue
		}
		if peer != nil {
			if peer.PktProcess(buf[:n], c.tap, true) {
				timeouts = 0
			} else {
				govpn.Printf(`[packet-unauthenticated remote="%s"]`, c.config.RemoteAddress)
				timeouts++
			}
			if atomic.LoadUint64(&peer.BytesIn)+atomic.LoadUint64(&peer.BytesOut) > govpn.MaxBytesPerKey {
				govpn.Printf(`[rehandshake-required remote="%s"]`, c.config.RemoteAddress)
				c.rehandshaking <- struct{}{}
				break MainCycle
			}
			continue
		}
		if c.idsCache.Find(buf[:n]) == nil {
			govpn.Printf(`[identity-invalid remote="%s"]`, c.config.RemoteAddress)
			continue
		}
		timeouts = 0
		peer = hs.Client(buf[:n])
		if peer == nil {
			continue
		}
		govpn.Printf(`[handshake-completed remote="%s"]`, c.config.RemoteAddress)
		c.knownPeers.Store(c.config.RemoteAddress, &peer)
		if c.firstUpCall {
			go govpn.ScriptCall(c.config.UpPath, c.config.InterfaceName, c.config.RemoteAddress)
			c.firstUpCall = false
		}
		hs.Zero()
		terminator = make(chan struct{})
		go govpn.PeerTapProcessor(peer, c.tap, terminator)
	}
	if terminator != nil {
		terminator <- struct{}{}
	}
	if hs != nil {
		hs.Zero()
	}
	if err = conn.Close(); err != nil {
		c.Error <- err
	}
}
