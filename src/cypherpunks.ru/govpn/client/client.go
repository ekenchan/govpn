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
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/agl/ed25519"

	"cypherpunks.ru/govpn"
)

type Protocol int

const (
	ProtocolUDP Protocol = iota
	ProtocolTCP
)

type Configuration struct {
	PrivateKey          *[ed25519.PrivateKeySize]byte
	Peer                *govpn.PeerConf
	Protocol            Protocol
	InterfaceName       string
	ProxyAddress        string
	ProxyAuthentication string
	RemoteAddress       string
	UpPath              string
	DownPath            string
	StatsAddress        string
	NoReconnect         bool
	MTU                 int
}

func (c *Configuration) Validate() error {
	if c.MTU > govpn.MTUMax {
		return fmt.Errorf("Invalid MTU %d, maximum allowable is %d", c.MTU, govpn.MTUMax)
	}
	if len(c.RemoteAddress) == 0 {
		return errors.New("Missing RemoteAddress")
	}
	if len(c.InterfaceName) == 0 {
		return errors.New("Missing InterfaceName")
	}
	return nil
}

func (c *Configuration) isProxy() bool {
	return len(c.ProxyAddress) > 0
}

type Client struct {
	idsCache      *govpn.MACCache
	tap           *govpn.TAP
	knownPeers    sync.Map
	statsPort     net.Listener
	timeouted     chan struct{}
	rehandshaking chan struct{}
	termination   chan struct{}
	firstUpCall   bool
	termSignal    chan os.Signal
	config        Configuration

	// Error channel receives any kind of routine errors
	Error chan error
}

func (c *Client) MainCycle() {
	var err error
	c.tap, err = govpn.TAPListen(c.config.InterfaceName, c.config.MTU)
	if err != nil {
		c.Error <- fmt.Errorf("Can not listen on TUN/TAP interface: %s", err.Error())
		return
	}

	if len(c.config.StatsAddress) > 0 {
		c.statsPort, err = net.Listen("tcp", c.config.StatsAddress)
		if err != nil {
			c.Error <- fmt.Errorf("Can't listen on stats port: %s", err.Error())
			return
		}
		go govpn.StatsProcessor(c.statsPort, &c.knownPeers)
	}

MainCycle:
	for {
		c.timeouted = make(chan struct{})
		c.rehandshaking = make(chan struct{})
		c.termination = make(chan struct{})
		switch c.config.Protocol {
		case ProtocolUDP:
			go c.startUDP()
		case ProtocolTCP:
			if c.config.isProxy() {
				go c.proxyTCP()
			} else {
				go c.startTCP()
			}
		}
		select {
		case <-c.termSignal:
			govpn.BothPrintf(`[finish remote="%s"]`, c.config.RemoteAddress)
			c.termination <- struct{}{}
			// empty value signals that everything is fine
			c.Error <- nil
			break MainCycle
		case <-c.timeouted:
			if c.config.NoReconnect {
				break MainCycle
			}
			govpn.BothPrintf(`[sleep seconds="%d"]`, c.config.Peer.Timeout/time.Second)
			time.Sleep(c.config.Peer.Timeout)
		case <-c.rehandshaking:
		}
		close(c.timeouted)
		close(c.rehandshaking)
		close(c.termination)
	}
	if _, err = govpn.ScriptCall(
		c.config.DownPath,
		c.config.InterfaceName,
		c.config.RemoteAddress,
	); err != nil {
		c.Error <- err
	}
}

func NewClient(conf Configuration, verifier *govpn.Verifier, termSignal chan os.Signal) *Client {
	client := Client{
		idsCache:    govpn.NewMACCache(),
		firstUpCall: true,
		config:      conf,
		termSignal:  termSignal,
		Error:       make(chan error, 1),
	}
	confs := map[govpn.PeerID]*govpn.PeerConf{*verifier.ID: conf.Peer}
	client.idsCache.Update(&confs)
	return &client
}
