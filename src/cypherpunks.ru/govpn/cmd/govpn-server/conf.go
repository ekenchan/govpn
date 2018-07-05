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
	"errors"
	"io/ioutil"
	"log"
	"time"

	"gopkg.in/yaml.v2"

	"cypherpunks.ru/govpn"
)

const (
	RefreshRate = time.Minute
)

var (
	confs    map[govpn.PeerID]*govpn.PeerConf
	idsCache *govpn.MACCache
)

func confRead() (*map[govpn.PeerID]*govpn.PeerConf, error) {
	data, err := ioutil.ReadFile(*confPath)
	if err != nil {
		return nil, err
	}
	confsRaw := new(map[string]govpn.PeerConf)
	err = yaml.Unmarshal(data, confsRaw)
	if err != nil {
		return nil, err
	}

	confs := make(map[govpn.PeerID]*govpn.PeerConf, len(*confsRaw))
	for name, pc := range *confsRaw {
		verifier, err := govpn.VerifierFromString(pc.VerifierRaw)
		if err != nil {
			return nil, errors.New("Unable to decode verifier: " + err.Error())
		}
		if pc.Encless {
			pc.Noise = true
		}
		if pc.MTU == 0 {
			pc.MTU = govpn.MTUDefault
		}
		if pc.MTU > govpn.MTUMax {
			govpn.Printf(`[mtu-high bind="%s" value="%d" overriden="%d"]`, *bindAddr, pc.MTU, govpn.MTUMax)
			pc.MTU = govpn.MTUMax
		}
		conf := govpn.PeerConf{
			Verifier: verifier,
			ID:       verifier.ID,
			Name:     name,
			Iface:    pc.Iface,
			MTU:      pc.MTU,
			Up:       pc.Up,
			Down:     pc.Down,
			Noise:    pc.Noise,
			CPR:      pc.CPR,
			Encless:  pc.Encless,
			TimeSync: pc.TimeSync,
		}
		if pc.TimeoutInt <= 0 {
			pc.TimeoutInt = govpn.TimeoutDefault
		}
		conf.Timeout = time.Second * time.Duration(pc.TimeoutInt)
		confs[*verifier.ID] = &conf
	}
	return &confs, nil
}

func confRefresh() error {
	newConfs, err := confRead()
	if err != nil {
		govpn.Printf(`[conf-parse-failed bind="%s" err="%s"]`, *bindAddr, err)
		return err
	}
	confs = *newConfs
	idsCache.Update(newConfs)
	return nil
}

func confInit() {
	idsCache = govpn.NewMACCache()
	if err := confRefresh(); err != nil {
		log.Fatalln(err)
	}
	go func() {
		for {
			time.Sleep(RefreshRate)
			confRefresh()
		}
	}()
}
