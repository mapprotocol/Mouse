// Copyright 2019 The mouse Authors
// This file is part of the mouse library.
//
// The mouse library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The mouse library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the mouse library. If not, see <http://www.gnu.org/licenses/>.

package mos

import (
	"github.com/marcopoloprotoco/mouse/core"
	"github.com/marcopoloprotoco/mouse/core/forkid"
	"github.com/marcopoloprotoco/mouse/p2p"
	"github.com/marcopoloprotoco/mouse/p2p/dnsdisc"
	"github.com/marcopoloprotoco/mouse/p2p/enode"
	"github.com/marcopoloprotoco/mouse/rlp"
)

// ethEntry is the "mos" ENR entry which advertises mos protocol
// on the discovery network.
type ethEntry struct {
	ForkID forkid.ID // Fork identifier per EIP-2124

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// ENRKey implements enr.Entry.
func (e ethEntry) ENRKey() string {
	return "mos"
}

// startEthEntryUpdate starts the ENR updater loop.
func (mos *Mouse) startEthEntryUpdate(ln *enode.LocalNode) {
	var newHead = make(chan core.ChainHeadEvent, 10)
	sub := mos.blockchain.SubscribeChainHeadEvent(newHead)

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case <-newHead:
				ln.Set(mos.currentEthEntry())
			case <-sub.Err():
				// Would be nice to sync with mos.Stop, but there is no
				// good way to do that.
				return
			}
		}
	}()
}

func (mos *Mouse) currentEthEntry() *ethEntry {
	return &ethEntry{ForkID: forkid.NewID(mos.blockchain)}
}

// setupDiscovery creates the node discovery source for the mos protocol.
func (mos *Mouse) setupDiscovery(cfg *p2p.Config) (enode.Iterator, error) {
	if cfg.NoDiscovery || len(mos.config.DiscoveryURLs) == 0 {
		return nil, nil
	}
	client := dnsdisc.NewClient(dnsdisc.Config{})
	return client.NewIterator(mos.config.DiscoveryURLs...)
}
