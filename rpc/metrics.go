// Copyright 2020 The mouse Authors
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

package rpc

import (
	"fmt"

	"github.com/marcopoloprotoco/mouse/metrics"
)

var (
	rpcRequestGauge        = metrics.NewRegisteredGauge("rpc/requests", nil)
	successfulRequestGauge = metrics.NewRegisteredGauge("rpc/success", nil)
	failedReqeustGauge     = metrics.NewRegisteredGauge("rpc/failure", nil)
	rpcServingTimer        = metrics.NewRegisteredTimer("rpc/duration/all", nil)
)

func newRPCServingTimer(method string, valid bool) metrics.Timer {
	flag := "success"
	if !valid {
		flag = "failure"
	}
	m := fmt.Sprintf("rpc/duration/%s/%s", method, flag)
	return metrics.GetOrRegisterTimer(m, nil)
}
