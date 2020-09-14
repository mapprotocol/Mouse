// Copyright 2015 The mouse Authors
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

// Contains the metrics collected by the downloader.

package downloader

import (
	"github.com/marcopoloprotoco/mouse/metrics"
)

var (
	headerInMeter      = metrics.NewRegisteredMeter("mos/downloader/headers/in", nil)
	headerReqTimer     = metrics.NewRegisteredTimer("mos/downloader/headers/req", nil)
	headerDropMeter    = metrics.NewRegisteredMeter("mos/downloader/headers/drop", nil)
	headerTimeoutMeter = metrics.NewRegisteredMeter("mos/downloader/headers/timeout", nil)

	bodyInMeter      = metrics.NewRegisteredMeter("mos/downloader/bodies/in", nil)
	bodyReqTimer     = metrics.NewRegisteredTimer("mos/downloader/bodies/req", nil)
	bodyDropMeter    = metrics.NewRegisteredMeter("mos/downloader/bodies/drop", nil)
	bodyTimeoutMeter = metrics.NewRegisteredMeter("mos/downloader/bodies/timeout", nil)

	receiptInMeter      = metrics.NewRegisteredMeter("mos/downloader/receipts/in", nil)
	receiptReqTimer     = metrics.NewRegisteredTimer("mos/downloader/receipts/req", nil)
	receiptDropMeter    = metrics.NewRegisteredMeter("mos/downloader/receipts/drop", nil)
	receiptTimeoutMeter = metrics.NewRegisteredMeter("mos/downloader/receipts/timeout", nil)

	stateInMeter   = metrics.NewRegisteredMeter("mos/downloader/states/in", nil)
	stateDropMeter = metrics.NewRegisteredMeter("mos/downloader/states/drop", nil)

	throttleCounter = metrics.NewRegisteredCounter("mos/downloader/throttle", nil)
)
