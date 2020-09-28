package main

import (
	"github.com/marcopoloprotoco/mouse/cmd/utils"
	"github.com/marcopoloprotoco/mouse/common"
	"gopkg.in/urfave/cli.v1"
)

var sendCommand = cli.Command{
	Name:   "send",
	Usage:  "Send general transaction",
	Action: utils.MigrateFlags(sendTX),
	Flags:  append(ImpawnFlags, AddressFlag),
}

func sendTX(ctx *cli.Context) error {
	loadPrivate(ctx)
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)
	PrintBalance(conn, from)

	address := ctx.GlobalString(AddressFlag.Name)
	if !common.IsHexAddress(address) {
		printError("Must input correct address")
	}

	value := trueToWei(ctx, false)
	txHash := sendContractTransaction(conn, from, common.HexToAddress(address), value, priKey, nil)
	getResult(conn, txHash, false, false)
	return nil
}

var queryTxCommand = cli.Command{
	Name:   "querytx",
	Usage:  "Query tx hash, get transaction result",
	Action: utils.MigrateFlags(queryTxImpawn),
	Flags:  append(ImpawnFlags, TxHashFlag),
}

func queryTxImpawn(ctx *cli.Context) error {
	conn, url := dialConn(ctx)
	printBaseInfo(conn, url)

	txhash := ctx.GlobalString(TxHashFlag.Name)
	if txhash == "" {
		printError("Must input tx hash")
	}
	queryTx(conn, common.HexToHash(txhash), false, true, false)
	return nil
}
