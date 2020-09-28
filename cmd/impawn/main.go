package main

import (
	"fmt"
	"github.com/marcopoloprotoco/mouse/cmd/utils"
	"github.com/marcopoloprotoco/mouse/internal/flags"
	"gopkg.in/urfave/cli.v1"
	"os"
	"path/filepath"
	"sort"
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""
	gitDate   = ""
	// The app that holds all commands and flags.
	app *cli.App

	// Flags needed by abigen
	KeyFlag = cli.StringFlag{
		Name:  "key",
		Usage: "Private key file path",
		Value: "",
	}
	KeyStoreFlag = cli.StringFlag{
		Name:  "keystore",
		Usage: "Keystore file path",
	}
	TrueValueFlag = cli.Uint64Flag{
		Name:  "value",
		Usage: "Staking value units one true",
		Value: 0,
	}
	FeeFlag = cli.Uint64Flag{
		Name:  "fee",
		Usage: "Staking fee",
		Value: 0,
	}
	AddressFlag = cli.StringFlag{
		Name:  "address",
		Usage: "Transfer address",
		Value: "",
	}
	TxHashFlag = cli.StringFlag{
		Name:  "txhash",
		Usage: "Input transaction hash",
		Value: "",
	}
	PubKeyKeyFlag = cli.StringFlag{
		Name:  "pubkey",
		Usage: "Committee public key for BFT (no 0x prefix)",
		Value: "",
	}
	BFTKeyKeyFlag = cli.StringFlag{
		Name:  "bftkey",
		Usage: "Committee bft key for BFT (no 0x prefix)",
		Value: "",
	}
	SnailNumberFlag = cli.Uint64Flag{
		Name:  "snailnumber",
		Usage: "Query reward use snail number,please current snail number -14",
	}
	ImpawnFlags = []cli.Flag{
		KeyFlag,
		KeyStoreFlag,
		utils.LegacyRPCListenAddrFlag,
		utils.LegacyRPCPortFlag,
		TrueValueFlag,
		FeeFlag,
		PubKeyKeyFlag,
		BFTKeyKeyFlag,
	}
)

func init() {
	app = cli.NewApp()
	app.Usage = "UpsChain Impawn tool"
	app.Name = filepath.Base(os.Args[0])
	app.Version = "1.0.0"
	app.Copyright = "Copyright 2019-2020 The UpsChain Authors"
	app.Flags = []cli.Flag{
		KeyFlag,
		KeyStoreFlag,
		utils.LegacyRPCListenAddrFlag,
		utils.LegacyRPCPortFlag,
		TrueValueFlag,
		FeeFlag,
		AddressFlag,
		TxHashFlag,
		PubKeyKeyFlag,
		SnailNumberFlag,
		BFTKeyKeyFlag,
	}
	app.Action = utils.MigrateFlags(impawn)
	app.CommandNotFound = func(ctx *cli.Context, cmd string) {
		fmt.Fprintf(os.Stderr, "No such command: %s\n", cmd)
		os.Exit(1)
	}
	// Add subcommands.
	app.Commands = []cli.Command{
		sendCommand,
		queryTxCommand,
	}
	cli.CommandHelpTemplate = flags.OriginCommandHelpTemplate
	sort.Sort(cli.CommandsByName(app.Commands))
}

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
