package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/marcopoloprotoco/mouse"
	"github.com/marcopoloprotoco/mouse/accounts/keystore"
	"github.com/marcopoloprotoco/mouse/cmd/utils"
	"github.com/marcopoloprotoco/mouse/common"
	"github.com/marcopoloprotoco/mouse/console/prompt"
	"github.com/marcopoloprotoco/mouse/core/types"
	"github.com/marcopoloprotoco/mouse/crypto"
	"github.com/marcopoloprotoco/mouse/mosclient"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var (
	key       string
	store     string
	ip        string
	port      int
	priKey    *ecdsa.PrivateKey
	from      common.Address
	trueValue uint64
	fee       uint64
	holder    common.Address
)

const (
	datadirPrivateKey      = "key"
	datadirDefaultKeyStore = "keystore"
	ImpawnAmount           = 20000
)

func impawn(ctx *cli.Context) error {

	loadPrivate(ctx)

	conn, url := dialConn(ctx)

	printBaseInfo(conn, url)

	PrintBalance(conn, from)

	if trueValue < ImpawnAmount {
		printError("Impawn value must bigger than ", ImpawnAmount)
	}

	return nil
}

func getPubKey(ctx *cli.Context, conn *mosclient.Client) (string, []byte, error) {
	var (
		pubkey string
		err    error
	)

	if ctx.GlobalIsSet(PubKeyKeyFlag.Name) {
		pubkey = ctx.GlobalString(PubKeyKeyFlag.Name)
	} else if ctx.GlobalIsSet(BFTKeyKeyFlag.Name) {
		bftKey, err := crypto.HexToECDSA(ctx.GlobalString(BFTKeyKeyFlag.Name))
		if err != nil {
			printError("bft key error", err)
		}
		pk := crypto.FromECDSAPub(&bftKey.PublicKey)
		pubkey = common.Bytes2Hex(pk)
	}

	pk := common.Hex2Bytes(pubkey)
	return pubkey, pk, err
}

func sendContractTransaction(client *mosclient.Client, from, toAddress common.Address, value *big.Int, privateKey *ecdsa.PrivateKey, input []byte) common.Hash {
	// Ensure a valid value field and resolve the account nonce
	nonce, err := client.PendingNonceAt(context.Background(), from)
	if err != nil {
		log.Fatal(err)
	}

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	gasLimit := uint64(2100000) // in units
	// If the contract surely has code (or code is not needed), estimate the transaction
	msg := mouse.CallMsg{From: from, To: &toAddress, GasPrice: gasPrice, Value: value, Data: input}
	gasLimit, err = client.EstimateGas(context.Background(), msg)
	if err != nil {
		fmt.Println("Contract exec failed", err)
	}
	if gasLimit < 1 {
		gasLimit = 866328
	}

	// Create the transaction, sign it and schedule it for execution
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, input)

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("TX data nonce ", nonce, " transfer value ", value, " gasLimit ", gasLimit, " gasPrice ", gasPrice, " chainID ", chainID)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
	}

	return signedTx.Hash()
}

func createKs() {
	ks := keystore.NewKeyStore("./createKs", keystore.StandardScryptN, keystore.StandardScryptP)
	password := "secret"
	account, err := ks.NewAccount(password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(account.Address.Hex()) // 0x20F8D42FB0F667F2E53930fed426f225752453b3
}

func importKs(password string) common.Address {
	file, err := getAllFile(datadirDefaultKeyStore)
	if err != nil {
		log.Fatal(err)
	}
	cks, _ := filepath.Abs(datadirDefaultKeyStore)

	jsonBytes, err := ioutil.ReadFile(filepath.Join(cks, file))
	if err != nil {
		log.Fatal(err)
	}

	//password := "secret"
	key, err := keystore.DecryptKey(jsonBytes, password)
	if err != nil {
		log.Fatal(err)
	}
	priKey = key.PrivateKey
	from = crypto.PubkeyToAddress(priKey.PublicKey)

	fmt.Println("address ", from.Hex())
	return from
}

func loadPrivateKey(path string) common.Address {
	var err error
	if path == "" {
		file, err := getAllFile(datadirPrivateKey)
		if err != nil {
			printError(" getAllFile file name error", err)
		}
		kab, _ := filepath.Abs(datadirPrivateKey)
		path = filepath.Join(kab, file)
	}
	priKey, err = crypto.LoadECDSA(path)
	if err != nil {
		printError("LoadECDSA error", err)
	}
	from = crypto.PubkeyToAddress(priKey.PublicKey)
	return from
}

func getAllFile(path string) (string, error) {
	rd, err := ioutil.ReadDir(path)
	if err != nil {
		printError("path ", err)
	}
	for _, fi := range rd {
		if fi.IsDir() {
			fmt.Printf("[%s]\n", path+"\\"+fi.Name())
			getAllFile(path + fi.Name() + "\\")
			return "", errors.New("path error")
		} else {
			fmt.Println(path, "dir has ", fi.Name(), "file")
			return fi.Name(), nil
		}
	}
	return "", err
}

func printError(error ...interface{}) {
	log.Fatal(error)
}

func trueToWei(ctx *cli.Context, zero bool) *big.Int {
	trueValue = ctx.GlobalUint64(TrueValueFlag.Name)
	if !zero && trueValue <= 0 {
		printError("Value must bigger than 0")
	}
	baseUnit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	value := new(big.Int).Mul(big.NewInt(int64(trueValue)), baseUnit)
	return value
}

func weiToTrue(value *big.Int) uint64 {
	baseUnit := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	valueT := new(big.Int).Div(value, baseUnit).Uint64()
	return valueT
}

func getResult(conn *mosclient.Client, txHash common.Hash, contract bool, delegate bool) {
	fmt.Println("Please waiting ", " txHash ", txHash.String())

	count := 0
	for {
		time.Sleep(time.Millisecond * 200)
		_, isPending, err := conn.TransactionByHash(context.Background(), txHash)
		if err != nil {
			log.Fatal(err)
		}
		count++
		if !isPending {
			break
		}
		if count >= 40 {
			fmt.Println("Please use querytx sub command query later.")
			os.Exit(0)
		}
	}

	queryTx(conn, txHash, contract, false, delegate)
}

func queryTx(conn *mosclient.Client, txHash common.Hash, contract bool, pending bool, delegate bool) {

	if pending {
		_, isPending, err := conn.TransactionByHash(context.Background(), txHash)
		if err != nil {
			log.Fatal(err)
		}
		if isPending {
			println("In tx_pool no validator  process this, please query later")
			os.Exit(0)
		}
	}

	receipt, err := conn.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		log.Fatal(err)
	}

	if receipt.Status == types.ReceiptStatusSuccessful {
		block, err := conn.BlockByHash(context.Background(), receipt.BlockHash)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Transaction Success", " block Number", receipt.BlockNumber.Uint64(), " block txs", len(block.Transactions()), "blockhash", block.Hash().Hex())
	} else if receipt.Status == types.ReceiptStatusFailed {
		fmt.Println("Transaction Failed ", " Block Number", receipt.BlockNumber.Uint64())
	}
}

func PrintBalance(conn *mosclient.Client, from common.Address) {
	balance, err := conn.BalanceAt(context.Background(), from, nil)
	if err != nil {
		log.Fatal(err)
	}
	fbalance := new(big.Float)
	fbalance.SetString(balance.String())
	trueValue := new(big.Float).Quo(fbalance, big.NewFloat(math.Pow10(18)))

	fmt.Println("Your wallet valid balance is ", trueValue, " true ")
}

func loadPrivate(ctx *cli.Context) {
	key = ctx.GlobalString(KeyFlag.Name)
	store = ctx.GlobalString(KeyStoreFlag.Name)
	if key != "" {
		loadPrivateKey(key)
	} else if store != "" {
		loadSigningKey(store)
	} else {
		printError("Must specify --key or --keystore")
	}

	if priKey == nil {
		printError("load privateKey failed")
	}
}

func dialConn(ctx *cli.Context) (*mosclient.Client, string) {
	ip = ctx.GlobalString(utils.LegacyRPCListenAddrFlag.Name)
	port = ctx.GlobalInt(utils.LegacyRPCPortFlag.Name)

	url := fmt.Sprintf("http://%s", fmt.Sprintf("%s:%d", ip, port))
	// Create an IPC based RPC connection to a remote node
	// "http://39.100.97.129:8545"
	conn, err := mosclient.Dial(url)
	if err != nil {
		log.Fatalf("Failed to connect to the Upschain client: %v", err)
	}
	return conn, url
}

func printBaseInfo(conn *mosclient.Client, url string) *types.Header {
	header, err := conn.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	if common.IsHexAddress(from.Hex()) {
		fmt.Println("Connect url ", url, " current number ", header.Number.String(), " address ", from.Hex())
	} else {
		fmt.Println("Connect url ", url, " current number ", header.Number.String())
	}

	return header
}

// loadSigningKey loads a private key in Ethereum keystore format.
func loadSigningKey(keyfile string) common.Address {
	keyjson, err := ioutil.ReadFile(keyfile)
	if err != nil {
		printError(fmt.Errorf("failed to read the keyfile at '%s': %v", keyfile, err))
	}
	password, _ := prompt.Stdin.PromptPassword("Please enter the password for '" + keyfile + "': ")
	//password := "secret"
	key, err := keystore.DecryptKey(keyjson, password)
	if err != nil {
		printError(fmt.Errorf("error decrypting key: %v", err))
	}
	priKey = key.PrivateKey
	from = crypto.PubkeyToAddress(priKey.PublicKey)
	//fmt.Println("address ", from.Hex(), "key", hex.EncodeToString(crypto.FromECDSA(priKey)))
	return from
}
