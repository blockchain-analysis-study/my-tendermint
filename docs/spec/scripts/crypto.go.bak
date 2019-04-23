package main

import (
	"fmt"
	"os"

	amino "my-tendermint/go-amino"
	cryptoAmino "my-tendermint/tendermint/crypto/encoding/amino"
)

func main() {
	cdc := amino.NewCodec()
	cryptoAmino.RegisterAmino(cdc)
	cdc.PrintTypes(os.Stdout)
	fmt.Println("")
}
