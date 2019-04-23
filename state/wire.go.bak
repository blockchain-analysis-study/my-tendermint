package state

import (
	amino "my-tendermint/go-amino"
	cryptoAmino "my-tendermint/tendermint/crypto/encoding/amino"
)

var cdc = amino.NewCodec()

func init() {
	cryptoAmino.RegisterAmino(cdc)
}
