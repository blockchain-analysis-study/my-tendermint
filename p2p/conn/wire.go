package conn

import (
	amino "my-tendermint/go-amino"
	cryptoAmino "my-tendermint/tendermint/crypto/encoding/amino"
)

var cdc *amino.Codec = amino.NewCodec()

func init() {
	cryptoAmino.RegisterAmino(cdc)
	RegisterPacket(cdc)
}
