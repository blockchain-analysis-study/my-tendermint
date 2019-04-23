package evidence

import (
	amino "my-tendermint/go-amino"
	cryptoAmino "my-tendermint/tendermint/crypto/encoding/amino"
	"my-tendermint/tendermint/types"
)

var cdc = amino.NewCodec()

func init() {
	RegisterEvidenceMessages(cdc)
	cryptoAmino.RegisterAmino(cdc)
	types.RegisterEvidences(cdc)
}

// For testing purposes only
func RegisterMockEvidences() {
	types.RegisterMockEvidences(cdc)
}
