package pubsub_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"my-tendermint/tendermint/libs/log"

	"my-tendermint/tendermint/libs/pubsub"
	"my-tendermint/tendermint/libs/pubsub/query"
)

func TestExample(t *testing.T) {
	s := pubsub.NewServer()
	s.SetLogger(log.TestingLogger())
	s.Start()
	defer s.Stop()

	ctx := context.Background()
	subscription, err := s.Subscribe(ctx, "example-client", query.MustParse("abci.account.name='John'"))
	require.NoError(t, err)
	err = s.PublishWithTags(ctx, "Tombstone", map[string]string{"abci.account.name": "John"})
	require.NoError(t, err)
	assertReceive(t, "Tombstone", subscription.Out())
}
