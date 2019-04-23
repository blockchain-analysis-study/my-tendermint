package proxy

import (
	"sync"

	"github.com/pkg/errors"

	abcicli "my-tendermint/tendermint/abci/client"
	"my-tendermint/tendermint/abci/example/counter"
	"my-tendermint/tendermint/abci/example/kvstore"
	"my-tendermint/tendermint/abci/types"
)

// NewABCIClient returns newly connected client
type ClientCreator interface {
	NewABCIClient() (abcicli.Client, error)
}

//----------------------------------------------------
// local proxy uses a mutex on an in-proc app

type localClientCreator struct {
	mtx *sync.Mutex
	app types.Application
}

/**
TODO 这个超级重要， 如果是 cosmos-sdk 调用的话 入参的这个 app 其实就是 GaiaApp 实例

在这里其实就是实现了 ABCI 协议的 Client
 */
func NewLocalClientCreator(app types.Application) ClientCreator {
	return &localClientCreator{
		mtx: new(sync.Mutex),
		app: app,
	}
}

func (l *localClientCreator) NewABCIClient() (abcicli.Client, error) {
	return abcicli.NewLocalClient(l.mtx, l.app), nil
}

//---------------------------------------------------------------
// remote proxy opens new connections to an external app process

type remoteClientCreator struct {
	addr        string
	transport   string
	mustConnect bool
}

func NewRemoteClientCreator(addr, transport string, mustConnect bool) ClientCreator {
	return &remoteClientCreator{
		addr:        addr,
		transport:   transport,
		mustConnect: mustConnect,
	}
}

func (r *remoteClientCreator) NewABCIClient() (abcicli.Client, error) {
	remoteApp, err := abcicli.NewClient(r.addr, r.transport, r.mustConnect)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to connect to proxy")
	}
	return remoteApp, nil
}

//-----------------------------------------------------------------
// default
/***
默认的 自身的client
 */
func DefaultClientCreator(addr, transport, dbDir string) ClientCreator {
	switch addr {
	case "counter":
		return NewLocalClientCreator(counter.NewCounterApplication(false))
	case "counter_serial":
		return NewLocalClientCreator(counter.NewCounterApplication(true))
	case "kvstore":
		return NewLocalClientCreator(kvstore.NewKVStoreApplication())
	case "persistent_kvstore":
		return NewLocalClientCreator(kvstore.NewPersistentKVStoreApplication(dbDir))
	case "noop":
		return NewLocalClientCreator(types.NewBaseApplication())
	default:
		mustConnect := false // loop retrying
		return NewRemoteClientCreator(addr, transport, mustConnect)
	}
}
