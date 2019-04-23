package node

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"

	amino "my-tendermint/go-amino"
	abci "my-tendermint/tendermint/abci/types"
	bc "my-tendermint/tendermint/blockchain"
	cfg "my-tendermint/tendermint/config"
	cs "my-tendermint/tendermint/consensus"
	"my-tendermint/tendermint/crypto/ed25519"
	"my-tendermint/tendermint/evidence"
	cmn "my-tendermint/tendermint/libs/common"
	dbm "my-tendermint/tendermint/libs/db"
	"my-tendermint/tendermint/libs/log"
	tmpubsub "my-tendermint/tendermint/libs/pubsub"
	mempl "my-tendermint/tendermint/mempool"
	"my-tendermint/tendermint/p2p"
	"my-tendermint/tendermint/p2p/pex"
	"my-tendermint/tendermint/privval"
	"my-tendermint/tendermint/proxy"
	rpccore "my-tendermint/tendermint/rpc/core"
	ctypes "my-tendermint/tendermint/rpc/core/types"
	grpccore "my-tendermint/tendermint/rpc/grpc"
	rpcserver "my-tendermint/tendermint/rpc/lib/server"
	sm "my-tendermint/tendermint/state"
	"my-tendermint/tendermint/state/txindex"
	"my-tendermint/tendermint/state/txindex/kv"
	"my-tendermint/tendermint/state/txindex/null"
	"my-tendermint/tendermint/types"
	tmtime "my-tendermint/tendermint/types/time"
	"my-tendermint/tendermint/version"
)

//------------------------------------------------------------------------------

// DBContext specifies config information for loading a new DB.
type DBContext struct {
	ID     string
	Config *cfg.Config
}

// DBProvider takes a DBContext and returns an instantiated DB.
type DBProvider func(*DBContext) (dbm.DB, error)

// DefaultDBProvider returns a database using the DBBackend and DBDir
// specified in the ctx.Config.
/**
在 cosmos-sdk中会调用这个传给 new 一个tendermint node 的函数
 */
func DefaultDBProvider(ctx *DBContext) (dbm.DB, error) {
	dbType := dbm.DBBackendType(ctx.Config.DBBackend)
	return dbm.NewDB(ctx.ID, dbType, ctx.Config.DBDir()), nil
}

// GenesisDocProvider returns a GenesisDoc.
// It allows the GenesisDoc to be pulled from sources other than the
// filesystem, for instance from a distributed key-value store cluster.
type GenesisDocProvider func() (*types.GenesisDoc, error)

// DefaultGenesisDocProviderFunc returns a GenesisDocProvider that loads
// the GenesisDoc from the config.GenesisFile() on the filesystem.
func DefaultGenesisDocProviderFunc(config *cfg.Config) GenesisDocProvider {
	return func() (*types.GenesisDoc, error) {
		return types.GenesisDocFromFile(config.GenesisFile())
	}
}

// NodeProvider takes a config and a logger and returns a ready to go Node.
type NodeProvider func(*cfg.Config, log.Logger) (*Node, error)

// DefaultNewNode returns a Tendermint node with default settings for the
// PrivValidator, ClientCreator, GenesisDoc, and DBProvider.
// It implements NodeProvider.
func DefaultNewNode(config *cfg.Config, logger log.Logger) (*Node, error) {
	// Generate node PrivKey
	nodeKey, err := p2p.LoadOrGenNodeKey(config.NodeKeyFile())
	if err != nil {
		return nil, err
	}

	// Convert old PrivValidator if it exists.
	oldPrivVal := config.OldPrivValidatorFile()
	newPrivValKey := config.PrivValidatorKeyFile()
	newPrivValState := config.PrivValidatorStateFile()
	if _, err := os.Stat(oldPrivVal); !os.IsNotExist(err) {
		oldPV, err := privval.LoadOldFilePV(oldPrivVal)
		if err != nil {
			return nil, fmt.Errorf("Error reading OldPrivValidator from %v: %v\n", oldPrivVal, err)
		}
		logger.Info("Upgrading PrivValidator file",
			"old", oldPrivVal,
			"newKey", newPrivValKey,
			"newState", newPrivValState,
		)
		oldPV.Upgrade(newPrivValKey, newPrivValState)
	}

	/**
	创建一个 tendermint 节点
	 */
	return NewNode(config,
		privval.LoadOrGenFilePV(newPrivValKey, newPrivValState),
		nodeKey,
		proxy.DefaultClientCreator(config.ProxyApp, config.ABCI, config.DBDir()),
		DefaultGenesisDocProviderFunc(config),
		/**
		创建 DB生产者
		 */
		DefaultDBProvider,
		DefaultMetricsProvider(config.Instrumentation),
		logger,
	)
}

// MetricsProvider returns a consensus, p2p and mempool Metrics.
type MetricsProvider func(chainID string) (*cs.Metrics, *p2p.Metrics, *mempl.Metrics, *sm.Metrics)

// DefaultMetricsProvider returns Metrics build using Prometheus client library
// if Prometheus is enabled. Otherwise, it returns no-op Metrics.
func DefaultMetricsProvider(config *cfg.InstrumentationConfig) MetricsProvider {
	return func(chainID string) (*cs.Metrics, *p2p.Metrics, *mempl.Metrics, *sm.Metrics) {
		if config.Prometheus {
			return cs.PrometheusMetrics(config.Namespace, "chain_id", chainID),
				p2p.PrometheusMetrics(config.Namespace, "chain_id", chainID),
				mempl.PrometheusMetrics(config.Namespace, "chain_id", chainID),
				sm.PrometheusMetrics(config.Namespace, "chain_id", chainID)
		}
		return cs.NopMetrics(), p2p.NopMetrics(), mempl.NopMetrics(), sm.NopMetrics()
	}
}

//------------------------------------------------------------------------------

// Node is the highest level interface to a full Tendermint node.
// It includes all configuration information and running services.
type Node struct {
	cmn.BaseService

	// config
	config        *cfg.Config
	genesisDoc    *types.GenesisDoc   // initial validator set
	privValidator types.PrivValidator // local node's validator key

	// network
	transport   *p2p.MultiplexTransport
	sw          *p2p.Switch  // p2p connections
	addrBook    pex.AddrBook // known peers
	nodeInfo    p2p.NodeInfo
	nodeKey     *p2p.NodeKey // our node privkey
	isListening bool

	// services
	eventBus         *types.EventBus // pub/sub for services
	stateDB          dbm.DB
	blockStore       *bc.BlockStore         // store the blockchain to disk
	bcReactor        *bc.BlockchainReactor  // for fast-syncing
	mempoolReactor   *mempl.MempoolReactor  // for gossipping transactions
	consensusState   *cs.ConsensusState     // latest consensus state
	consensusReactor *cs.ConsensusReactor   // for participating in the consensus
	evidencePool     *evidence.EvidencePool // tracking evidence
	proxyApp         proxy.AppConns         // connection to the application
	rpcListeners     []net.Listener         // rpc servers
	txIndexer        txindex.TxIndexer
	indexerService   *txindex.IndexerService
	prometheusSrv    *http.Server
}

// NewNode returns a new, ready to go, Tendermint Node.
/**
创建一个 tendermint 节点

TODO 注意： 如果是 cosmos-sdk 调用的话，最终会在 startInProcess 中调用该方法，生成一个 tendermint node
 */
func NewNode(config *cfg.Config,
	// 一个可以签署 votes 和 proposals 的本地Tendermint验证器
	privValidator types.PrivValidator,
	// 节点的 nodeKey
	nodeKey *p2p.NodeKey,
	// client的创建器
	clientCreator proxy.ClientCreator,
	// 创世文件的 生产函数
	genesisDocProvider GenesisDocProvider,

	// 如果是 cosmos-sdk 的话，这里会是： node.DefaultDBProvider
	dbProvider DBProvider,
	// 统计用的
	metricsProvider MetricsProvider,
	logger log.Logger) (*Node, error) {

	// Get BlockStore
	// 初始化blockstore数据库
	blockStoreDB, err := dbProvider(&DBContext{"blockstore", config})
	if err != nil {
		return nil, err
	}

	// 返回了个blockStoreDB的包装层，里面还包含了 链上最高块的 height
	blockStore := bc.NewBlockStore(blockStoreDB)

	// Get State
	// 初始化state数据库
	stateDB, err := dbProvider(&DBContext{"state", config})
	if err != nil {
		return nil, err
	}

	// Get genesis doc
	// TODO: move to state package?
	// 从硬盘上读取创世文件
	genDoc, err := loadGenesisDoc(stateDB)
	if err != nil {
		genDoc, err = genesisDocProvider()
		if err != nil {
			return nil, err
		}
		// save genesis doc to prevent a certain class of user errors (e.g. when it
		// was changed, accidentally or not). Also good for audit trail.
		saveGenesisDoc(stateDB, genDoc)
	}


	/**
	TODO 注意了这一步超级重要
	从DB中加载 创世快的 state
	 */
	state, err := sm.LoadStateFromDBOrGenesisDoc(stateDB, genDoc)
	if err != nil {
		return nil, err
	}

	// Create the proxyApp and establish connections to the ABCI app (consensus, mempool, query).
	/**
	创建proxyApp并建立与ABCI应用程序的连接（共识，mempool，查询）。
	 */
	proxyApp := proxy.NewAppConns(clientCreator)
	proxyApp.SetLogger(logger.With("module", "proxy"))
	// 启动这个 proxyApp (a tendermint client)
	if err := proxyApp.Start(); err != nil {
		return nil, fmt.Errorf("Error starting proxy app connections: %v", err)
	}

	// EventBus and IndexerService must be started before the handshake because
	// we might need to index the txs of the replayed block as this might not have happened
	// when the node stopped last time (i.e. the node stopped after it saved the block
	// but before it indexed the txs, or, endblocker panicked)
	/**
	todo : 必须在 handshake 之前启动EventBus和IndexerService，
	因为我们可能需要索引重放块的txs，
	因为当节点上次停止时可能没有发生这种情况
	（即节点在保存块之后但在索引tx之前停止， 或者，endblocker 发生了 panic）
	 */
	eventBus := types.NewEventBus()
	eventBus.SetLogger(logger.With("module", "events"))

	// 启动 事件 bus
	err = eventBus.Start()
	if err != nil {
		return nil, err
	}

	// Transaction indexing
	// tx的 索引器 ??
	var txIndexer txindex.TxIndexer
	switch config.TxIndex.Indexer {
	case "kv":
		store, err := dbProvider(&DBContext{"tx_index", config})
		if err != nil {
			return nil, err
		}
		if config.TxIndex.IndexTags != "" {
			txIndexer = kv.NewTxIndex(store, kv.IndexTags(splitAndTrimEmpty(config.TxIndex.IndexTags, ",", " ")))
		} else if config.TxIndex.IndexAllTags {
			txIndexer = kv.NewTxIndex(store, kv.IndexAllTags())
		} else {
			txIndexer = kv.NewTxIndex(store)
		}
	default:
		txIndexer = &null.TxIndex{}
	}

	/**
	索引服务
	 */
	indexerService := txindex.NewIndexerService(txIndexer, eventBus)
	indexerService.SetLogger(logger.With("module", "txindex"))

	err = indexerService.Start()
	if err != nil {
		return nil, err
	}

	// Create the handshaker, which calls RequestInfo, sets the AppVersion on the state,
	// and replays any blocks as necessary to sync tendermint with the app.
	/**
	创建调用RequestInfo的握手，在状态上设置AppVersion，
	并根据需要重放任何块以与应用程序同步tendermint。
	 */
	consensusLogger := logger.With("module", "consensus")
	handshaker := cs.NewHandshaker(stateDB, state, blockStore, genDoc)
	handshaker.SetLogger(consensusLogger)
	handshaker.SetEventBus(eventBus)

	/**
	处理 P2P 握手(handshake)？？ TODO
	 */
	if err := handshaker.Handshake(proxyApp); err != nil {
		return nil, fmt.Errorf("Error during handshake: %v", err)
	}

	// Reload the state. It will have the Version.Consensus.App set by the
	// Handshake, and may have other modifications as well (ie. depending on
	// what happened during block replay).
	/**
	加载当前最新的 state
	 */
	state = sm.LoadState(stateDB)

	// Log the version info.
	logger.Info("Version info",
		"software", version.TMCoreSemVer,
		"block", version.BlockProtocol,
		"p2p", version.P2PProtocol,
	)

	// If the state and software differ in block version, at least log it.
	// 如果state和软件的block版本不同，请至少记录它。记录下日志
	if state.Version.Consensus.Block != version.BlockProtocol {
		logger.Info("Software and state have different block protocols",
			"software", version.BlockProtocol,
			"state", state.Version.Consensus.Block,
		)
	}

	//
	if config.PrivValidatorListenAddr != "" {
		// If an address is provided, listen on the socket for a connection from an
		// external signing process.
		//
		// 如果提供了地址，请在套接字上侦听来自外部签名过程的连接。
		// FIXME: we should start services inside OnStart
		// FIXME：我们应该在OnStart中启动服务
		privValidator, err = createAndStartPrivValidatorSocketClient(config.PrivValidatorListenAddr, logger)
		if err != nil {
			return nil, errors.Wrap(err, "Error with private validator socket client")
		}
	}

	// Decide whether to fast-sync or not
	// We don't fast-sync when the only validator is us.
	/**
	决定是否快速同步
	当唯一的验证器是我们时，我们不会快速同步。
	 */
	fastSync := config.FastSync   // //默认开启快速同步
	if state.Validators.Size() == 1 {
		addr, _ := state.Validators.GetByIndex(0)   //返回验证人的地址
		privValAddr := privValidator.GetPubKey().Address()
		if bytes.Equal(privValAddr, addr) { //如果只有一个验证者，禁用快速同步
			fastSync = false
		}
	}

	/**
	获取当前节点公钥
	 */
	pubKey := privValidator.GetPubKey()
	addr := pubKey.Address()
	// Log whether this node is a validator or an observer
	// Log（打印日志） whether this node is a validator or an observer（观察者）
	if state.Validators.HasAddress(addr) {
		// 当前节点的pubkey 是当前验证人
		consensusLogger.Info("This node is a validator", "addr", addr, "pubKey", pubKey)
	} else {
		// 当前节点的pubkey 不是当前验证人
		consensusLogger.Info("This node is not a validator", "addr", addr, "pubKey", pubKey)
	}

	// 创建各种 统计生产器
	csMetrics, p2pMetrics, memplMetrics, smMetrics := metricsProvider(genDoc.ChainID)

	// Make MempoolReactor
	/**
	创建交易池
	 */
	mempool := mempl.NewMempool(
		config.Mempool,
		proxyApp.Mempool(),
		state.LastBlockHeight,
		mempl.WithMetrics(memplMetrics),
		mempl.WithPreCheck(sm.TxPreCheck(state)),
		mempl.WithPostCheck(sm.TxPostCheck(state)),
	)

	// 交易池相关的logger
	mempoolLogger := logger.With("module", "mempool")
	mempool.SetLogger(mempoolLogger)
	if config.Mempool.WalEnabled() {
		mempool.InitWAL() // no need to have the mempool wal during tests
	}

	/**
	根绝交易池和配置项创建 交易反应器
	 */
	mempoolReactor := mempl.NewMempoolReactor(config.Mempool, mempool)
	mempoolReactor.SetLogger(mempoolLogger)

	// 确保实时 监听交易池的可用tx
	if config.Consensus.WaitForTxs() {
		mempool.EnableTxsAvailable()
	}

	// Make Evidence Reactor
	/**
	创建 凭证反应器 (跨链用 ??)
	 */
	evidenceDB, err := dbProvider(&DBContext{"evidence", config})
	if err != nil {
		return nil, err
	}
	evidenceLogger := logger.With("module", "evidence")
	evidencePool := evidence.NewEvidencePool(stateDB, evidenceDB)
	evidencePool.SetLogger(evidenceLogger)
	//
	evidenceReactor := evidence.NewEvidenceReactor(evidencePool)
	evidenceReactor.SetLogger(evidenceLogger)

	blockExecLogger := logger.With("module", "state")
	// make block executor for consensus and blockchain reactors to execute blocks
	/**
	初始化 区块执行器
	使块执行器达成共识，并使区块链反应器执行块
	 */
	blockExec := sm.NewBlockExecutor(
		stateDB,
		blockExecLogger,

		/** TODO 创建proxyApp并建立与ABCI应用程序的连接（共识，mempool，查询）。 */
		proxyApp.Consensus(),
		mempool,
		evidencePool,
		sm.BlockExecutorWithMetrics(smMetrics),
	)

	// Make BlockchainReactor
	/**
	创建 链反应器
	 */
	bcReactor := bc.NewBlockchainReactor(state.Copy(), blockExec, blockStore, fastSync)
	bcReactor.SetLogger(logger.With("module", "blockchain"))

	// Make ConsensusReactor
	/**
	创建共识 state
	 */
	consensusState := cs.NewConsensusState(
		config.Consensus,
		state.Copy(),
		blockExec,
		blockStore,
		mempool,
		evidencePool,
		cs.StateMetrics(csMetrics),
	)
	consensusState.SetLogger(consensusLogger)
	if privValidator != nil {
		consensusState.SetPrivValidator(privValidator)
	}

	/**
	创建共识 反应器
	 */
	consensusReactor := cs.NewConsensusReactor(consensusState, fastSync, cs.ReactorMetrics(csMetrics))
	consensusReactor.SetLogger(consensusLogger)

	// services which will be publishing and/or subscribing for messages (events)
	// consensusReactor will set it on consensusState and blockExecutor
	consensusReactor.SetEventBus(eventBus)

	p2pLogger := logger.With("module", "p2p")

	/**
	创建一个 node 的基础信息
	 */
	nodeInfo, err := makeNodeInfo(
		config,
		nodeKey.ID(),
		txIndexer,
		genDoc.ChainID,
		p2p.NewProtocolVersion(
			version.P2PProtocol, // global
			state.Version.Consensus.Block,
			state.Version.Consensus.App,
		),
	)
	if err != nil {
		return nil, err
	}

	// Setup Transport.
	// 设置 传输 相关
	var (
		// MConnConfig返回一个MConnConfig，其中包含从P2PConfig更新的字段。
		mConnConfig = p2p.MConnConfig(config.P2P)
		// NewMultiplexTransport返回一个连接tcp的多路复用 peer。
		transport   = p2p.NewMultiplexTransport(nodeInfo, *nodeKey, mConnConfig)

		// p2p连接过滤器
		connFilters = []p2p.ConnFilterFunc{}
		// p2p节点过滤器
		peerFilters = []p2p.PeerFilterFunc{}
	)

	// 不允许重复IP
	if !config.P2P.AllowDuplicateIP {
		// 添加重复IP的连接过滤器
		connFilters = append(connFilters, p2p.ConnDuplicateIPFilter())
	}

	// Filter peers by addr or pubkey with an ABCI query.
	// If the query return code is OK, add peer.
	/**
	使用addr或pubkey通过ABCI查询过滤 peers。
	如果查询返回代码是OK，则添加peer。
	 */
	if config.FilterPeers {
		// 添加 连接过滤
		connFilters = append(
			connFilters,
			// ABCI query for address filtering.
			func(_ p2p.ConnSet, c net.Conn, _ []net.IP) error {
				res, err := proxyApp.Query().QuerySync(abci.RequestQuery{
					Path: fmt.Sprintf("/p2p/filter/addr/%s", c.RemoteAddr().String()),
				})
				if err != nil {
					return err
				}
				if res.IsErr() {
					return fmt.Errorf("Error querying abci app: %v", res)
				}

				return nil
			},
		)

		// 添加 peer 过滤
		peerFilters = append(
			peerFilters,
			// ABCI query for ID filtering.
			func(_ p2p.IPeerSet, p p2p.Peer) error {
				res, err := proxyApp.Query().QuerySync(abci.RequestQuery{
					Path: fmt.Sprintf("/p2p/filter/id/%s", p.ID()),
				})
				if err != nil {
					return err
				}
				if res.IsErr() {
					return fmt.Errorf("Error querying abci app: %v", res)
				}

				return nil
			},
		)
	}

	// MultiplexTransportConnFilters设置拒绝新连接的过滤器。
	p2p.MultiplexTransportConnFilters(connFilters...)(transport)

	// Setup Switch.
	/**
	设置  P2P开关 实例 (交换机 ??)
	 */
	sw := p2p.NewSwitch(
		config.P2P,
		transport,
		p2p.WithMetrics(p2pMetrics),
		// SwitchPeerFilters设置拒绝新 peers 的过滤器。
		p2p.SwitchPeerFilters(peerFilters...),
	)
	// 添加 p2p logger
	sw.SetLogger(p2pLogger)
	// 添加 mempool反应器
	sw.AddReactor("MEMPOOL", mempoolReactor)
	// 添加 blockchain反应器
	sw.AddReactor("BLOCKCHAIN", bcReactor)
	// 添加 共识反应器
	sw.AddReactor("CONSENSUS", consensusReactor)
	// 添加 凭证反应器
	sw.AddReactor("EVIDENCE", evidenceReactor)
	// 添加 节点基础信息
	sw.SetNodeInfo(nodeInfo)
	// 添加 nodeKey
	sw.SetNodeKey(nodeKey)

	p2pLogger.Info("P2P Node ID", "ID", nodeKey.ID(), "file", config.NodeKeyFile())

	// Optionally, start the pex reactor
	//
	// TODO:
	//
	// We need to set Seeds and PersistentPeers on the switch,
	// since it needs to be able to use these (and their DNS names)
	// even if the PEX is off. We can include the DNS name in the NetAddress,
	// but it would still be nice to have a clear list of the current "PersistentPeers"
	// somewhere that we can return with net_info.
	//
	// If PEX is on, it should handle dialing the seeds. Otherwise the switch does it.
	// Note we currently use the addrBook regardless at least for AddOurAddress
	/**
	可选的，启动 pex反应器 （peer交换反应器  peer-exchange reactor）

	我们需要在 P2P开关 上设置Seeds （种子节点?）和 PersistentPeers （内置节点?），
	因为即使PEX关闭，它也需要能够使用这些（及其DNS名称）。
	我们可以在NetAddress中包含DNS名称，
	但是我们可以使用net_info返回当前“PersistentPeers”的清单，
	这仍然很好。


	如果PEX打开，它应该处理 连接种子节点。 否则开关会这样做。
	注意我们目前使用addrBook，至少对于AddOurAddress
	 */
	// 创建地址 字典 (硬编码种子节点 ?)
	addrBook := pex.NewAddrBook(config.P2P.AddrBookFile(), config.P2P.AddrBookStrict)

	// Add ourselves to addrbook to prevent dialing ourselves
	// 将自己添加到addrbook以防止 连接自己
	addrBook.AddOurAddress(sw.NetAddress())


	addrBook.SetLogger(p2pLogger.With("book", config.P2P.AddrBookFile()))

	// 如果 启用 pex 反应器的话
	if config.P2P.PexReactor {
		// TODO persistent peers ? so we can have their DNS addrs saved
		// TODO 持久的 peers？ 所以我们可以保存他们的DNS地址
		// 创建一个 pex 反应器实例
		pexReactor := pex.NewPEXReactor(addrBook,
			&pex.PEXReactorConfig{
				Seeds:    splitAndTrimEmpty(config.P2P.Seeds, ",", " "),
				SeedMode: config.P2P.SeedMode,
			})
		pexReactor.SetLogger(logger.With("module", "pex"))

		// 将pex 反应器添加到 p2p 开关
		sw.AddReactor("PEX", pexReactor)
	}

	// 将地址字典 添加到 p2p 开关
	sw.SetAddrBook(addrBook)

	// run the profile server
	// 运行配置文件服务器
	//
	// 或全部当前node的监听地址
	profileHost := config.ProfListenAddress
	if profileHost != "" {
		go func() {
			logger.Error("Profile server", "err", http.ListenAndServe(profileHost, nil))
		}()
	}

	/**
	TODO
	初始化一个 tendermint 的node实例
	 */
	node := &Node{
		// 配置
		config:        config,
		// 创世文件
		genesisDoc:    genDoc,
		// 一个可以签署 votes 和 proposals 的本地Tendermint验证器
		privValidator: privValidator,
		// 一个连接tcp的多路复用 peer。（传输器 相关）
		transport: transport,
		//  p2p 开关
		sw:        sw,
		// 地址字典
		addrBook:  addrBook,
		// 当前节点的node的基础信息
		nodeInfo:  nodeInfo,
		// 当前节点的nodeKey
		nodeKey:   nodeKey,

		// 当前的stateDB (state/state.go)
		stateDB:          stateDB,
		// blockStoreDB的包装层，里面还包含了 链上最高块的 height
		blockStore:       blockStore,
		/* 创建一个blockchain 的反应器 */
		bcReactor:        bcReactor,
		/* 创建一个 交易池的 反应器 */
		mempoolReactor:   mempoolReactor,
		/* 共识state */
		consensusState:   consensusState,
		/* 共识反应器 */
		consensusReactor: consensusReactor,
		/* 凭证pool */
		evidencePool:     evidencePool,
		//  proxyApp并建立与ABCI应用程序的连接（共识，mempool，查询）。
		proxyApp:         proxyApp,
		// tx的 索引器
		txIndexer:        txIndexer,
		// 索引服务
		indexerService:   indexerService,
		// 事件 bus
		eventBus:         eventBus,
	}

	/**
	最后将该node实例添加到 BaseService
	 */
	node.BaseService = *cmn.NewBaseService(logger, "Node", node)
	// 返回一个 tendermint 节点实例
	return node, nil
}

// OnStart starts the Node. It implements cmn.Service.
// OnStart启动Node。 它实现了cmn.Service。
func (n *Node) OnStart() error {
	now := tmtime.Now()
	genTime := n.genesisDoc.GenesisTime
	if genTime.After(now) {
		n.Logger.Info("Genesis time is in the future. Sleeping until then...", "genTime", genTime)
		time.Sleep(genTime.Sub(now))
	}

	// Add private IDs to addrbook to block those peers being added
	n.addrBook.AddPrivateIDs(splitAndTrimEmpty(n.config.P2P.PrivatePeerIDs, ",", " "))

	// Start the RPC server before the P2P server
	// so we can eg. receive txs for the first block
	if n.config.RPC.ListenAddress != "" {
		listeners, err := n.startRPC()
		if err != nil {
			return err
		}
		n.rpcListeners = listeners
	}

	if n.config.Instrumentation.Prometheus &&
		n.config.Instrumentation.PrometheusListenAddr != "" {
		n.prometheusSrv = n.startPrometheusServer(n.config.Instrumentation.PrometheusListenAddr)
	}

	// Start the transport.
	addr, err := p2p.NewNetAddressStringWithOptionalID(n.config.P2P.ListenAddress)
	if err != nil {
		return err
	}
	if err := n.transport.Listen(*addr); err != nil {
		return err
	}

	n.isListening = true

	// Start the switch (the P2P server).
	err = n.sw.Start()
	if err != nil {
		return err
	}

	// Always connect to persistent peers
	if n.config.P2P.PersistentPeers != "" {
		err = n.sw.DialPeersAsync(n.addrBook, splitAndTrimEmpty(n.config.P2P.PersistentPeers, ",", " "), true)
		if err != nil {
			return err
		}
	}

	return nil
}

// OnStop stops the Node. It implements cmn.Service.
// OnStop停止节点。 它实现了cmn.Service。
func (n *Node) OnStop() {
	n.BaseService.OnStop()

	n.Logger.Info("Stopping Node")

	// first stop the non-reactor services
	n.eventBus.Stop()
	n.indexerService.Stop()

	// now stop the reactors
	// TODO: gracefully disconnect from peers.
	n.sw.Stop()

	// stop mempool WAL
	if n.config.Mempool.WalEnabled() {
		n.mempoolReactor.Mempool.CloseWAL()
	}

	if err := n.transport.Close(); err != nil {
		n.Logger.Error("Error closing transport", "err", err)
	}

	n.isListening = false

	// finally stop the listeners / external services
	for _, l := range n.rpcListeners {
		n.Logger.Info("Closing rpc listener", "listener", l)
		if err := l.Close(); err != nil {
			n.Logger.Error("Error closing listener", "listener", l, "err", err)
		}
	}

	if pvsc, ok := n.privValidator.(cmn.Service); ok {
		pvsc.Stop()
	}

	if n.prometheusSrv != nil {
		if err := n.prometheusSrv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			n.Logger.Error("Prometheus HTTP server Shutdown", "err", err)
		}
	}
}

// ConfigureRPC sets all variables in rpccore so they will serve
// rpc calls from this node
func (n *Node) ConfigureRPC() {
	rpccore.SetStateDB(n.stateDB)
	rpccore.SetBlockStore(n.blockStore)
	rpccore.SetConsensusState(n.consensusState)
	rpccore.SetMempool(n.mempoolReactor.Mempool)
	rpccore.SetEvidencePool(n.evidencePool)
	rpccore.SetP2PPeers(n.sw)
	rpccore.SetP2PTransport(n)
	pubKey := n.privValidator.GetPubKey()
	rpccore.SetPubKey(pubKey)
	rpccore.SetGenesisDoc(n.genesisDoc)
	rpccore.SetAddrBook(n.addrBook)
	rpccore.SetProxyAppQuery(n.proxyApp.Query())
	rpccore.SetTxIndexer(n.txIndexer)
	rpccore.SetConsensusReactor(n.consensusReactor)
	rpccore.SetEventBus(n.eventBus)
	rpccore.SetLogger(n.Logger.With("module", "rpc"))
	rpccore.SetConfig(*n.config.RPC)
}

func (n *Node) startRPC() ([]net.Listener, error) {
	n.ConfigureRPC()
	listenAddrs := splitAndTrimEmpty(n.config.RPC.ListenAddress, ",", " ")
	coreCodec := amino.NewCodec()
	ctypes.RegisterAmino(coreCodec)

	if n.config.RPC.Unsafe {
		rpccore.AddUnsafeRoutes()
	}

	// we may expose the rpc over both a unix and tcp socket
	listeners := make([]net.Listener, len(listenAddrs))
	for i, listenAddr := range listenAddrs {
		mux := http.NewServeMux()
		rpcLogger := n.Logger.With("module", "rpc-server")
		wmLogger := rpcLogger.With("protocol", "websocket")
		wm := rpcserver.NewWebsocketManager(rpccore.Routes, coreCodec,
			rpcserver.OnDisconnect(func(remoteAddr string) {
				err := n.eventBus.UnsubscribeAll(context.Background(), remoteAddr)
				if err != nil && err != tmpubsub.ErrSubscriptionNotFound {
					wmLogger.Error("Failed to unsubscribe addr from events", "addr", remoteAddr, "err", err)
				}
			}))
		wm.SetLogger(wmLogger)
		mux.HandleFunc("/websocket", wm.WebsocketHandler)
		rpcserver.RegisterRPCFuncs(mux, rpccore.Routes, coreCodec, rpcLogger)

		config := rpcserver.DefaultConfig()
		config.MaxOpenConnections = n.config.RPC.MaxOpenConnections
		// If necessary adjust global WriteTimeout to ensure it's greater than
		// TimeoutBroadcastTxCommit.
		// See https://my-tendermint/tendermint/issues/3435
		if config.WriteTimeout <= n.config.RPC.TimeoutBroadcastTxCommit {
			config.WriteTimeout = n.config.RPC.TimeoutBroadcastTxCommit + 1*time.Second
		}

		listener, err := rpcserver.Listen(
			listenAddr,
			config,
		)
		if err != nil {
			return nil, err
		}

		var rootHandler http.Handler = mux
		if n.config.RPC.IsCorsEnabled() {
			corsMiddleware := cors.New(cors.Options{
				AllowedOrigins: n.config.RPC.CORSAllowedOrigins,
				AllowedMethods: n.config.RPC.CORSAllowedMethods,
				AllowedHeaders: n.config.RPC.CORSAllowedHeaders,
			})
			rootHandler = corsMiddleware.Handler(mux)
		}
		if n.config.RPC.IsTLSEnabled() {
			go rpcserver.StartHTTPAndTLSServer(
				listener,
				rootHandler,
				n.config.RPC.CertFile(),
				n.config.RPC.KeyFile(),
				rpcLogger,
				config,
			)
		} else {
			go rpcserver.StartHTTPServer(
				listener,
				rootHandler,
				rpcLogger,
				config,
			)
		}

		listeners[i] = listener
	}

	// we expose a simplified api over grpc for convenience to app devs
	grpcListenAddr := n.config.RPC.GRPCListenAddress
	if grpcListenAddr != "" {
		config := rpcserver.DefaultConfig()
		config.MaxOpenConnections = n.config.RPC.MaxOpenConnections
		listener, err := rpcserver.Listen(grpcListenAddr, config)
		if err != nil {
			return nil, err
		}
		go grpccore.StartGRPCServer(listener)
		listeners = append(listeners, listener)
	}

	return listeners, nil
}

// startPrometheusServer starts a Prometheus HTTP server, listening for metrics
// collectors on addr.
func (n *Node) startPrometheusServer(addr string) *http.Server {
	srv := &http.Server{
		Addr: addr,
		Handler: promhttp.InstrumentMetricHandler(
			prometheus.DefaultRegisterer, promhttp.HandlerFor(
				prometheus.DefaultGatherer,
				promhttp.HandlerOpts{MaxRequestsInFlight: n.config.Instrumentation.MaxOpenConnections},
			),
		),
	}
	go func() {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// Error starting or closing listener:
			n.Logger.Error("Prometheus HTTP server ListenAndServe", "err", err)
		}
	}()
	return srv
}

// Switch returns the Node's Switch.
func (n *Node) Switch() *p2p.Switch {
	return n.sw
}

// BlockStore returns the Node's BlockStore.
func (n *Node) BlockStore() *bc.BlockStore {
	return n.blockStore
}

// ConsensusState returns the Node's ConsensusState.
func (n *Node) ConsensusState() *cs.ConsensusState {
	return n.consensusState
}

// ConsensusReactor returns the Node's ConsensusReactor.
func (n *Node) ConsensusReactor() *cs.ConsensusReactor {
	return n.consensusReactor
}

// MempoolReactor returns the Node's MempoolReactor.
func (n *Node) MempoolReactor() *mempl.MempoolReactor {
	return n.mempoolReactor
}

// EvidencePool returns the Node's EvidencePool.
func (n *Node) EvidencePool() *evidence.EvidencePool {
	return n.evidencePool
}

// EventBus returns the Node's EventBus.
func (n *Node) EventBus() *types.EventBus {
	return n.eventBus
}

// PrivValidator returns the Node's PrivValidator.
// XXX: for convenience only!
func (n *Node) PrivValidator() types.PrivValidator {
	return n.privValidator
}

// GenesisDoc returns the Node's GenesisDoc.
func (n *Node) GenesisDoc() *types.GenesisDoc {
	return n.genesisDoc
}

// ProxyApp returns the Node's AppConns, representing its connections to the ABCI application.
func (n *Node) ProxyApp() proxy.AppConns {
	return n.proxyApp
}

// Config returns the Node's config.
func (n *Node) Config() *cfg.Config {
	return n.config
}

//------------------------------------------------------------------------------

func (n *Node) Listeners() []string {
	return []string{
		fmt.Sprintf("Listener(@%v)", n.config.P2P.ExternalAddress),
	}
}

func (n *Node) IsListening() bool {
	return n.isListening
}

// NodeInfo returns the Node's Info from the Switch.
func (n *Node) NodeInfo() p2p.NodeInfo {
	return n.nodeInfo
}

func makeNodeInfo(
	config *cfg.Config,
	nodeID p2p.ID,
	txIndexer txindex.TxIndexer,
	chainID string,
	protocolVersion p2p.ProtocolVersion,
) (p2p.NodeInfo, error) {
	txIndexerStatus := "on"
	if _, ok := txIndexer.(*null.TxIndex); ok {
		txIndexerStatus = "off"
	}
	nodeInfo := p2p.DefaultNodeInfo{
		ProtocolVersion: protocolVersion,
		ID_:             nodeID,
		Network:         chainID,
		Version:         version.TMCoreSemVer,
		Channels: []byte{
			bc.BlockchainChannel,
			cs.StateChannel, cs.DataChannel, cs.VoteChannel, cs.VoteSetBitsChannel,
			mempl.MempoolChannel,
			evidence.EvidenceChannel,
		},
		Moniker: config.Moniker,
		Other: p2p.DefaultNodeInfoOther{
			TxIndex:    txIndexerStatus,
			RPCAddress: config.RPC.ListenAddress,
		},
	}

	if config.P2P.PexReactor {
		nodeInfo.Channels = append(nodeInfo.Channels, pex.PexChannel)
	}

	lAddr := config.P2P.ExternalAddress

	if lAddr == "" {
		lAddr = config.P2P.ListenAddress
	}

	nodeInfo.ListenAddr = lAddr

	err := nodeInfo.Validate()
	return nodeInfo, err
}

//------------------------------------------------------------------------------

var (
	genesisDocKey = []byte("genesisDoc")
)

// panics if failed to unmarshal bytes
func loadGenesisDoc(db dbm.DB) (*types.GenesisDoc, error) {
	bytes := db.Get(genesisDocKey)
	if len(bytes) == 0 {
		return nil, errors.New("Genesis doc not found")
	}
	var genDoc *types.GenesisDoc
	err := cdc.UnmarshalJSON(bytes, &genDoc)
	if err != nil {
		cmn.PanicCrisis(fmt.Sprintf("Failed to load genesis doc due to unmarshaling error: %v (bytes: %X)", err, bytes))
	}
	return genDoc, nil
}

// panics if failed to marshal the given genesis document
func saveGenesisDoc(db dbm.DB, genDoc *types.GenesisDoc) {
	bytes, err := cdc.MarshalJSON(genDoc)
	if err != nil {
		cmn.PanicCrisis(fmt.Sprintf("Failed to save genesis doc due to marshaling error: %v", err))
	}
	db.SetSync(genesisDocKey, bytes)
}

func createAndStartPrivValidatorSocketClient(
	listenAddr string,
	logger log.Logger,
) (types.PrivValidator, error) {
	var listener net.Listener

	protocol, address := cmn.ProtocolAndAddress(listenAddr)
	ln, err := net.Listen(protocol, address)
	if err != nil {
		return nil, err
	}
	switch protocol {
	case "unix":
		listener = privval.NewUnixListener(ln)
	case "tcp":
		// TODO: persist this key so external signer
		// can actually authenticate us
		listener = privval.NewTCPListener(ln, ed25519.GenPrivKey())
	default:
		return nil, fmt.Errorf(
			"Wrong listen address: expected either 'tcp' or 'unix' protocols, got %s",
			protocol,
		)
	}

	pvsc := privval.NewSignerValidatorEndpoint(logger.With("module", "privval"), listener)
	if err := pvsc.Start(); err != nil {
		return nil, errors.Wrap(err, "failed to start private validator")
	}

	return pvsc, nil
}

// splitAndTrimEmpty slices s into all subslices separated by sep and returns a
// slice of the string s with all leading and trailing Unicode code points
// contained in cutset removed. If sep is empty, SplitAndTrim splits after each
// UTF-8 sequence. First part is equivalent to strings.SplitN with a count of
// -1.  also filter out empty strings, only return non-empty strings.
func splitAndTrimEmpty(s, sep, cutset string) []string {
	if s == "" {
		return []string{}
	}

	spl := strings.Split(s, sep)
	nonEmptyStrings := make([]string, 0, len(spl))
	for i := 0; i < len(spl); i++ {
		element := strings.Trim(spl[i], cutset)
		if element != "" {
			nonEmptyStrings = append(nonEmptyStrings, element)
		}
	}
	return nonEmptyStrings
}
