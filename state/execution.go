package state

import (
	"fmt"
	"time"

	abci "my-tendermint/tendermint/abci/types"
	dbm "my-tendermint/tendermint/libs/db"
	"my-tendermint/tendermint/libs/fail"
	"my-tendermint/tendermint/libs/log"
	"my-tendermint/tendermint/proxy"
	"my-tendermint/tendermint/types"
)

//-----------------------------------------------------------------------------
// BlockExecutor handles block execution and state updates.
// It exposes ApplyBlock(), which validates & executes the block, updates state w/ ABCI responses,
// then commits and updates the mempool atomically, then saves state.

// BlockExecutor provides the context and accessories for properly executing a block.
type BlockExecutor struct {
	// save state, validators, consensus params, abci responses here
	db dbm.DB

	// execute the app against this
	//
	// 针对此执行应用程序
	//
	/** TODO 创建proxyApp并建立与ABCI应用程序的连接（共识，mempool，查询）。 */
	// 这里是入参了 proxyApp.Consensus() 获取到的所有参与共识的链接？
	proxyApp proxy.AppConnConsensus

	// events
	eventBus types.BlockEventPublisher

	// manage the mempool lock during commit
	// and update both with block results after commit.
	mempool Mempool
	evpool  EvidencePool

	logger log.Logger

	metrics *Metrics
}

type BlockExecutorOption func(executor *BlockExecutor)

func BlockExecutorWithMetrics(metrics *Metrics) BlockExecutorOption {
	return func(blockExec *BlockExecutor) {
		blockExec.metrics = metrics
	}
}

// NewBlockExecutor returns a new BlockExecutor with a NopEventBus.
// Call SetEventBus to provide one.
func NewBlockExecutor(db dbm.DB, logger log.Logger, proxyApp proxy.AppConnConsensus, mempool Mempool, evpool EvidencePool, options ...BlockExecutorOption) *BlockExecutor {
	res := &BlockExecutor{
		db:       db,

		/** TODO 创建proxyApp并建立与ABCI应用程序的连接（共识，mempool，查询）。 */
		// 这里是入参了 proxyApp.Consensus() 获取到的所有参与共识的链接？
		proxyApp: proxyApp,
		eventBus: types.NopEventBus{},
		mempool:  mempool,
		evpool:   evpool,
		logger:   logger,
		metrics:  NopMetrics(),
	}

	for _, option := range options {
		option(res)
	}

	return res
}

// SetEventBus - sets the event bus for publishing block related events.
// If not called, it defaults to types.NopEventBus.
func (blockExec *BlockExecutor) SetEventBus(eventBus types.BlockEventPublisher) {
	blockExec.eventBus = eventBus
}

// CreateProposalBlock calls state.MakeBlock with evidence from the evpool
// and txs from the mempool. The max bytes must be big enough to fit the commit.
// Up to 1/10th of the block space is allcoated for maximum sized evidence.
// The rest is given to txs, up to the max gas.
/**
TODO： 重要
由提议者 打包一个block
 */
func (blockExec *BlockExecutor) CreateProposalBlock(
	height int64,
	state State, commit *types.Commit,
	proposerAddr []byte,
) (*types.Block, *types.PartSet) {

	maxBytes := state.ConsensusParams.Block.MaxBytes
	maxGas := state.ConsensusParams.Block.MaxGas

	// Fetch a limited amount of valid evidence
	maxNumEvidence, _ := types.MaxEvidencePerBlock(maxBytes)
	/*
	收集 所有双签证据
	*/
	evidence := blockExec.evpool.PendingEvidence(maxNumEvidence)

	// Fetch a limited amount of valid txs
	maxDataBytes := types.MaxDataBytes(maxBytes, state.Validators.Size(), len(evidence))

	// 读取 mempool(交易池) 中的 tx
	txs := blockExec.mempool.ReapMaxBytesMaxGas(maxDataBytes, maxGas)

	// 根据state 和tx打包一个 block
	return state.MakeBlock(height, txs, commit, evidence, proposerAddr)
}

// ValidateBlock validates the given block against the given state.
// If the block is invalid, it returns an error.
// Validation does not mutate state, but does require historical information from the stateDB,
// ie. to verify evidence from a validator at an old height.
// 校验区块
func (blockExec *BlockExecutor) ValidateBlock(state State, block *types.Block) error {
	return validateBlock(blockExec.evpool, blockExec.db, state, block)
}

// ApplyBlock validates the block against the state, executes it against the app,
// fires the relevant events, commits the app, and saves the new state and responses.
// It's the only function that needs to be called
// from outside this package to process and commit an entire block.
// It takes a blockID to avoid recomputing the parts hash.
/**
ApplyBlock:
针对 state 验证块，针对应用程序执行块，触发相关事件，提交应用程序，并保存新状态和响应。
它是唯一需要从此包外部调用以处理和提交整个块的函数。
它需要一个blockID来避免重新计算部件哈希值。
 */
func (blockExec *BlockExecutor) ApplyBlock(state State, blockID types.BlockID, block *types.Block) (State, error) {

	/**
	先校验区块
	 */
	if err := blockExec.ValidateBlock(state, block); err != nil {
		return state, ErrInvalidBlock(err)
	}


	// 当前时间戳
	startTime := time.Now().UnixNano()

	//
	//
	/** TODO 创建proxyApp并建立与ABCI应用程序的连接（共识，mempool，查询）。 */
	// 这里是入参了 proxyApp.Consensus() 获取到的所有参与共识的链接？
	/*
	TODO 每个块执行之前， 每个块执行其中交易， 每个块执行之后 都要组合里作为入口

	TODO 执行 block 的代理
	*/
	abciResponses, err := execBlockOnProxyApp(blockExec.logger, blockExec.proxyApp, block, state.LastValidators, blockExec.db)
	endTime := time.Now().UnixNano()
	blockExec.metrics.BlockProcessingTime.Observe(float64(endTime-startTime) / 1000000)
	if err != nil {
		return state, ErrProxyAppConn(err)
	}

	fail.Fail() // XXX

	// Save the results before we commit.
	// 保存 ABCI 回来的resp
	// 把 resp 存起来 ??
	saveABCIResponses(blockExec.db, block.Height, abciResponses)

	fail.Fail() // XXX

	// TODO
	// validate the validator updates and convert to tendermint types
	// 验证验证器更新并转换为tendermint类型
	abciValUpdates := abciResponses.EndBlock.ValidatorUpdates
	err = validateValidatorUpdates(abciValUpdates, state.ConsensusParams.Validator)
	if err != nil {
		return state, fmt.Errorf("Error in validator updates: %v", err)
	}
	validatorUpdates, err := types.PB2TM.ValidatorUpdates(abciValUpdates)
	if err != nil {
		return state, err
	}
	if len(validatorUpdates) > 0 {
		blockExec.logger.Info("Updates to validators", "updates", types.ValidatorListString(validatorUpdates))
	}

	// Update the state with the block and responses.
	/**
	TODO ###########
	TODO ###########

	TODO 重要， 这个才是 state 更新的 入口
	TODO 根据拉回来的 cosmos 的实时验证人 更新 state
	根据执行完的 block 和 ABCI的resp结果 更新当前 state
	 */
	state, err = updateState(state, blockID, &block.Header, abciResponses, validatorUpdates)
	if err != nil {
		return state, fmt.Errorf("Commit failed for application: %v", err)
	}

	// Lock mempool, commit app state, update mempoool.
	appHash, err := blockExec.Commit(state, block)
	if err != nil {
		return state, fmt.Errorf("Commit failed for application: %v", err)
	}

	// Update evpool with the block and state.
	blockExec.evpool.Update(block, state)

	fail.Fail() // XXX

	// Update the app hash and save the state.
	state.AppHash = appHash
	SaveState(blockExec.db, state)

	fail.Fail() // XXX

	// Events are fired after everything else.
	// NOTE: if we crash between Commit and Save, events wont be fired during replay
	fireEvents(blockExec.logger, blockExec.eventBus, block, abciResponses, validatorUpdates)

	return state, nil
}

// Commit locks the mempool, runs the ABCI Commit message, and updates the
// mempool.
// It returns the result of calling abci.Commit (the AppHash), and an error.
// The Mempool must be locked during commit and update because state is
// typically reset on Commit and old txs must be replayed against committed
// state before new txs are run in the mempool, lest they be invalid.
func (blockExec *BlockExecutor) Commit(
	state State,
	block *types.Block,
) ([]byte, error) {
	blockExec.mempool.Lock()
	defer blockExec.mempool.Unlock()

	// while mempool is Locked, flush to ensure all async requests have completed
	// in the ABCI app before Commit.
	err := blockExec.mempool.FlushAppConn()
	if err != nil {
		blockExec.logger.Error("Client error during mempool.FlushAppConn", "err", err)
		return nil, err
	}

	// Commit block, get hash back
	res, err := blockExec.proxyApp.CommitSync()
	if err != nil {
		blockExec.logger.Error(
			"Client error during proxyAppConn.CommitSync",
			"err", err,
		)
		return nil, err
	}
	// ResponseCommit has no error code - just data

	blockExec.logger.Info(
		"Committed state",
		"height", block.Height,
		"txs", block.NumTxs,
		"appHash", fmt.Sprintf("%X", res.Data),
	)

	// Update mempool.
	err = blockExec.mempool.Update(
		block.Height,
		block.Txs,
		TxPreCheck(state),
		TxPostCheck(state),
	)

	return res.Data, err
}

//---------------------------------------------------------
// Helper functions for executing blocks and updating state

// Executes block's transactions on proxyAppConn.
// Returns a list of transaction results and updates to the validator set
/**
TODO 重要的 辅助函数
辅助函数用于执行block和更新state  TODO (注意: 这个是重放 block，而不是 打包新 block 哦)

在proxyAppConn上执行块的 tx。
返回 tx结果列表和 验证人集的更新
 */
func execBlockOnProxyApp(
	logger log.Logger,

	/** TODO 创建proxyApp并建立与ABCI应用程序的连接（共识，mempool，查询）。 */
	// 这里是入参了 proxyApp.Consensus() 获取到的所有参与共识的链接？
	proxyAppConn proxy.AppConnConsensus,
	block *types.Block,
	lastValSet *types.ValidatorSet,
	stateDB dbm.DB,
) (*ABCIResponses, error) {
	var validTxs, invalidTxs = 0, 0

	txIndex := 0

	// 根据 block 创建了一个 resp ？？
	abciResponses := NewABCIResponses(block)

	// Execute transactions and get hash.
	// 执行 tx 并获取 Hash
	//
	// 定义一个内部函数 （定义一个回调函数）
	proxyCb := func(req *abci.Request, res *abci.Response) {

		// 判断 入参的res类型
		switch r := res.Value.(type) {

		// 如果是 交付tx 类型
		case *abci.Response_DeliverTx:
			// TODO: make use of res.Log
			// TODO: make use of this info
			// Blocks may include invalid txs.
			// 块可能包括无效的tx
			//
			// DeliverTx 代表是一个 交付类型tx
			txRes := r.DeliverTx

			// 如果ok 则 有效tx计数 +1
			if txRes.Code == abci.CodeTypeOK {
				validTxs++
			} else {
					// 否则无效tx计数 +1
				logger.Debug("Invalid tx", "code", txRes.Code, "log", txRes.Log)
				invalidTxs++
			}

			// 记录这个 tx 的res
			abciResponses.DeliverTx[txIndex] = txRes
			txIndex++
		}
	}

	// 设置 resp 回调
	// TODO 注意： 这里调用 cosmos
	proxyAppConn.SetResponseCallback(proxyCb)


	// TODO 在执行区块之前，拉取关于当前 验证人相关的一些信息，
	commitInfo, byzVals := getBeginBlockValidatorInfo(block, lastValSet, stateDB)

	// Begin block
	//
	// TODO 重要
	//
	// TODO 执行一个区块开始前 调用 func (app *GaiaApp) BeginBlocker(ctx sdk.Context, req abci.RequestBeginBlock) abci.ResponseBeginBlock
	// func (app *GaiaApp) BeginBlocker()
	var err error
	abciResponses.BeginBlock, err = proxyAppConn.BeginBlockSync(abci.RequestBeginBlock{
		Hash:                block.Hash(),
		Header:              types.TM2PB.Header(&block.Header),
		LastCommitInfo:      commitInfo,
		ByzantineValidators: byzVals,
	})
	if err != nil {
		logger.Error("Error in proxyAppConn.BeginBlock", "err", err)
		return nil, err
	}

	// Run txs of block.
	/*
	TODO 执行当前区块中的每一笔交易
	*/
	for _, tx := range block.Txs {

		/*
		TODO 这里调用了 cosmos 的 func (app *BaseApp) DeliverTx(txBytes []byte) (res abci.ResponseDeliverTx)

		执行交易为什么放到上层，因为 tendermint 只是个共识层，不同的链集成了 tendermint的话，需要自己实现这些 rpc接口，
		自己维护自己的 业务交易逻辑，tendermint 才不管这个，tendermint只管交易的结果！
		*/
		proxyAppConn.DeliverTxAsync(tx)
		if err := proxyAppConn.Error(); err != nil {
			return nil, err
		}
	}

	// End block.
	// TODO 获取cosmos变更的 验证人 列表
	// TODO 注意了 这一步超级重要
	// TODO 调用了 cosmos的 func (app *GaiaApp) EndBlocker(ctx sdk.Context, req abci.RequestEndBlock) abci.ResponseEndBlock
	// 获取到上层 cosmos 的最新的变更(排序之后的 验证人列表) 都在abciResponses里面了
	// types.pb.go
	abciResponses.EndBlock, err = proxyAppConn.EndBlockSync(abci.RequestEndBlock{Height: block.Height})
	if err != nil {
		logger.Error("Error in proxyAppConn.EndBlock", "err", err)
		return nil, err
	}

	logger.Info("Executed block", "height", block.Height, "validTxs", validTxs, "invalidTxs", invalidTxs)

	return abciResponses, nil
}


/*
TODO 执行一个block之前拉取当前验证人的  所有相关信息
*/
func getBeginBlockValidatorInfo(block *types.Block, lastValSet *types.ValidatorSet, stateDB dbm.DB) (abci.LastCommitInfo, []abci.Evidence) {

	// Sanity check that commit length matches validator set size -
	// only applies after first block
	if block.Height > 1 {
		precommitLen := len(block.LastCommit.Precommits)
		valSetLen := len(lastValSet.Validators)
		if precommitLen != valSetLen {
			// sanity check
			panic(fmt.Sprintf("precommit length (%d) doesn't match valset length (%d) at height %d\n\n%v\n\n%v",
				precommitLen, valSetLen, block.Height, block.LastCommit.Precommits, lastValSet.Validators))
		}
	}

	// Collect the vote info (list of validators and whether or not they signed).
	voteInfos := make([]abci.VoteInfo, len(lastValSet.Validators))
	for i, val := range lastValSet.Validators {
		var vote *types.CommitSig
		if i < len(block.LastCommit.Precommits) {
			vote = block.LastCommit.Precommits[i]
		}
		voteInfo := abci.VoteInfo{
			Validator:       types.TM2PB.Validator(val),
			SignedLastBlock: vote != nil,
		}
		voteInfos[i] = voteInfo
	}

	commitInfo := abci.LastCommitInfo{
		Round: int32(block.LastCommit.Round()),
		Votes: voteInfos,
	}

	byzVals := make([]abci.Evidence, len(block.Evidence.Evidence))
	/*
	TODO 收集所有关于 拜占庭双签的证据
	*/
	for i, ev := range block.Evidence.Evidence {
		// We need the validator set. We already did this in validateBlock.
		// TODO: Should we instead cache the valset in the evidence itself and add
		// `SetValidatorSet()` and `ToABCI` methods ?
		valset, err := LoadValidators(stateDB, ev.Height())
		if err != nil {
			panic(err) // shouldn't happen
		}
		byzVals[i] = types.TM2PB.Evidence(ev, valset, block.Time)
	}

	return commitInfo, byzVals

}

// TODO 校验从 cosmos 过来的验证人列表是否 合法
func validateValidatorUpdates(abciUpdates []abci.ValidatorUpdate,
	params types.ValidatorParams) error {

	/**
	TODO 遍历从 cosmos 过来的最新的 验证人列表
	遍历入参的 abci.ValidatorUpdate 类型的验证人列表
	 */
	for _, valUpdate := range abciUpdates {
		if valUpdate.GetPower() < 0 {
			return fmt.Errorf("Voting power can't be negative %v", valUpdate)
		} else if valUpdate.GetPower() == 0 {
			// valUpdatecontinue, since this is deleting the validator, and thus there is no
			// pubkey to check
			/**
			如果是一个没有质押/委托金的验证人，那么我们可以跳过了
			 */
			continue
		}

		// Check if validator's pubkey matches an ABCI type in the consensus params
		// 检查验证器的pubkey是否与共识参数中的ABCI类型匹配
		thisKeyType := valUpdate.PubKey.Type
		if !params.IsValidPubkeyType(thisKeyType) {
			return fmt.Errorf("Validator %v is using pubkey %s, which is unsupported for consensus",
				valUpdate, thisKeyType)
		}
	}
	return nil
}

// updateState returns a new State updated according to the header and responses.
// updateState:
// 返回根据 header 和 abci resp更新的新状态。
func updateState(
	state State,
	blockID types.BlockID,
	header *types.Header,
	abciResponses *ABCIResponses,
	validatorUpdates []*types.Validator,
) (State, error) {

	// Copy the valset so we can apply changes from EndBlock
	// and update s.LastValidators and s.Validators.
	nValSet := state.NextValidators.Copy()

	// Update the validator set with the latest abciResponses.
	lastHeightValsChanged := state.LastHeightValidatorsChanged
	if len(validatorUpdates) > 0 {
		// TODO 这不很重要，更新验证人列表 (根据 cosmos 过来的验证人列表)
		err := nValSet.UpdateWithChangeSet(validatorUpdates)
		if err != nil {
			return state, fmt.Errorf("Error changing validator set: %v", err)
		}
		// Change results from this height but only applies to the next next height.
		lastHeightValsChanged = header.Height + 1 + 1
	}
	// Update validator proposer priority and set state variables.
	/**
	TODO 重要， 更新验证人 ， 提议人的权重 并设置 状态变量

	TODO 选出提议人
	 */
	nValSet.IncrementProposerPriority(1)

	// Update the params with the latest abciResponses.
	/**
	使用最新的abciResponses更新params。
	 */
	nextParams := state.ConsensusParams
	lastHeightParamsChanged := state.LastHeightConsensusParamsChanged

	// 从 cosmos返回的 resp 中获取 共识参数
	if abciResponses.EndBlock.ConsensusParamUpdates != nil {
		// NOTE: must not mutate s.ConsensusParams
		nextParams = state.ConsensusParams.Update(abciResponses.EndBlock.ConsensusParamUpdates)
		err := nextParams.Validate()
		if err != nil {
			return state, fmt.Errorf("Error updating consensus params: %v", err)
		}
		// Change results from this height but only applies to the next height.
		lastHeightParamsChanged = header.Height + 1
	}

	// TODO: allow app to upgrade version
	nextVersion := state.Version

	// NOTE: the AppHash has not been populated.
	// It will be filled on state.Save.
	return State{
		Version:                          nextVersion,
		ChainID:                          state.ChainID,
		LastBlockHeight:                  header.Height,
		LastBlockTotalTx:                 state.LastBlockTotalTx + header.NumTxs,
		LastBlockID:                      blockID,
		LastBlockTime:                    header.Time,
		/**
		替换三轮验证人列表
		 */
		// 注意了下一轮验证人列表可能会更改
		NextValidators:                   nValSet,
		// 下一轮的编程当前轮
		Validators:                       state.NextValidators.Copy(),
		// 当前轮的编程 上一轮
		LastValidators:                   state.Validators.Copy(),

		LastHeightValidatorsChanged:      lastHeightValsChanged,
		ConsensusParams:                  nextParams,
		LastHeightConsensusParamsChanged: lastHeightParamsChanged,
		LastResultsHash:                  abciResponses.ResultsHash(),
		AppHash:                          nil,
	}, nil
}

// Fire NewBlock, NewBlockHeader.
// Fire TxEvent for every tx.
// NOTE: if Tendermint crashes before commit, some or all of these events may be published again.
func fireEvents(logger log.Logger, eventBus types.BlockEventPublisher, block *types.Block, abciResponses *ABCIResponses, validatorUpdates []*types.Validator) {
	eventBus.PublishEventNewBlock(types.EventDataNewBlock{
		Block:            block,
		ResultBeginBlock: *abciResponses.BeginBlock,
		ResultEndBlock:   *abciResponses.EndBlock,
	})
	eventBus.PublishEventNewBlockHeader(types.EventDataNewBlockHeader{
		Header:           block.Header,
		ResultBeginBlock: *abciResponses.BeginBlock,
		ResultEndBlock:   *abciResponses.EndBlock,
	})

	for i, tx := range block.Data.Txs {
		eventBus.PublishEventTx(types.EventDataTx{TxResult: types.TxResult{
			Height: block.Height,
			Index:  uint32(i),
			Tx:     tx,
			Result: *(abciResponses.DeliverTx[i]),
		}})
	}

	if len(validatorUpdates) > 0 {
		eventBus.PublishEventValidatorSetUpdates(
			types.EventDataValidatorSetUpdates{ValidatorUpdates: validatorUpdates})
	}
}

//----------------------------------------------------------------------------------------------------
// Execute block without state. TODO: eliminate

// ExecCommitBlock executes and commits a block on the proxyApp without validating or mutating the state.
// It returns the application root hash (result of abci.Commit).
func ExecCommitBlock(
	appConnConsensus proxy.AppConnConsensus,
	block *types.Block,
	logger log.Logger,
	lastValSet *types.ValidatorSet,
	stateDB dbm.DB,
) ([]byte, error) {
	_, err := execBlockOnProxyApp(logger, appConnConsensus, block, lastValSet, stateDB)
	if err != nil {
		logger.Error("Error executing block on proxy app", "height", block.Height, "err", err)
		return nil, err
	}
	// Commit block, get hash back
	res, err := appConnConsensus.CommitSync()
	if err != nil {
		logger.Error("Client error during proxyAppConn.CommitSync", "err", res)
		return nil, err
	}
	// ResponseCommit has no error or log, just data
	return res.Data, nil
}
