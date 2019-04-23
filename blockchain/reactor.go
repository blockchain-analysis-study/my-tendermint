package blockchain

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	amino "my-tendermint/go-amino"

	"my-tendermint/tendermint/libs/log"
	"my-tendermint/tendermint/p2p"
	sm "my-tendermint/tendermint/state"
	"my-tendermint/tendermint/types"
)

const (
	// BlockchainChannel is a channel for blocks and status updates (`BlockStore` height)
	BlockchainChannel = byte(0x40)

	trySyncIntervalMS = 10

	// stop syncing when last block's time is
	// within this much of the system time.
	// stopSyncingDurationMinutes = 10

	// ask for best height every 10s
	statusUpdateIntervalSeconds = 10
	// check if we should switch to consensus reactor
	switchToConsensusIntervalSeconds = 1

	// NOTE: keep up to date with bcBlockResponseMessage
	bcBlockResponseMessagePrefixSize   = 4
	bcBlockResponseMessageFieldKeySize = 1
	maxMsgSize                         = types.MaxBlockSizeBytes +
		bcBlockResponseMessagePrefixSize +
		bcBlockResponseMessageFieldKeySize
)

type consensusReactor interface {
	// for when we switch from blockchain reactor and fast sync to
	// the consensus machine
	SwitchToConsensus(sm.State, int)
}

type peerError struct {
	err    error
	peerID p2p.ID
}

func (e peerError) Error() string {
	return fmt.Sprintf("error with peer %v: %s", e.peerID, e.err.Error())
}

// BlockchainReactor handles long-term catchup syncing.
/**
Blockchain Reactor:
处理长期追赶同步。
 */
type BlockchainReactor struct {

	// 继承基础反应器
	p2p.BaseReactor

	// immutable
	// 一成不变
	// 这个就是 state (state/state.go)
	initialState sm.State

	// 区块执行器
	blockExec *sm.BlockExecutor

	// block db 的包装层
	store     *BlockStore

	// 一个专门做同步的 pool？ 类似以太坊的peerManager ？
	pool      *BlockPool

	// 是否快速同步模式
	fastSync  bool

	// 单向 接收通道
	// 引用和 BlockPool 中的引用一致
	requestsCh <-chan BlockRequest
	errorsCh   <-chan peerError
}

// NewBlockchainReactor returns new reactor instance.
// 实例化一个blockchain的反应器
func NewBlockchainReactor(state sm.State, blockExec *sm.BlockExecutor, store *BlockStore,
	fastSync bool) *BlockchainReactor {

	if state.LastBlockHeight != store.Height() {
		panic(fmt.Sprintf("state (%v) and store (%v) height mismatch", state.LastBlockHeight,
			store.Height()))
	}

	/**
	创建 双向通道
	用来接收 BlockRequest
	BlockRequest：结构体总只有  height 和 p2p.PID 两个字段
	 */
	requestsCh := make(chan BlockRequest, maxTotalRequesters)

	const capacity = 1000                      // must be bigger than peers count   必须要比节点的数量多

	/**
	创建双向通道
	 */
	errorsCh := make(chan peerError, capacity) // so we don't block in #Receive#pool.AddBlock

	pool := NewBlockPool(
		store.Height()+1,

		// 把引用赋值给 BlockPool 中的 单向 发送通道字段
		requestsCh,
		errorsCh,
	)

	bcR := &BlockchainReactor{
		initialState: state,
		blockExec:    blockExec,
		store:        store,
		pool:         pool,
		fastSync:     fastSync,

		// 把引用赋值给 BlockchainReactor 中的 单向 接收通道字段
		requestsCh:   requestsCh,
		errorsCh:     errorsCh,
	}
	bcR.BaseReactor = *p2p.NewBaseReactor("BlockchainReactor", bcR)
	return bcR
}

// SetLogger implements cmn.Service by setting the logger on reactor and pool.
func (bcR *BlockchainReactor) SetLogger(l log.Logger) {
	bcR.BaseService.Logger = l
	bcR.pool.Logger = l
}

// OnStart implements cmn.Service.
func (bcR *BlockchainReactor) OnStart() error {

	// 如果是 快速同步模式
	if bcR.fastSync {

		// 启动 BlockPool 中的 BaseServive
		// 这里最终调到 node的start()
		err := bcR.pool.Start()
		if err != nil {
			return err
		}

		/**
		启动 守护进程
		处理交易？
		 */
		go bcR.poolRoutine()
	}
	return nil
}

// OnStop implements cmn.Service.
func (bcR *BlockchainReactor) OnStop() {
	bcR.pool.Stop()
}

// GetChannels implements Reactor
func (bcR *BlockchainReactor) GetChannels() []*p2p.ChannelDescriptor {
	return []*p2p.ChannelDescriptor{
		{
			ID:                  BlockchainChannel,
			Priority:            10,
			SendQueueCapacity:   1000,
			RecvBufferCapacity:  50 * 4096,
			RecvMessageCapacity: maxMsgSize,
		},
	}
}

// AddPeer implements Reactor by sending our state to peer.
func (bcR *BlockchainReactor) AddPeer(peer p2p.Peer) {
	msgBytes := cdc.MustMarshalBinaryBare(&bcStatusResponseMessage{bcR.store.Height()})
	if !peer.Send(BlockchainChannel, msgBytes) {
		// doing nothing, will try later in `poolRoutine`
	}
	// peer is added to the pool once we receive the first
	// bcStatusResponseMessage from the peer and call pool.SetPeerHeight
}

// RemovePeer implements Reactor by removing peer from the pool.
func (bcR *BlockchainReactor) RemovePeer(peer p2p.Peer, reason interface{}) {
	bcR.pool.RemovePeer(peer.ID())
}

// respondToPeer loads a block and sends it to the requesting peer,
// if we have it. Otherwise, we'll respond saying we don't have it.
// According to the Tendermint spec, if all nodes are honest,
// no node should be requesting for a block that's non-existent.
func (bcR *BlockchainReactor) respondToPeer(msg *bcBlockRequestMessage,
	src p2p.Peer) (queued bool) {

	block := bcR.store.LoadBlock(msg.Height)
	if block != nil {
		msgBytes := cdc.MustMarshalBinaryBare(&bcBlockResponseMessage{Block: block})
		return src.TrySend(BlockchainChannel, msgBytes)
	}

	bcR.Logger.Info("Peer asking for a block we don't have", "src", src, "height", msg.Height)

	msgBytes := cdc.MustMarshalBinaryBare(&bcNoBlockResponseMessage{Height: msg.Height})
	return src.TrySend(BlockchainChannel, msgBytes)
}

// Receive implements Reactor by handling 4 types of messages (look below).
func (bcR *BlockchainReactor) Receive(chID byte, src p2p.Peer, msgBytes []byte) {
	msg, err := decodeMsg(msgBytes)
	if err != nil {
		bcR.Logger.Error("Error decoding message", "src", src, "chId", chID, "msg", msg, "err", err, "bytes", msgBytes)
		bcR.Switch.StopPeerForError(src, err)
		return
	}

	if err = msg.ValidateBasic(); err != nil {
		bcR.Logger.Error("Peer sent us invalid msg", "peer", src, "msg", msg, "err", err)
		bcR.Switch.StopPeerForError(src, err)
		return
	}

	bcR.Logger.Debug("Receive", "src", src, "chID", chID, "msg", msg)

	switch msg := msg.(type) {
	case *bcBlockRequestMessage:
		if queued := bcR.respondToPeer(msg, src); !queued {
			// Unfortunately not queued since the queue is full.
		}
	case *bcBlockResponseMessage:
		bcR.pool.AddBlock(src.ID(), msg.Block, len(msgBytes))
	case *bcStatusRequestMessage:
		// Send peer our state.
		msgBytes := cdc.MustMarshalBinaryBare(&bcStatusResponseMessage{bcR.store.Height()})
		queued := src.TrySend(BlockchainChannel, msgBytes)
		if !queued {
			// sorry
		}
	case *bcStatusResponseMessage:
		// Got a peer status. Unverified.
		bcR.pool.SetPeerHeight(src.ID(), msg.Height)
	default:
		bcR.Logger.Error(fmt.Sprintf("Unknown message type %v", reflect.TypeOf(msg)))
	}
}

// Handle messages from the poolReactor telling the reactor what to do.
// NOTE: Don't sleep in the FOR_LOOP or otherwise slow it down!
/**
TODO 超级重要
交易执行入口？
处理来自poolReactor的消息，告诉reactor如何做。
注意：不要在FOR_LOOP中 sleep或以其他方式减速！
 */
func (bcR *BlockchainReactor) poolRoutine() {

	/**
	某些 tick 打孔器
	 */
	trySyncTicker := time.NewTicker(trySyncIntervalMS * time.Millisecond)
	statusUpdateTicker := time.NewTicker(statusUpdateIntervalSeconds * time.Second)
	switchToConsensusTicker := time.NewTicker(switchToConsensusIntervalSeconds * time.Second)

	// 区块同步计数
	blocksSynced := 0

	// 从 链反应器中获取 链ID
	chainID := bcR.initialState.ChainID
	state := bcR.initialState

	// 最后一百？？ 啥啊 不就是当前时间戳么？
	lastHundred := time.Now()
	// 最后的百分比？
	lastRate := 0.0

	didProcessCh := make(chan struct{}, 1)

FOR_LOOP:
	for {
		select {
		// 如果接受到一个 远端peer 的请求
		case request := <-bcR.requestsCh:

			// 获取当中的 peer 实例
			peer := bcR.Switch.Peers().Get(request.PeerID)
			if peer == nil {
				continue FOR_LOOP // Peer has since been disconnected.
			}
			msgBytes := cdc.MustMarshalBinaryBare(&bcBlockRequestMessage{request.Height})
			/**
			TODO
			尝试性的 往对端节点发起请求
			 */
			queued := peer.TrySend(BlockchainChannel, msgBytes)
			if !queued {
				// We couldn't make the request, send-queue full.
				// The pool handles timeouts, just let it go.
				/**
				我们无法发出请求，发送队列已满。
				pool处理超时，让它 过掉。
				 */
				continue FOR_LOOP
			}

		case err := <-bcR.errorsCh:
			peer := bcR.Switch.Peers().Get(err.peerID)
			if peer != nil {
				bcR.Switch.StopPeerForError(peer, err)
			}

		case <-statusUpdateTicker.C:
			// ask for status updates
			// 广播 本地中的 blockstore 中的height
			go bcR.BroadcastStatusRequest() // nolint: errcheck

		case <-switchToConsensusTicker.C:
			// 获取 本地 pool 中的某些状态： height 之类
			height, numPending, lenRequesters := bcR.pool.GetStatus()
			outbound, inbound, _ := bcR.Switch.NumPeers()
			bcR.Logger.Debug("Consensus ticker", "numPending", numPending, "total", lenRequesters,
				"outbound", outbound, "inbound", inbound)

			// 如果当前pool 追赶上了 最新的chain的最高块
			if bcR.pool.IsCaughtUp() {
				bcR.Logger.Info("Time to switch to consensus reactor!", "height", height)
				bcR.pool.Stop()

				// 获取之前注册在 sw 对象中的 共识反应器
				conR, ok := bcR.Switch.Reactor("CONSENSUS").(consensusReactor)
				if ok {
					conR.SwitchToConsensus(state, blocksSynced)
				} else {
					// should only happen during testing
				}

				break FOR_LOOP
			}

		case <-trySyncTicker.C: // chan time
			select {
			case didProcessCh <- struct{}{}:
			default:
			}

			/**
			接受到执行区块信号
			 */
		case <-didProcessCh:
			// NOTE: It is a subtle mistake to process more than a single block
			// at a time (e.g. 10) here, because we only TrySend 1 request per
			// loop.  The ratio mismatch can result in starving of blocks, a
			// sudden burst of requests and responses, and repeat.
			// Consequently, it is better to split these routines rather than
			// coupling them as it's written here.  TODO uncouple from request
			// routine.

			// See if there are any blocks to sync.
			first, second := bcR.pool.PeekTwoBlocks()
			//bcR.Logger.Info("TrySync peeked", "first", first, "second", second)
			if first == nil || second == nil {
				// We need both to sync the first block.
				continue FOR_LOOP
			} else {
				// Try again quickly next loop.
				didProcessCh <- struct{}{}
			}

			firstParts := first.MakePartSet(types.BlockPartSizeBytes)
			firstPartsHeader := firstParts.Header()
			firstID := types.BlockID{Hash: first.Hash(), PartsHeader: firstPartsHeader}
			// Finally, verify the first block using the second's commit
			// NOTE: we can probably make this more efficient, but note that calling
			// first.Hash() doesn't verify the tx contents, so MakePartSet() is
			// currently necessary.
			err := state.Validators.VerifyCommit(
				chainID, firstID, first.Height, second.LastCommit)
			if err != nil {
				bcR.Logger.Error("Error in validation", "err", err)
				peerID := bcR.pool.RedoRequest(first.Height)
				peer := bcR.Switch.Peers().Get(peerID)
				if peer != nil {
					// NOTE: we've already removed the peer's request, but we
					// still need to clean up the rest.
					bcR.Switch.StopPeerForError(peer, fmt.Errorf("BlockchainReactor validation error: %v", err))
				}
				peerID2 := bcR.pool.RedoRequest(second.Height)
				peer2 := bcR.Switch.Peers().Get(peerID2)
				if peer2 != nil && peer2 != peer {
					// NOTE: we've already removed the peer's request, but we
					// still need to clean up the rest.
					bcR.Switch.StopPeerForError(peer2, fmt.Errorf("BlockchainReactor validation error: %v", err))
				}
				continue FOR_LOOP
			} else {
				bcR.pool.PopRequest()

				// TODO: batch saves so we dont persist to disk every block
				bcR.store.SaveBlock(first, firstParts, second.LastCommit)

				// TODO: same thing for app - but we would need a way to
				// get the hash without persisting the state
				var err error
				/**
				TODO 重要
				这里执行区块
				 */
				state, err = bcR.blockExec.ApplyBlock(state, firstID, first)
				if err != nil {
					// TODO This is bad, are we zombie?
					// TODO 这很糟糕，我们是僵尸吗？
					panic(fmt.Sprintf("Failed to process committed block (%d:%X): %v", first.Height, first.Hash(), err))
				}
				blocksSynced++

				if blocksSynced%100 == 0 {
					lastRate = 0.9*lastRate + 0.1*(100/time.Since(lastHundred).Seconds())
					bcR.Logger.Info("Fast Sync Rate", "height", bcR.pool.height,
						"max_peer_height", bcR.pool.MaxPeerHeight(), "blocks/s", lastRate)
					lastHundred = time.Now()
				}
			}
			continue FOR_LOOP

		case <-bcR.Quit():
			break FOR_LOOP
		}
	}
}

// BroadcastStatusRequest broadcasts `BlockStore` height.
// BroadcastStatusRequest:
// 广播`BlockStore`高度。
func (bcR *BlockchainReactor) BroadcastStatusRequest() error {
	msgBytes := cdc.MustMarshalBinaryBare(&bcStatusRequestMessage{bcR.store.Height()})
	bcR.Switch.Broadcast(BlockchainChannel, msgBytes)
	return nil
}

//-----------------------------------------------------------------------------
// Messages

// BlockchainMessage is a generic message for this reactor.
type BlockchainMessage interface {
	ValidateBasic() error
}

func RegisterBlockchainMessages(cdc *amino.Codec) {
	cdc.RegisterInterface((*BlockchainMessage)(nil), nil)
	cdc.RegisterConcrete(&bcBlockRequestMessage{}, "tendermint/blockchain/BlockRequest", nil)
	cdc.RegisterConcrete(&bcBlockResponseMessage{}, "tendermint/blockchain/BlockResponse", nil)
	cdc.RegisterConcrete(&bcNoBlockResponseMessage{}, "tendermint/blockchain/NoBlockResponse", nil)
	cdc.RegisterConcrete(&bcStatusResponseMessage{}, "tendermint/blockchain/StatusResponse", nil)
	cdc.RegisterConcrete(&bcStatusRequestMessage{}, "tendermint/blockchain/StatusRequest", nil)
}

func decodeMsg(bz []byte) (msg BlockchainMessage, err error) {
	if len(bz) > maxMsgSize {
		return msg, fmt.Errorf("Msg exceeds max size (%d > %d)", len(bz), maxMsgSize)
	}
	err = cdc.UnmarshalBinaryBare(bz, &msg)
	return
}

//-------------------------------------

type bcBlockRequestMessage struct {
	Height int64
}

// ValidateBasic performs basic validation.
func (m *bcBlockRequestMessage) ValidateBasic() error {
	if m.Height < 0 {
		return errors.New("Negative Height")
	}
	return nil
}

func (m *bcBlockRequestMessage) String() string {
	return fmt.Sprintf("[bcBlockRequestMessage %v]", m.Height)
}

type bcNoBlockResponseMessage struct {
	Height int64
}

// ValidateBasic performs basic validation.
func (m *bcNoBlockResponseMessage) ValidateBasic() error {
	if m.Height < 0 {
		return errors.New("Negative Height")
	}
	return nil
}

func (brm *bcNoBlockResponseMessage) String() string {
	return fmt.Sprintf("[bcNoBlockResponseMessage %d]", brm.Height)
}

//-------------------------------------

type bcBlockResponseMessage struct {
	Block *types.Block
}

// ValidateBasic performs basic validation.
func (m *bcBlockResponseMessage) ValidateBasic() error {
	return m.Block.ValidateBasic()
}

func (m *bcBlockResponseMessage) String() string {
	return fmt.Sprintf("[bcBlockResponseMessage %v]", m.Block.Height)
}

//-------------------------------------

type bcStatusRequestMessage struct {
	Height int64
}

// ValidateBasic performs basic validation.
func (m *bcStatusRequestMessage) ValidateBasic() error {
	if m.Height < 0 {
		return errors.New("Negative Height")
	}
	return nil
}

func (m *bcStatusRequestMessage) String() string {
	return fmt.Sprintf("[bcStatusRequestMessage %v]", m.Height)
}

//-------------------------------------

type bcStatusResponseMessage struct {
	Height int64
}

// ValidateBasic performs basic validation.
func (m *bcStatusResponseMessage) ValidateBasic() error {
	if m.Height < 0 {
		return errors.New("Negative Height")
	}
	return nil
}

func (m *bcStatusResponseMessage) String() string {
	return fmt.Sprintf("[bcStatusResponseMessage %v]", m.Height)
}
