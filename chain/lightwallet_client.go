package chain

import (
	"container/list"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcutil/gcs/builder"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/gcs"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// ErrLightWalletClientShuttingDown is an error returned when we attempt
	// to receive a notification for a specific item and the lightwallet client
	// is in the middle of shutting down.
	ErrLightWalletClientShuttingDown = errors.New("client is shutting down")
)

// LightWalletClient represents a persistent client connection to a lightwallet server
// for information regarding the current best block chain.
type LightWalletClient struct {
	started int32 // To be used atomically.
	stopped int32 // To be used atomically.

	// birthday is the earliest time for which we should begin scanning the
	// chain.
	birthday time.Time

	// chainParams are the parameters of the current chain this client is
	// active under.
	chainParams *chaincfg.Params

	// id is the unique ID of this client assigned by the backing lightwallet
	// connection.
	id uint64

	// ChainConn is the backing client to our rescan client that contains
	// the RPC and ZMQ connections to a lightwallet node.
	ChainConn *LightWalletConn

	// bestBlock keeps track of the tip of the current best chain.
	bestBlockMtx sync.RWMutex
	bestBlock    waddrmgr.BlockStamp

	// notifyBlocks signals whether the client is sending block
	// notifications to the caller.
	notifyBlocks uint32

	// rescanUpdate is a channel will be sent items that we should match
	// transactions against while processing a chain rescan to determine if
	// they are relevant to the client.
	rescanUpdate chan interface{}

	// watchedAddresses, watchedOutPoints, and watchedTxs are the set of
	// items we should match transactions against while processing a chain
	// rescan to determine if they are relevant to the client.
	watchMtx         sync.RWMutex
	watchedAddresses map[string]struct{}
	watchedOutPoints map[wire.OutPoint]struct{}
	watchedTxs       map[chainhash.Hash]struct{}

	// notificationQueue is a concurrent unbounded queue that handles
	// dispatching notifications to the subscriber of this client.
	//
	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed. For example,
	// BlockConnected notifications for greater block heights can remove the
	// need to process earlier notifications still waiting to be processed.
	notificationQueue *ConcurrentQueue

	// zmqHeaderNtfns is a channel through which ZMQ block events will be
	// retrieved from the backing lightwallet connection.
	zmqHeaderNtfns chan *wire.BlockHeader

	zmqChangeTipNtnfs chan *wire.MsgBlock

	quit chan struct{}
	wg   sync.WaitGroup
}

// A compile-time check to ensure that LightWalletClient satisfies the
// chain.Interface interface.
var _ Interface = (*LightWalletClient)(nil)

// BackEnd returns the name of the driver.
func (c *LightWalletClient) BackEnd() string {
	return "lightwallet"
}

// GetBestBlock returns the highest block known to lightwallet.
func (c *LightWalletClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	return c.ChainConn.grpcClient.GetBestBlock()
}

// GetFilterBlock returns filter block for given hash
func (c *LightWalletClient) GetFilterBlock(hash *chainhash.Hash) ([]*wire.MsgTx, error) {
	return c.ChainConn.grpcClient.GetFilterBlock(hash)
}

// GetUnspentOutput returns utxo set for given hash and index
func (c *LightWalletClient) GetUnspentOutput(hash *chainhash.Hash, index uint32) (*btcjson.GetUnspentOutputResult, error) {
	return c.ChainConn.grpcClient.GetUnspentOutput(hash, index)
}

// GetBlockHeight returns the height for the hash, if known, or returns an
// error.
func (c *LightWalletClient) GetBlockHeight(hash *chainhash.Hash) (int32, error) {
	return c.ChainConn.grpcClient.GetBlockHeight(hash)
}

// GetBlock returns a block from the hash.
func (c *LightWalletClient) GetBlock(hash *chainhash.Hash) (*wire.MsgBlock, error) {
	return c.ChainConn.grpcClient.GetBlock(hash)
}

// GetBlockHash returns a block hash from the height.
func (c *LightWalletClient) GetBlockHash(height int64) (*chainhash.Hash, error) {
	return c.ChainConn.grpcClient.GetBlockHash(height)
}

// GetBlockHeader returns a block header from the hash.
func (c *LightWalletClient) GetBlockHeader(
	hash *chainhash.Hash) (*wire.BlockHeader, error) {

	return c.ChainConn.grpcClient.GetBlockHeader(hash)
}

// GetBlockHeaderVerbose returns a block header from the hash.
func (c *LightWalletClient) GetBlockHeaderVerbose(
	hash *chainhash.Hash) (*btcjson.GetBlockHeaderVerboseResult, error) {

	return c.ChainConn.grpcClient.GetBlockHeaderVerbose(hash)
}

// GetRawTransaction returns a transaction from the tx hash.
func (c *LightWalletClient) GetRawTransaction(
	hash *chainhash.Hash) (*btcutil.Tx, error) {

	txConf, err := c.ChainConn.grpcClient.GetRawTransaction(hash)

	if err != nil {
		return nil, err
	}

	return btcutil.NewTx(txConf.Tx), nil

}

// GetRawTransaction returns a transaction from the tx hash.
func (c *LightWalletClient) GetRawTransactionVerbose(
	hash *chainhash.Hash) (*btcutil.Tx, *chainhash.Hash, uint32, error) {
	txConf, err := c.ChainConn.grpcClient.GetRawTransaction(hash)

	if err != nil {
		return nil, nil, 0, err
	}

	tx := btcutil.NewTx(txConf.Tx)
	tx.SetIndex(int(txConf.TxIndex))
	return tx, txConf.BlockHash, txConf.BlockHeight, nil
}

// SendRawTransaction sends a raw transaction via lightwallet.
func (c *LightWalletClient) SendRawTransaction(tx *wire.MsgTx,
	allowHighFees bool) (*chainhash.Hash, error) {

	return c.ChainConn.grpcClient.SendRawTransaction(tx, allowHighFees)
}

// GetCFilter returns a raw filter for given hash.
func (c *LightWalletClient) GetCFilter(hash *chainhash.Hash) (*gcs.Filter, error) {
	return c.ChainConn.grpcClient.GetBlockFilter(hash)
}

func (c *LightWalletClient) Generate(numBlocks uint32) ([]*chainhash.Hash, error) {
	return c.ChainConn.grpcClient.Generate(numBlocks)
}

// IsCurrent returns whether the chain backend considers its view of the network
// as "current".
func (c *LightWalletClient) IsCurrent() bool {
	bestHash, _, err := c.GetBestBlock()
	if err != nil {
		return false
	}
	bestHeader, err := c.GetBlockHeader(bestHash)
	if err != nil {
		return false
	}
	return bestHeader.Timestamp.After(time.Now().Add(-isCurrentDelta))
}

// Notifications returns a channel to retrieve notifications from.
//
// NOTE: This is part of the chain.Interface interface.
func (c *LightWalletClient) Notifications() <-chan interface{} {
	return c.notificationQueue.ChanOut()
}

// NotifyReceived allows the chain backend to notify the caller whenever a
// transaction pays to any of the given addresses.
//
// NOTE: This is part of the chain.Interface interface.
func (c *LightWalletClient) NotifyReceived(addrs []btcutil.Address) error {
	c.NotifyBlocks()

	select {
	case c.rescanUpdate <- addrs:
	case <-c.quit:
		return ErrLightWalletClientShuttingDown
	}

	return nil
}

// NotifySpent allows the chain backend to notify the caller whenever a
// transaction spends any of the given outpoints.
func (c *LightWalletClient) NotifySpent(outPoints []*wire.OutPoint) error {
	c.NotifyBlocks()

	select {
	case c.rescanUpdate <- outPoints:
	case <-c.quit:
		return ErrLightWalletClientShuttingDown
	}

	return nil
}

// NotifyTx allows the chain backend to notify the caller whenever any of the
// given transactions confirm within the chain.
func (c *LightWalletClient) NotifyTx(txids []chainhash.Hash) error {
	c.NotifyBlocks()

	select {
	case c.rescanUpdate <- txids:
	case <-c.quit:
		return ErrLightWalletClientShuttingDown
	}

	return nil
}

// NotifyBlocks allows the chain backend to notify the caller whenever a block
// is connected or disconnected.
//
// NOTE: This is part of the chain.Interface interface.
func (c *LightWalletClient) NotifyBlocks() error {
	atomic.StoreUint32(&c.notifyBlocks, 1)
	return nil
}

// shouldNotifyBlocks determines whether the client should send block
// notifications to the caller.
func (c *LightWalletClient) shouldNotifyBlocks() bool {
	return atomic.LoadUint32(&c.notifyBlocks) == 1
}

// LoadTxFilter uses the given filters to what we should match transactions
// against to determine if they are relevant to the client. The reset argument
// is used to reset the current filters.
//
// The current filters supported are of the following types:
//	[]btcutil.Address
//	[]wire.OutPoint
//	[]*wire.OutPoint
//	map[wire.OutPoint]btcutil.Address
//	[]chainhash.Hash
//	[]*chainhash.Hash
func (c *LightWalletClient) LoadTxFilter(reset bool, filters ...interface{}) error {
	if reset {
		select {
		case c.rescanUpdate <- struct{}{}:
		case <-c.quit:
			return ErrLightWalletClientShuttingDown
		}
	}

	updateFilter := func(filter interface{}) error {
		select {
		case c.rescanUpdate <- filter:
		case <-c.quit:
			return ErrLightWalletClientShuttingDown
		}

		return nil
	}

	// In order to make this operation atomic, we'll iterate through the
	// filters twice: the first to ensure there aren't any unsupported
	// filter types, and the second to actually update our filters.
	for _, filter := range filters {
		switch filter := filter.(type) {
		case []btcutil.Address, []wire.OutPoint, []*wire.OutPoint,
		map[wire.OutPoint]btcutil.Address, []chainhash.Hash,
		[]*chainhash.Hash:

			// Proceed to check the next filter type.
		default:
			return fmt.Errorf("unsupported filter type %T", filter)
		}
	}

	for _, filter := range filters {
		if err := updateFilter(filter); err != nil {
			return err
		}
	}

	return nil
}

// RescanBlocks rescans any blocks passed, returning only the blocks that
// matched as []btcjson.BlockDetails.
func (c *LightWalletClient) RescanBlocks(
	blockHashes []chainhash.Hash) ([]btcjson.RescannedBlock, error) {

	rescannedBlocks := make([]btcjson.RescannedBlock, 0, len(blockHashes))
	for _, hash := range blockHashes {
		header, err := c.GetBlockHeaderVerbose(&hash)
		if err != nil {
			log.Warnf("Unable to get header %s from lightwallet: %s",
				hash, err)
			continue
		}

		block, err := c.GetBlock(&hash)

		relevantTxs, err := c.filterBlock(block, header.Height, false)
		if len(relevantTxs) > 0 {
			rescannedBlock := btcjson.RescannedBlock{
				Hash: hash.String(),
			}
			for _, tx := range relevantTxs {
				rescannedBlock.Transactions = append(
					rescannedBlock.Transactions,
					hex.EncodeToString(tx.SerializedTx),
				)
			}

			rescannedBlocks = append(rescannedBlocks, rescannedBlock)
		}
	}

	return rescannedBlocks, nil
}

// Rescan rescans from the block with the given hash until the current block,
// after adding the passed addresses and outpoints to the client's watch list.
func (c *LightWalletClient) Rescan(blockHash *chainhash.Hash,
	addresses []btcutil.Address, outPoints map[wire.OutPoint]btcutil.Address) error {

	// A block hash is required to use as the starting point of the rescan.
	if blockHash == nil {
		return errors.New("rescan requires a starting block hash")
	}

	// We'll then update our filters with the given outpoints and addresses.
	select {
	case c.rescanUpdate <- addresses:
	case <-c.quit:
		return ErrLightWalletClientShuttingDown
	}

	select {
	case c.rescanUpdate <- outPoints:
	case <-c.quit:
		return ErrLightWalletClientShuttingDown
	}

	// Once the filters have been updated, we can begin the rescan.
	select {
	case c.rescanUpdate <- *blockHash:
	case <-c.quit:
		return ErrLightWalletClientShuttingDown
	}

	return nil
}

// Start initializes the lightwallet rescan client using the backing lightwallet
// connection and starts all goroutines necessary in order to process rescans
// and ZMQ notifications.
//
// NOTE: This is part of the chain.Interface interface.
func (c *LightWalletClient) Start() error {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	// Start the notification queue and immediately dispatch a
	// ClientConnected notification to the caller. This is needed as some of
	// the callers will require this notification before proceeding.
	c.notificationQueue.Start()
	c.notificationQueue.ChanIn() <- ClientConnected{}

	// Retrieve the best block of the chain.
	bestHash, bestHeight, err := c.GetBestBlock()
	if err != nil {
		return fmt.Errorf("unable to retrieve best block: %v", err)
	}
	bestHeader, err := c.GetBlockHeaderVerbose(bestHash)
	if err != nil {
		return fmt.Errorf("unable to retrieve header for best block: "+
			"%v", err)
	}

	c.bestBlockMtx.Lock()
	c.bestBlock = waddrmgr.BlockStamp{
		Hash:      *bestHash,
		Height:    bestHeight,
		Timestamp: time.Unix(bestHeader.Time, 0),
	}
	c.bestBlockMtx.Unlock()

	// Once the client has started successfully, we'll include it in the set
	// of rescan clients of the backing lightwallet connection in order to
	// received ZMQ event notifications.
	c.ChainConn.AddClient(c)

	c.wg.Add(2)
	go c.rescanHandler()
	go c.ntfnHandler()

	return nil
}

// Stop stops the lightwallet rescan client from processing rescans and ZMQ
// notifications.
//
// NOTE: This is part of the chain.Interface interface.
func (c *LightWalletClient) Stop() {
	if !atomic.CompareAndSwapInt32(&c.stopped, 0, 1) {
		return
	}

	close(c.quit)

	// Remove this client's reference from the lightwallet connection to
	// prevent sending notifications to it after it's been stopped.
	c.ChainConn.RemoveClient(c.id)

	c.notificationQueue.Stop()
}

// WaitForShutdown blocks until the client has finished disconnecting and all
// handlers have exited.
//
// NOTE: This is part of the chain.Interface interface.
func (c *LightWalletClient) WaitForShutdown() {
	c.wg.Wait()
}

// rescanHandler handles the logic needed for the caller to trigger a chain
// rescan.
//
// NOTE: This must be called as a goroutine.
func (c *LightWalletClient) rescanHandler() {
	defer c.wg.Done()

	for {
		select {
		case update := <-c.rescanUpdate:
			switch update := update.(type) {

			// We're clearing the filters.
			case struct{}:
				c.watchMtx.Lock()
				c.watchedOutPoints = make(map[wire.OutPoint]struct{})
				c.watchedAddresses = make(map[string]struct{})
				c.watchedTxs = make(map[chainhash.Hash]struct{})
				c.watchMtx.Unlock()

				// We're adding the addresses to our filter.
			case []btcutil.Address:
				c.watchMtx.Lock()
				for _, addr := range update {
					c.watchedAddresses[addr.String()] = struct{}{}
				}
				c.watchMtx.Unlock()

				// We're adding the outpoints to our filter.
			case []wire.OutPoint:
				c.watchMtx.Lock()
				for _, op := range update {
					c.watchedOutPoints[op] = struct{}{}
				}
				c.watchMtx.Unlock()
			case []*wire.OutPoint:
				c.watchMtx.Lock()
				for _, op := range update {
					c.watchedOutPoints[*op] = struct{}{}
				}
				c.watchMtx.Unlock()

				// We're adding the outpoints that map to the scripts
				// that we should scan for to our filter.
			case map[wire.OutPoint]btcutil.Address:
				c.watchMtx.Lock()
				for op := range update {
					c.watchedOutPoints[op] = struct{}{}
				}
				c.watchMtx.Unlock()

				// We're adding the transactions to our filter.
			case []chainhash.Hash:
				c.watchMtx.Lock()
				for _, txid := range update {
					c.watchedTxs[txid] = struct{}{}
				}
				c.watchMtx.Unlock()
			case []*chainhash.Hash:
				c.watchMtx.Lock()
				for _, txid := range update {
					c.watchedTxs[*txid] = struct{}{}
				}
				c.watchMtx.Unlock()

				// We're starting a rescan from the hash.
			case chainhash.Hash:
				if err := c.rescan(update); err != nil {
					log.Errorf("Unable to complete chain "+
						"rescan: %v", err)
				}
			default:
				log.Warnf("Received unexpected filter type %T",
					update)
			}
		case <-c.quit:
			return
		}
	}
}

// ntfnHandler handles the logic to retrieve ZMQ notifications from the backing
// lightwallet connection.
//
// NOTE: This must be called as a goroutine.
func (c *LightWalletClient) ntfnHandler() {
	defer c.wg.Done()

	for {
		select {
		case header := <-c.zmqHeaderNtfns:
			// TODO: Rostyslav Antonyshyn add valid handler for zmq headers
			header.Nonce = 0
		case newBlock := <-c.zmqChangeTipNtnfs:

			c.bestBlockMtx.Lock()
			bestBlock := c.bestBlock
			c.bestBlockMtx.Unlock()

			if newBlock.Header.PrevBlock == bestBlock.Hash {
				newBlockHeight := bestBlock.Height + 1

				_, err := c.filterBlock(
					newBlock, newBlockHeight, true,
				)
				if err != nil {
					log.Errorf("Unable to filter block %v: %v",
						newBlock.Header.BlockHash().String(), err)
					continue
				}

				// With the block succesfully filtered, we'll
				// make it our new best block.
				bestBlock.Hash = newBlock.Header.BlockHash()
				bestBlock.Height = newBlockHeight
				bestBlock.Timestamp = newBlock.Header.Timestamp

				c.bestBlockMtx.Lock()
				c.bestBlock = bestBlock
				c.bestBlockMtx.Unlock()

				continue
			}

			// Otherwise, we've encountered a reorg.
			if err := c.reorg(bestBlock, newBlock); err != nil {
				log.Errorf("Unable to process chain reorg: %v",
					err)
			}
		case <-c.quit:
			return
		}
	}
}

// reorg processes a reorganization during chain synchronization. This is
// separate from a rescan's handling of a reorg. This will rewind back until it
// finds a common ancestor and notify all the new blocks since then.
func (c *LightWalletClient) reorg(currentBlock waddrmgr.BlockStamp,
	reorgBlock *wire.MsgBlock) error {

	// Retrieve the best known height based on the block which caused the
	// reorg. This way, we can preserve the chain of blocks we need to
	// retrieve.
	bestHash := reorgBlock.BlockHash()
	bestHeight, err := c.GetBlockHeight(&bestHash)
	if err != nil {
		return fmt.Errorf("unable to get block height for %v: %v",
			bestHash, err)
	}

	log.Debugf("Possible reorg at block: height=%v, hash=%v", bestHeight,
		bestHash)

	if bestHeight < currentBlock.Height {
		log.Debugf("Detected multiple reorgs: best_height=%v below "+
			"current_height=%v", bestHeight, currentBlock.Height)
		return nil
	}

	// We'll now keep track of all the blocks known to the *chain*, starting
	// from the best block known to us until the best block in the chain.
	// This will let us fast-forward despite any future reorgs.
	blocksToNotify := list.New()
	blocksToNotify.PushFront(reorgBlock)
	previousBlock := reorgBlock.Header.PrevBlock
	for i := bestHeight - 1; i >= currentBlock.Height; i-- {
		block, err := c.GetBlock(&previousBlock)
		if err != nil {
			return fmt.Errorf("unable to get block %v: %v",
				previousBlock, err)
		}
		blocksToNotify.PushFront(block)
		previousBlock = block.Header.PrevBlock
	}

	// Rewind back to the last common ancestor block using the previous
	// block hash from each header to avoid any race conditions. If we
	// encounter more reorgs, they'll be queued and we'll repeat the cycle.
	//
	// We'll start by retrieving the header to the best block known to us.
	currentHeader, err := c.GetBlockHeader(&currentBlock.Hash)
	if err != nil {
		return fmt.Errorf("unable to get block header for %v: %v",
			currentBlock.Hash, err)
	}

	// Then, we'll walk backwards in the chain until we find our common
	// ancestor.
	for previousBlock != currentHeader.PrevBlock {
		// Since the previous hashes don't match, the current block has
		// been reorged out of the chain, so we should send a
		// BlockDisconnected notification for it.
		log.Debugf("Disconnecting block: height=%v, hash=%v",
			currentBlock.Height, currentBlock.Hash)

		c.onBlockDisconnected(
			&currentBlock.Hash, currentBlock.Height,
			currentBlock.Timestamp,
		)

		// Our current block should now reflect the previous one to
		// continue the common ancestor search.
		currentHeader, err = c.GetBlockHeader(&currentHeader.PrevBlock)
		if err != nil {
			return fmt.Errorf("unable to get block header for %v: %v",
				currentHeader.PrevBlock, err)
		}

		currentBlock.Height--
		currentBlock.Hash = currentHeader.PrevBlock
		currentBlock.Timestamp = currentHeader.Timestamp

		// Store the correct block in our list in order to notify it
		// once we've found our common ancestor.
		block, err := c.GetBlock(&previousBlock)
		if err != nil {
			return fmt.Errorf("unable to get block %v: %v",
				previousBlock, err)
		}
		blocksToNotify.PushFront(block)
		previousBlock = block.Header.PrevBlock
	}

	// Disconnect the last block from the old chain. Since the previous
	// block remains the same between the old and new chains, the tip will
	// now be the last common ancestor.
	log.Debugf("Disconnecting block: height=%v, hash=%v",
		currentBlock.Height, currentBlock.Hash)

	c.onBlockDisconnected(
		&currentBlock.Hash, currentBlock.Height, currentHeader.Timestamp,
	)

	currentBlock.Height--

	// Now we fast-forward to the new block, notifying along the way.
	for blocksToNotify.Front() != nil {
		nextBlock := blocksToNotify.Front().Value.(*wire.MsgBlock)
		nextHeight := currentBlock.Height + 1
		nextHash := nextBlock.BlockHash()
		nextHeader, err := c.GetBlockHeader(&nextHash)
		if err != nil {
			return fmt.Errorf("unable to get block header for %v: %v",
				nextHash, err)
		}

		_, err = c.filterBlock(nextBlock, nextHeight, true)

		if err != nil {
			return fmt.Errorf("unable to filter block %v during reorg", nextHash.String())
		}

		currentBlock.Height = nextHeight
		currentBlock.Hash = nextHash
		currentBlock.Timestamp = nextHeader.Timestamp

		blocksToNotify.Remove(blocksToNotify.Front())
	}

	c.bestBlockMtx.Lock()
	c.bestBlock = currentBlock
	c.bestBlockMtx.Unlock()

	return nil
}

// SetBirthday sets the birthday of the lightwallet rescan client.
//
// NOTE: This should be done before the client has been started in order for it
// to properly carry its duties.
func (c *LightWalletClient) SetBirthday(t time.Time) {
	c.birthday = t
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *LightWalletClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	c.bestBlockMtx.RLock()
	bestBlock := c.bestBlock
	c.bestBlockMtx.RUnlock()

	return &bestBlock, nil
}

// onBlockConnected is a callback that's executed whenever a new block has been
// detected. This will queue a BlockConnected notification to the caller.
func (c *LightWalletClient) onBlockConnected(hash *chainhash.Hash, height int32,
	timestamp time.Time) {

	if c.shouldNotifyBlocks() {
		select {
		case c.notificationQueue.ChanIn() <- BlockConnected{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: height,
			},
			Time: timestamp,
		}:
		case <-c.quit:
		}
	}
}

// onFilteredBlockConnected is an alternative callback that's executed whenever
// a new block has been detected. It serves the same purpose as
// onBlockConnected, but it also includes a list of the relevant transactions
// found within the block being connected. This will queue a
// FilteredBlockConnected notification to the caller.
func (c *LightWalletClient) onFilteredBlockConnected(height int32,
	header *wire.BlockHeader, relevantTxs []*wtxmgr.TxRecord) {

	if c.shouldNotifyBlocks() {
		select {
		case c.notificationQueue.ChanIn() <- FilteredBlockConnected{
			Block: &wtxmgr.BlockMeta{
				Block: wtxmgr.Block{
					Hash:   header.BlockHash(),
					Height: height,
				},
				Time: header.Timestamp,
			},
			RelevantTxs: relevantTxs,
		}:
		case <-c.quit:
		}
	}
}

// onBlockDisconnected is a callback that's executed whenever a block has been
// disconnected. This will queue a BlockDisconnected notification to the caller
// with the details of the block being disconnected.
func (c *LightWalletClient) onBlockDisconnected(hash *chainhash.Hash, height int32,
	timestamp time.Time) {

	if c.shouldNotifyBlocks() {
		select {
		case c.notificationQueue.ChanIn() <- BlockDisconnected{
			Block: wtxmgr.Block{
				Hash:   *hash,
				Height: height,
			},
			Time: timestamp,
		}:
		case <-c.quit:
		}
	}
}

// onRelevantTx is a callback that's executed whenever a transaction is relevant
// to the caller. This means that the transaction matched a specific item in the
// client's different filters. This will queue a RelevantTx notification to the
// caller.
func (c *LightWalletClient) onRelevantTx(tx *wtxmgr.TxRecord,
	blockDetails *btcjson.BlockDetails) {

	block, err := parseBlock(blockDetails)
	if err != nil {
		log.Errorf("Unable to send onRelevantTx notification, failed "+
			"parse block: %v", err)
		return
	}

	select {
	case c.notificationQueue.ChanIn() <- RelevantTx{
		TxRecord: tx,
		Block:    block,
	}:
	case <-c.quit:
	}
}

// onRescanProgress is a callback that's executed whenever a rescan is in
// progress. This will queue a RescanProgress notification to the caller with
// the current rescan progress details.
func (c *LightWalletClient) onRescanProgress(hash *chainhash.Hash, height int32,
	timestamp time.Time) {

	select {
	case c.notificationQueue.ChanIn() <- &RescanProgress{
		Hash:   hash,
		Height: height,
		Time:   timestamp,
	}:
	case <-c.quit:
	}
}

// onRescanFinished is a callback that's executed whenever a rescan has
// finished. This will queue a RescanFinished notification to the caller with
// the details of the last block in the range of the rescan.
func (c *LightWalletClient) onRescanFinished(hash *chainhash.Hash, height int32,
	timestamp time.Time) {

	log.Infof("Rescan finished at %d (%s)", height, hash)

	select {
	case c.notificationQueue.ChanIn() <- &RescanFinished{
		Hash:   hash,
		Height: height,
		Time:   timestamp,
	}:
	case <-c.quit:
	}
}

// FilterBlocks scans the blocks contained in the FilterBlocksRequest for any
// addresses of interest. Each block will be fetched and filtered sequentially,
// returning a FilterBlocksReponse for the first block containing a matching
// address. If no matches are found in the range of blocks requested, the
// returned response will be nil.
//
// NOTE: This is part of the chain.Interface interface.
func (c *LightWalletClient) FilterBlocks(
	req *FilterBlocksRequest) (*FilterBlocksResponse, error) {

	blockFilterer := NewBlockFilterer(c.chainParams, req)

	// Construct the watchlist using the addresses and outpoints contained
	// in the filter blocks request.
	watchList, err := buildFilterBlocksWatchList(req)
	if err != nil {
		return nil, err
	}

	// Iterate over the requested blocks, fetching the compact filter for
	// each one, and matching it against the watchlist generated above. If
	// the filter returns a positive match, the full block is then requested
	// and scanned for addresses using the block filterer.
	for i, blk := range req.Blocks {
		filter, err := c.GetCFilter(&blk.Hash)
		if err != nil {
			return nil, err
		}

		// Skip any empty filters.
		if filter == nil || filter.N() == 0 {
			continue
		}


		key := builder.DeriveKey(&blk.Hash)
		matched, err := filter.MatchAny(key, watchList)
		if err != nil {
			return nil, err
		} else if !matched {
			continue
		}

		log.Infof("Fetching block height=%d hash=%v",
			blk.Height, blk.Hash)

		// TODO(conner): can optimize bandwidth by only fetching
		// stripped blocks
		rawBlock, err := c.GetBlock(&blk.Hash)
		if err != nil {
			return nil, err
		}

		if !blockFilterer.FilterBlock(rawBlock) {
			continue
		}

		// If any external or internal addresses were detected in this
		// block, we return them to the caller so that the rescan
		// windows can widened with subsequent addresses. The
		// `BatchIndex` is returned so that the caller can compute the
		// *next* block from which to begin again.
		resp := &FilterBlocksResponse{
			BatchIndex:         uint32(i),
			BlockMeta:          blk,
			FoundExternalAddrs: blockFilterer.FoundExternal,
			FoundInternalAddrs: blockFilterer.FoundInternal,
			FoundOutPoints:     blockFilterer.FoundOutPoints,
			RelevantTxns:       blockFilterer.RelevantTxns,
		}

		return resp, nil
	}

	// No addresses were found for this range.
	return nil, nil
}

// rescan performs a rescan of the chain using a lightwallet backend, from the
// specified hash to the best known hash, while watching out for reorgs that
// happen during the rescan. It uses the addresses and outputs being tracked by
// the client in the watch list. This is called only within a queue processing
// loop.
func (c *LightWalletClient) rescan(start chainhash.Hash) error {
	log.Infof("Starting rescan from block %s", start)

	// We start by getting the best already processed block. We only use
	// the height, as the hash can change during a reorganization, which we
	// catch by testing connectivity from known blocks to the previous
	// block.


	bestHash, bestHeight, err := c.GetBestBlock()
	if err != nil {
		return err
	}

	bestHeader, err := c.GetBlockHeaderVerbose(bestHash)
	if err != nil {
		return err
	}
	bestBlock := waddrmgr.BlockStamp{
		Hash:      *bestHash,
		Height:    bestHeight,
		Timestamp: time.Unix(bestHeader.Time, 0),
	}

	// Create a list of headers sorted in forward order. We'll use this in
	// the event that we need to backtrack due to a chain reorg.
	headers := list.New()
	previousHeader, err := c.GetBlockHeaderVerbose(&start)
	if err != nil {
		return err
	}
	previousHash, err := chainhash.NewHashFromStr(previousHeader.Hash)
	if err != nil {
		return err
	}
	headers.PushBack(previousHeader)

	// Queue a RescanFinished notification to the caller with the last block
	// processed throughout the rescan once done.
	defer c.onRescanFinished(
		previousHash, previousHeader.Height,
		time.Unix(previousHeader.Time, 0),
	)

	// Cycle through all of the blocks known to lightwallet, being mindful of
	// reorgs.
	for i := previousHeader.Height + 1; i <= bestBlock.Height; i++ {
		hash, err := c.GetBlockHash(int64(i))
		if err != nil {
			return err
		}

		// If the previous header is before the wallet birthday, fetch
		// the current header and construct a dummy block, rather than
		// fetching the whole block itself. This speeds things up as we
		// no longer have to fetch the whole block when we know it won't
		// match any of our filters.

		afterBirthday := previousHeader.Time >= c.birthday.Unix()

		blockHeader, err := c.GetBlockHeader(hash)
		if err != nil {
			return err
		}

		block := &wire.MsgBlock{
			Header: *blockHeader,
		}

		if !afterBirthday {
			afterBirthday = c.birthday.Before(blockHeader.Timestamp)
			if afterBirthday {
				c.onRescanProgress(
					previousHash, i,
					blockHeader.Timestamp,
				)
			}
		}

		if afterBirthday {
			block.Transactions, err = c.GetFilterBlock(hash)

			if err != nil {
				return err
			}
		}

		for blockHeader.PrevBlock.String() != previousHeader.Hash {
			// If we're in this for loop, it looks like we've been
			// reorganized. We now walk backwards to the common
			// ancestor between the best chain and the known chain.
			//
			// First, we signal a disconnected block to rewind the
			// rescan state.
			c.onBlockDisconnected(
				previousHash, previousHeader.Height,
				time.Unix(previousHeader.Time, 0),
			)

			// Get the previous block of the best chain.
			hash, err := c.GetBlockHash(int64(i - 1))
			if err != nil {
				return err
			}
			blockHeader, err = c.GetBlockHeader(hash)
			if err != nil {
				return err
			}

			// Then, we'll the get the header of this previous
			// block.
			if headers.Back() != nil {
				// If it's already in the headers list, we can
				// just get it from there and remove the
				// current hash.
				headers.Remove(headers.Back())
				if headers.Back() != nil {
					previousHeader = headers.Back().
						Value.(*btcjson.GetBlockHeaderVerboseResult)
					previousHash, err = chainhash.NewHashFromStr(
						previousHeader.Hash,
					)
					if err != nil {
						return err
					}
				}
			} else {
				// Otherwise, we get it from lightwallet.
				previousHash, err = chainhash.NewHashFromStr(
					previousHeader.PreviousHash,
				)
				if err != nil {
					return err
				}
				previousHeader, err = c.GetBlockHeaderVerbose(
					previousHash,
				)
				if err != nil {
					return err
				}
			}
		}

		// Now that we've ensured we haven't come across a reorg, we'll
		// add the current block header to our list of headers.
		blockHash := blockHeader.BlockHash()
		previousHash = &blockHash
		previousHeader = &btcjson.GetBlockHeaderVerboseResult{
			Hash:         blockHash.String(),
			Height:       i,
			PreviousHash: blockHeader.PrevBlock.String(),
			Time:         blockHeader.Timestamp.Unix(),
		}
		headers.PushBack(previousHeader)

		// Notify the block and any of its relevant transacations.
		if _, err = c.filterBlock(block, i, true); err != nil {
			return err
		}

		if i%10000 == 0 {
			c.onRescanProgress(
				previousHash, i, blockHeader.Timestamp,
			)
		}

		// If we've reached the previously best known block, check to
		// make sure the underlying node hasn't synchronized additional
		// blocks. If it has, update the best known block and continue
		// to rescan to that point.
		if i == bestBlock.Height {
			bestHash, bestHeight, err = c.GetBestBlock()
			if err != nil {
				return err
			}
			bestHeader, err = c.GetBlockHeaderVerbose(bestHash)
			if err != nil {
				return err
			}

			bestBlock.Hash = *bestHash
			bestBlock.Height = bestHeight
			bestBlock.Timestamp = time.Unix(bestHeader.Time, 0)
		}
	}

	return nil
}

// filterBlock filters a block for watched outpoints and addresses, and returns
// any matching transactions, sending notifications along the way.
func (c *LightWalletClient) filterBlock(block *wire.MsgBlock, height int32,
	notify bool) ([]*wtxmgr.TxRecord, error) {

	// If this block happened before the client's birthday, then we'll skip
	// it entirely.
	if block.Header.Timestamp.Before(c.birthday) {
		return nil, nil
	}

	if c.shouldNotifyBlocks() {
		log.Debugf("Filtering block %d (%s) with %d transactions",
			height, block.BlockHash(), len(block.Transactions))
	}

	// Create a block details template to use for all of the confirmed
	// transactions found within this block.
	blockHash := block.BlockHash()
	blockDetails := &btcjson.BlockDetails{
		Hash:   blockHash.String(),
		Height: height,
		Time:   block.Header.Timestamp.Unix(),
	}

	//
	// Now, we'll through all of the transactions in the block keeping track
	// of any relevant to the caller.
	var relevantTxs []*wtxmgr.TxRecord
	confirmedTxs := make(map[chainhash.Hash]struct{})
	for _, tx := range block.Transactions {

		rec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())

		if err != nil {
			log.Errorf("Failed to create tx record\n")
		}

		isRelevant, err := c.filterTx(rec, blockDetails, notify)
		if err != nil {
			log.Warnf("Unable to filter transaction %v: %v",
				rec.Hash, err)
			continue
		}

		if isRelevant {
			relevantTxs = append(relevantTxs, rec)
			confirmedTxs[rec.Hash] = struct{}{}
		}
	}

	if notify {
		c.onFilteredBlockConnected(height, &block.Header, relevantTxs)
		c.onBlockConnected(&blockHash, height, block.Header.Timestamp)
	}

	return relevantTxs, nil
}

// filterTx determines whether a transaction is relevant to the client by
// inspecting the client's different filters.
func (c *LightWalletClient) filterTx(rec *wtxmgr.TxRecord,
	blockDetails *btcjson.BlockDetails,
	notify bool) (bool, error) {

	// TODO(yuraolex): check this
	// We shouldn't rely on filtering here, as light wallet delivers already filtered
	// transactions, so only transactions that are relevant to current setup will be dispatched
	// so no need for filtering here.

	if blockDetails != nil {
		rec.Received = time.Unix(blockDetails.Time, 0)
	}

	// We'll begin the filtering process by holding the lock to ensure we
	// match exactly against what's currently in the filters.
	c.watchMtx.Lock()
	defer c.watchMtx.Unlock()

	// Otherwise, this is a new transaction we have yet to see. We'll need
	// to determine if this transaction is somehow relevant to the caller.
	var isRelevant bool

	// We'll start by checking all inputs and determining whether it spends
	// an existing outpoint or a pkScript encoded as an address in our watch
	// list.
	for _, txIn := range rec.MsgTx.TxIn {
		// If it matches an outpoint in our watch list, we can exit our
		// loop early.
		if _, ok := c.watchedOutPoints[txIn.PreviousOutPoint]; ok {
			isRelevant = true
			break
		}

		// Otherwise, we'll check whether it matches a pkScript in our
		// watch list encoded as an address. To do so, we'll re-derive
		// the pkScript of the output the input is attempting to spend.
		pkScript, err := txscript.ComputePkScript(
			txIn.SignatureScript, txIn.Witness,
		)
		if err != nil {
			// Non-standard outputs can be safely skipped.
			continue
		}
		addr, err := pkScript.Address(c.chainParams)
		if err != nil {
			// Non-standard outputs can be safely skipped.
			continue
		}
		if _, ok := c.watchedAddresses[addr.String()]; ok {
			isRelevant = true
			break
		}
	}

	// We'll also cycle through its outputs to determine if it pays to
	// any of the currently watched addresses. If an output matches, we'll
	// add it to our watch list.
	for i, txOut := range rec.MsgTx.TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			txOut.PkScript, c.chainParams,
		)
		if err != nil {
			// Non-standard outputs can be safely skipped.
			continue
		}

		for _, addr := range addrs {
			if _, ok := c.watchedAddresses[addr.String()]; ok {
				isRelevant = true
				op := wire.OutPoint{
					Hash:  rec.Hash,
					Index: uint32(i),
				}
				c.watchedOutPoints[op] = struct{}{}
			}
		}
	}

	// If the transaction didn't pay to any of our watched addresses, we'll
	// check if we're currently watching for the hash of this transaction.
	if !isRelevant {
		if _, ok := c.watchedTxs[rec.Hash]; ok {
			isRelevant = true
		}
	}

	// If the transaction is not relevant to us, we can simply exit.
	if !isRelevant {
		return false, nil
	}

	c.onRelevantTx(rec, blockDetails)

	return true, nil
}
