package chain

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	grpcclient "github.com/btcsuite/btcd/grpcclient"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightninglabs/gozmq"
	//"github.com/lightningnetwork/lnd/signal"
)

// BitcoindConn represents a persistent client connection to a bitcoind node
// that listens for events read from a ZMQ connection.
type LightWalletConn struct {
	started int32 // To be used atomically.
	stopped int32 // To be used atomically.

	// rescanClientCounter is an atomic counter that assigns a unique ID to
	// each new bitcoind rescan client using the current bitcoind
	// connection.
	rescanClientCounter uint64

	// chainParams identifies the current network the bitcoind node is
	// running on.
	chainParams *chaincfg.Params

	// client is the RPC client to the bitcoind node.
	//client	*rpcclient.Client
	grpcClient *grpcclient.Client

	// zmqHeaderHost is the host listening for ZMQ connections that will be
	// responsible for delivering raw header events.
	zmqHeaderHost string

	// zmqPollInterval is the interval at which we'll attempt to retrieve an
	// event from the ZMQ connection.
	zmqPollInterval time.Duration

	// rescanClients is the set of active bitcoind rescan clients to which
	// ZMQ event notfications will be sent to.
	rescanClientsMtx sync.Mutex
	rescanClients    map[uint64]*LightWalletClient

	quit chan struct{}
	wg   sync.WaitGroup
}

// NewBitcoindConn creates a client connection to the node described by the host
// string. The connection is not established immediately, but must be done using
// the Start method. If the remote node does not operate on the same bitcoin
// network as described by the passed chain parameters, the connection will be
// disconnected.
func NewLightWalletConn(chainParams *chaincfg.Params, host, user, pass,
	zmqHeaderHost string, zmqPollInterval time.Duration) (*LightWalletConn, error) {

	clientCfg := &rpcclient.ConnConfig{
		Host:                 host,
		User:                 user,
		Pass:                 pass,
		DisableAutoReconnect: false,
		DisableConnectOnNew:  true,
		DisableTLS:           true,
		HTTPPostMode:         true,
	}

	grpcClient, err := grpcclient.New(clientCfg)
	if err != nil {
		return nil, err
	}

	conn := &LightWalletConn{
		chainParams:     chainParams,
		grpcClient:      grpcClient,
		zmqHeaderHost:   zmqHeaderHost,
		zmqPollInterval: zmqPollInterval,
		rescanClients:   make(map[uint64]*LightWalletClient),
		quit:            make(chan struct{}),
	}

	return conn, nil
}

func (c *LightWalletConn) RPCClient() *grpcclient.Client{
	return c.grpcClient
}

// Start attempts to establish a RPC and ZMQ connection to a bitcoind node. If
// successful, a goroutine is spawned to read events from the ZMQ connection.
// It's possible for this function to fail due to a limited number of connection
// attempts. This is done to prevent waiting forever on the connection to be
// established in the case that the node is down.
func (c *LightWalletConn) Start() error {
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return nil
	}

	// Verify that the node is running on the expected network.
	net, err := c.getCurrentNet()
	if err != nil {
		c.grpcClient.Disconnect()
		return err
	}

	if net != c.chainParams.Net {
		c.grpcClient.Disconnect()
		return fmt.Errorf("expected network %v, got %v",
			c.chainParams.Net, net)
	}

	// Establish two different ZMQ connections to bitcoind to retrieve block
	// and transaction event notifications. We'll use two as a separation of
	// concern to ensure one type of event isn't dropped from the connection
	// queue due to another type of event filling it up.

	zmqHeaderConn, err := gozmq.Subscribe(
		c.zmqHeaderHost, []string{"hashblock", "rawheader"}, c.zmqPollInterval,
	)
	if err != nil {
		c.grpcClient.Disconnect()
		return fmt.Errorf("unable to subscribe for zmq header events: "+
			"%v", err)
	}

	c.wg.Add(1)
	go c.headerEventHandler(zmqHeaderConn)

	return nil
}

// Stop terminates the RPC and ZMQ connection to a bitcoind node and removes any
// active rescan clients.
func (c *LightWalletConn) Stop() {
	if !atomic.CompareAndSwapInt32(&c.stopped, 0, 1) {
		return
	}

	for _, client := range c.rescanClients {
		client.Stop()
	}

	close(c.quit)
	c.grpcClient.Disconnect()
	c.wg.Wait()
}

// blockEventHandler reads raw header events from the ZMQ header socket and
// forwards them along to the current rescan client.
//
// NOTE: This must be run as a goroutine.
func (c *LightWalletConn) headerEventHandler(conn *gozmq.Conn) {
	defer c.wg.Done()
	defer conn.Close()
	//defer signal.RequestShutdown()

	log.Info("Started listening for header notifications via ZMQ "+
		"on", c.zmqHeaderHost)

	var (
		command [len("rawheader")]byte
		seqNum  [seqNumLen]byte
		data    = make([]byte, maxRawBlockSize)
	)

	for {
		// Before attempting to read from the ZMQ socket, we'll make
		// sure to check if we've been requested to shut down.
		select {
		case <-c.quit:
			return
		default:
		}

		// Poll an event from the ZMQ socket.
		var (
			msgBytes = [][]byte{command[:], data, seqNum[:]}
			err  error
		)

		// Poll an event from the ZMQ socket.
		msgBytes, err = conn.Receive(msgBytes)
		if err != nil {

			// EOF should only be returned if the connection was
			// explicitly closed, so we can exit at this point.
			if strings.Contains(err.Error(), "EOF") ||
				strings.Contains(err.Error(), "An existing connection was forcibly closed by the remote host") {
					return
			}

			// It's possible that the connection to the socket
			// continuously times out, so we'll prevent logging this
			// error to prevent spamming the logs.
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				continue
			}

			log.Errorf("Unable to receive ZMQ rawheader message: %v",
				err)
			continue
		}

		// We have an event! We'll now ensure it is a block event,
		// deserialize it, and report it to the different rescan
		// clients.
		eventType := string(msgBytes[0])

		switch eventType {
		case "rawheader":
			lightHeader := &wire.LightWalletHeader{}
			r := bytes.NewReader(msgBytes[1])
			// Decode the raw bytes into a proper header.
			if err := lightHeader.DeserializeLightHeader(r); err != nil {
				log.Errorf("Unable to deserialize header: %v",
					err)
				continue
			}

			blockHeader := lightHeader.BlockHeader()

			c.rescanClientsMtx.Lock()
			for _, client := range c.rescanClients {
				select {
				case client.zmqHeaderNtfns <- blockHeader:
				case <-client.quit:
				case <-c.quit:
					c.rescanClientsMtx.Unlock()
					return
				}
			}
			c.rescanClientsMtx.Unlock()
		case "hashblock":
			hash := hex.EncodeToString(msgBytes[1])
			chainHash,_ := chainhash.NewHashFromStr(hash)

			block, err := c.grpcClient.GetBlock(chainHash)
			if err != nil {
				continue;
			}

			c.rescanClientsMtx.Lock()
			for _, client := range c.rescanClients {
				select {
				case client.zmqChangeTipNtnfs <- block:
				case <-client.quit:
				case <-c.quit:
					c.rescanClientsMtx.Unlock()
					return
				}
			}
			c.rescanClientsMtx.Unlock()

		default:
			// It's possible that the message wasn't fully read if
			// bitcoind shuts down, which will produce an unreadable
			// event type. To prevent from logging it, we'll make
			// sure it conforms to the ASCII standard.
			if eventType == "" || !isASCII(eventType) {
				continue
			}

			log.Warnf("Received unexpected event type from "+
				"rawblock subscription: %v", eventType)
		}
	}
}

// getCurrentNet returns the network on which the bitcoind node is running.
func (c *LightWalletConn) getCurrentNet() (wire.BitcoinNet, error) {

	hash, err := c.grpcClient.GetBlockHash(0)
	if err != nil {
		return 0, err
	}

	switch *hash {
	case *chaincfg.TestNet3Params.GenesisHash:
		return chaincfg.LitecoinLWTestNetParams.Net, nil
	case *chaincfg.RegressionNetParams.GenesisHash:
		return chaincfg.LitecoinLWRegTestParams.Net, nil
	case *chaincfg.MainNetParams.GenesisHash:
		return chaincfg.LitecoinLWParams.Net, nil
	default:
		return 0, fmt.Errorf("unknown network with genesis hash %v", hash)
	}
}

// NewLightWalletClient returns a bitcoind client using the current bitcoind
// connection. This allows us to share the same connection using multiple
// clients.
func (c *LightWalletConn) NewLightWalletClient() *LightWalletClient {
	return &LightWalletClient{
		quit: make(chan struct{}),

		id: atomic.AddUint64(&c.rescanClientCounter, 1),

		chainParams: c.chainParams,
		ChainConn:   c,

		rescanUpdate:     make(chan interface{}),
		watchedAddresses: make(map[string]struct{}),
		watchedOutPoints: make(map[wire.OutPoint]struct{}),
		watchedTxs:       make(map[chainhash.Hash]struct{}),

		notificationQueue: NewConcurrentQueue(20),
		zmqHeaderNtfns:    make(chan *wire.BlockHeader),
		zmqChangeTipNtnfs: make(chan *wire.MsgBlock),
	}
}

// AddClient adds a client to the set of active rescan clients of the current
// chain connection. This allows the connection to include the specified client
// in its notification delivery.
//
// NOTE: This function is safe for concurrent access.
func (c *LightWalletConn) AddClient(client *LightWalletClient) {
	c.rescanClientsMtx.Lock()
	defer c.rescanClientsMtx.Unlock()

	c.rescanClients[client.id] = client
}

// RemoveClient removes the client with the given ID from the set of active
// rescan clients. Once removed, the client will no longer receive block and
// transaction notifications from the chain connection.
//
// NOTE: This function is safe for concurrent access.
func (c *LightWalletConn) RemoveClient(id uint64) {
	c.rescanClientsMtx.Lock()
	defer c.rescanClientsMtx.Unlock()

	delete(c.rescanClients, id)
}
