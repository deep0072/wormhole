package node

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	math_rand "math/rand"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/certusone/wormhole/node/pkg/common"
	"github.com/certusone/wormhole/node/pkg/db"
	"github.com/certusone/wormhole/node/pkg/devnet"
	publicrpcv1 "github.com/certusone/wormhole/node/pkg/proto/publicrpc/v1"
	"github.com/certusone/wormhole/node/pkg/readiness"
	"github.com/certusone/wormhole/node/pkg/supervisor"
	"github.com/certusone/wormhole/node/pkg/watchers"
	"github.com/certusone/wormhole/node/pkg/watchers/mock"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	libp2p_crypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2p_peer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/test-go/testify/assert"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	eth_common "github.com/ethereum/go-ethereum/common"
)

const LOCAL_RPC_PORTRANGE_START = 10000
const LOCAL_P2P_PORTRANGE_START = 13000

type mockGuardian struct {
	p2pKey           libp2p_crypto.PrivKey
	MockObservationC chan *common.MessagePublication
	MockSetC         chan *common.GuardianSet
	gk               *ecdsa.PrivateKey
	guardianAddr     eth_common.Address
	ready            bool
}

func newMockGuardianSet(n int) []mockGuardian {
	gs := make([]mockGuardian, n)

	for i := 0; i < n; i++ {
		gs[i].p2pKey = devnet.DeterministicP2PPrivKeyByIndex(int64(i))
		gs[i].MockObservationC = make(chan *common.MessagePublication)
		gs[i].MockSetC = make(chan *common.GuardianSet)

		// generate guardian key
		gk, err := ecdsa.GenerateKey(eth_crypto.S256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		gs[i].gk = gk
		gs[i].guardianAddr = GuardianKeyToAddress(gk.PublicKey)
	}

	return gs
}

func mockGuardianSetToGuardianAddrList(gs []mockGuardian) []eth_common.Address {
	result := make([]eth_common.Address, len(gs))
	for i, g := range gs {
		result[i] = g.guardianAddr
	}
	return result
}

func mockPublicSocket(mockGuardianIndex uint) string {
	return fmt.Sprintf("/tmp/test_guardian_%d_public.socket", mockGuardianIndex)
}

func mockAdminStocket(mockGuardianIndex uint) string {
	return fmt.Sprintf("/tmp/test_guardian_%d_admin.socket", mockGuardianIndex)
}

func mockPublicRpc(mockGuardianIndex uint) string {
	return fmt.Sprintf("127.0.0.1:%d", mockGuardianIndex+LOCAL_RPC_PORTRANGE_START)
}

// mockGuardianRunnable returns a runnable that first sets up a mock guardian an then runs it.
func mockGuardianRunnable(gs []mockGuardian, mockGuardianIndex uint) supervisor.Runnable {
	return func(ctx context.Context) error {
		// Create a sub-context with cancel function that we can pass to G.run.
		ctx, ctxCancel := context.WithCancel(ctx)
		defer ctxCancel()
		logger := supervisor.Logger(ctx)

		// setup db
		dataDir := fmt.Sprintf("/tmp/test_guardian_%d", mockGuardianIndex)
		_ = os.RemoveAll(dataDir) // delete any pre-existing data
		db := db.OpenDb(logger, &dataDir)
		defer db.Close()

		// set environment
		env := common.GoTest

		// setup a mock watcher
		var watcherConfigs = []watchers.WatcherConfig{
			&mock.WatcherConfig{
				NetworkID:        "mock",
				ChainID:          vaa.ChainIDEthereum,
				MockObservationC: gs[mockGuardianIndex].MockObservationC,
				MockSetC:         gs[mockGuardianIndex].MockSetC,
				ObservationDb:    nil, // TODO(future work) add observation DB to support re-observation request
			},
		}

		// configure p2p
		nodeName := fmt.Sprintf("g-%d", mockGuardianIndex)
		networkID := "/wormhole/localdev"
		zeroPeerId, err := libp2p_peer.IDFromPublicKey(gs[0].p2pKey.GetPublic())
		if err != nil {
			return err
		}
		bootstrapPeers := fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic/p2p/%s", LOCAL_P2P_PORTRANGE_START, zeroPeerId.String())
		p2pPort := uint(LOCAL_P2P_PORTRANGE_START + mockGuardianIndex)

		// configure publicRpc
		publicSocketPath := mockPublicSocket(mockGuardianIndex)
		publicRpc := mockPublicRpc(mockGuardianIndex)

		// configure adminservice
		adminSocketPath := mockAdminStocket(mockGuardianIndex)
		rpcMap := make(map[string]string)

		// assemble all the options
		guardianOptions := []GuardianOption{
			GuardianOptionWatchers(watcherConfigs, nil),
			GuardianOptionAccountant("", "", false), // effectively disable accountant
			GuardianOptionGovernor(false),           // disable governor
			GuardianOptionP2P(gs[mockGuardianIndex].p2pKey, networkID, bootstrapPeers, nodeName, false, p2pPort, ""),
			GuardianOptionPublicRpcSocket(publicSocketPath, common.GrpcLogDetailFull),
			GuardianOptionPublicrpcTcpService(publicRpc, common.GrpcLogDetailFull),
			GuardianOptionAdminService(adminSocketPath, nil, nil, rpcMap),
		}

		guardianNode := NewGuardianNode(
			env,
			db,
			gs[mockGuardianIndex].gk,
			nil,
		)

		if err = supervisor.Run(ctx, "g", guardianNode.Run(ctxCancel, guardianOptions...)); err != nil {
			panic(err)
		}

		<-ctx.Done()

		// cleanup
		// _ = os.RemoveAll(dataDir) // we don't do this for now since this could run before BadgerDB's flush(), causing an error; Meh

		return nil
	}
}

// setupLogsCapture is a helper function for making a zap logger/observer combination for testing that certain logs have been made
func setupLogsCapture() (*zap.Logger, *observer.ObservedLogs) {
	observedCore, logs := observer.New(zap.DebugLevel)
	logger, _ := zap.NewDevelopment(zap.WrapCore(func(c zapcore.Core) zapcore.Core { return zapcore.NewTee(c, observedCore) }))
	return logger, logs
}

func TestNodes(t *testing.T) {
	const testTimeout = time.Second * 60
	const numGuardians = 3
	const numMessages = 3
	const guardianSetIndex = 5           // index of the active guardian set (can be anything, just needs to be set to something)
	const vaaCheckGuardianIndex uint = 0 // we will query this guardian's publicrpc for VAAs

	readiness.NoPanic = true // otherwise we'd panic when running multiple guardians

	// Test's main lifecycle context.
	rootCtx, rootCtxCancel := context.WithTimeout(context.Background(), testTimeout)
	defer rootCtxCancel()

	zapLogger, zapObserver := setupLogsCapture()

	supervisor.New(rootCtx, zapLogger, func(ctx context.Context) error {
		logger := supervisor.Logger(ctx)

		// create the Guardian Set
		gs := newMockGuardianSet(numGuardians)

		// run the guardians
		for i := 0; i < numGuardians; i++ {
			gRun := mockGuardianRunnable(gs, uint(i))
			err := supervisor.Run(ctx, fmt.Sprintf("g-%d", i), gRun)
			assert.NoError(t, err)
		}
		logger.Info("All Guardians initiated.")
		supervisor.Signal(ctx, supervisor.SignalHealthy)

		// Inform them of the Guardian Set
		commonGuardianSet := common.GuardianSet{
			Keys:  mockGuardianSetToGuardianAddrList(gs),
			Index: guardianSetIndex,
		}
		for i, g := range gs {
			logger.Info("Sending guardian set update", zap.Int("guardian_index", i))
			g.MockSetC <- &commonGuardianSet
		}

		// Wait for them to connect each other and receive at least one heartbeat
		// example log entry that we're looking for:
		// 		DEBUG	root.g-2.g.p2p	p2p/p2p.go:465	valid signed heartbeat received	{"value": "node_name:\"g-0\"  timestamp:1685677055425243683  version:\"development\"  guardian_addr:\"0xeF2a03eAec928DD0EEAf35aD31e34d2b53152c07\"  boot_timestamp:1685677040424855922  p2p_node_id:\"\\x00$\\x08\\x01\\x12 \\x97\\xf3\\xbd\\x87\\x13\\x15(\\x1e\\x8b\\x83\\xedǩ\\xfd\\x05A\\x06aTD\\x90p\\xcc\\xdb<\\xddB\\xcfi\\xccވ\"", "from": "12D3KooWL3XJ9EMCyZvmmGXL2LMiVBtrVa2BuESsJiXkSj7333Jw"}
		// TODO maybe instead of looking at log entries, we could determine this status through prometheus metrics, which might be more stable
		re := regexp.MustCompile("g-[0-9]+")

		for readyCounter := 0; readyCounter < len(gs); {
			// read log messages
			for _, loggedEntry := range zapObserver.FilterMessage("valid signed heartbeat received").All() {
				for _, f := range loggedEntry.Context {
					if f.Key == "value" {
						s, ok := f.Interface.(fmt.Stringer)
						assert.True(t, ok)
						match := re.FindStringSubmatch(s.String())
						assert.NotZero(t, len(match))
						guardianId, err := strconv.Atoi(match[0][2:])
						assert.NoError(t, err)
						assert.True(t, guardianId < len(gs))

						if gs[guardianId].ready == false {
							gs[guardianId].ready = true
							readyCounter++
						}
					}
				}
			}
			time.Sleep(time.Microsecond * 100)
		}
		logger.Info("All Guardians have received at least one heartbeat.")

		// have them make some observations
		sentMessagesLog := make([]common.MessagePublication, numMessages)
		ticker := time.NewTicker(time.Millisecond)

		for i := 0; i < numMessages; i++ {
			select {
			case <-ctx.Done():
				return nil
			case t := <-ticker.C:
				// create a mock message
				msg := common.MessagePublication{
					TxHash:           [32]byte{1, 2, 3},
					Timestamp:        time.Unix(int64(t.Unix()), 0), // convert time to unix and back to match what is done during serialization/de-serialization
					Nonce:            math_rand.Uint32(),            //nolint
					Sequence:         uint64(i),
					ConsistencyLevel: 1,
					EmitterChain:     vaa.ChainIDEthereum,
					EmitterAddress:   [32]byte{1, 2, 3},
					Payload:          []byte{},
					Unreliable:       false,
				}

				sentMessagesLog[i] = msg

				// make the guardians observe it
				for guardianIndex, g := range gs {
					msgCopy := msg
					logger.Info("requesting mock observation for guardian", msgCopy.ZapFields(zap.Int("guardian_index", guardianIndex))...)
					g.MockObservationC <- &msgCopy
				}
			}
		}

		// Wait for publicrpc to come online
		for zapObserver.FilterMessage("publicrpc server listening").FilterField(zap.String("addr", mockPublicRpc(vaaCheckGuardianIndex))).Len() == 0 {
			logger.Info("publicrpc seems to be offline (according to logs). Waiting 100ms...")
			time.Sleep(time.Microsecond * 100)
		}

		// check that the VAAs were generated and g0 has them
		logger.Info("Connecting to publicrpc...")
		conn, err := grpc.Dial(mockPublicRpc(vaaCheckGuardianIndex), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)

		defer conn.Close()
		c := publicrpcv1.NewPublicRPCServiceClient(conn)

		gsAddrList := mockGuardianSetToGuardianAddrList(gs)

		for i, msg := range sentMessagesLog {
			var r *publicrpcv1.GetSignedVAAResponse

			logger.Info("Checking for Quorum on message", zap.Int("message_index", i))

			// poll the API until we get a response without error
			for {
				select {
				case <-ctx.Done():
					assert.Fail(t, "timed out")
				default:
					// timeout for grpc query
					logger.Info("attempting to query for VAA", zap.Int("message_index", i))
					queryCtx, queryCancel := context.WithTimeout(context.Background(), time.Second)
					r, err = c.GetSignedVAA(queryCtx, &publicrpcv1.GetSignedVAARequest{
						MessageId: &publicrpcv1.MessageID{
							EmitterChain:   publicrpcv1.ChainID(msg.EmitterChain),
							EmitterAddress: msg.EmitterAddress.String(),
							Sequence:       msg.Sequence,
						},
					})
					queryCancel()
					if err != nil {
						logger.Info("error querying for VAA. Trying agin in 100ms.", zap.Int("message_index", i))
					}
				}
				if err == nil && r != nil {
					logger.Info("Received VAA from publicrpc", zap.Int("message_index", i))
					break
				}
				time.Sleep(time.Millisecond * 100)
			}

			logger.Info("publicrpc VAA bytes", zap.Binary("bytes", r.VaaBytes))

			returnedVaa, err := vaa.Unmarshal(r.VaaBytes)
			assert.NoError(t, err)

			// Check signatures
			err = returnedVaa.Verify(gsAddrList)
			assert.NoError(t, err)

			// Match all the fields
			assert.Equal(t, returnedVaa.Version, uint8(1))
			assert.Equal(t, returnedVaa.GuardianSetIndex, uint32(guardianSetIndex))
			assert.Equal(t, returnedVaa.Timestamp, msg.Timestamp)
			assert.Equal(t, returnedVaa.Nonce, msg.Nonce)
			assert.Equal(t, returnedVaa.Sequence, msg.Sequence)
			assert.Equal(t, returnedVaa.ConsistencyLevel, msg.ConsistencyLevel)
			assert.Equal(t, returnedVaa.EmitterChain, msg.EmitterChain)
			assert.Equal(t, returnedVaa.EmitterAddress, msg.EmitterAddress)
			assert.Equal(t, returnedVaa.Payload, msg.Payload)
		}

		// Everything good!
		logger.Info("Tests passed.")

		supervisor.Signal(ctx, supervisor.SignalDone)

		rootCtxCancel()
		return nil
	},
		supervisor.WithPropagatePanic)

	<-rootCtx.Done()
	assert.NotEqual(t, rootCtx.Err(), context.DeadlineExceeded)
	zapLogger.Info("Test root context cancelled, exiting...")
}
