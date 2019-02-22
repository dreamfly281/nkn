package moca

import (
	"bytes"
	"time"

	"github.com/nknorg/nkn/core/ledger"
	"github.com/nknorg/nkn/util/log"
	"github.com/nknorg/nkn/util/timer"
)

// startProposing starts the proposing routing
func (consensus *Consensus) startProposing() {
	// Fixme proposingInterval is 500ms, isn't too short
	proposingTimer := time.NewTimer(proposingStartDelay)
	for {
		select {
		case <-proposingTimer.C:
			currHgt := ledger.DefaultLedger.Store.GetHeight()
			expectedHgt := consensus.GetExpectedHeight()
			timestamp := time.Now().Unix()
			if consensus.isBlockProposer(currHgt, timestamp) {
				log.Infof("I am the block proposer at height %d", currHgt + 1)
				block, err := consensus.proposeBlock(currHgt, timestamp)
				if err != nil {
					log.Errorf("Propose block %d at %v error: %v", currHgt + 1, timestamp, err)
					break
				}

				blockHash := block.Header.Hash()
				log.Infof("Propose block %s at height %d", blockHash.ToHexString(), expectedHgt)

				err = consensus.receiveProposal(block)
				if err != nil {
					log.Error(err)
					break
				}

				time.Sleep(electionStartDelay)
			}
		}
		timer.ResetTimer(proposingTimer, proposingInterval)
	}
}

// isBlockProposer returns if local node is the block proposer of block height+1
// at a given timestamp
func (consensus *Consensus) isBlockProposer(height uint32, timestamp int64) bool {
	nextPublicKey, nextChordID, err := ledger.GetNextBlockSigner(height, timestamp)
	if err != nil {
		log.Errorf("Get next block signer error: %v", err)
		return false
	}

	publickKey, err := consensus.account.PublicKey.EncodePoint(true)
	if err != nil {
		log.Errorf("Encode public key error: %v", err)
		return false
	}

	if !bytes.Equal(publickKey, nextPublicKey) {
		return false
	}

	if len(nextChordID) > 0 && !bytes.Equal(consensus.localNode.GetChordID(), nextChordID) {
		return false
	}

	return true
}

// proposeBlock proposes a new block at give height and timestamp
func (consensus *Consensus) proposeBlock(height uint32, currTime int64) (*ledger.Block, error) {
	txn, winnerType, err := ledger.GetNextMiningSigChainTxn(height, currTime)
	if err != nil {
		return nil, err
	}

	return consensus.mining.BuildBlock(height, consensus.localNode.GetChordID(), txn, winnerType, currTime)
}
