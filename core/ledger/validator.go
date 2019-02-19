package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/gogo/protobuf/proto"
	. "github.com/nknorg/nkn/common"
	"github.com/nknorg/nkn/core/signature"
	tx "github.com/nknorg/nkn/core/transaction"
	"github.com/nknorg/nkn/core/transaction/payload"
	"github.com/nknorg/nkn/crypto"
	. "github.com/nknorg/nkn/errors"
	"github.com/nknorg/nkn/util/log"
	"github.com/nknorg/nkn/por"
	"github.com/nknorg/nkn/util/config"
)

const (
	TimestampTolerance = 40 * time.Second
)

type VBlock struct {
	Block       *Block
	ReceiveTime int64
}

type TransactionArray []*tx.Transaction

func (iterable TransactionArray) Iterate(handler func(item *tx.Transaction) ErrCode) ErrCode {
	for _, item := range iterable {
		result := handler(item)
		if result != ErrNoError {
			return result
		}
	}

	return ErrNoError
}

func TransactionCheck(block *Block) error {
	if block.Transactions == nil {
		return errors.New("empty block")
	}
	if block.Transactions[0].TxType != tx.Coinbase {
		return errors.New("first transaction in block is not Coinbase")
	}
	for i, txn := range block.Transactions {
		if i != 0 && txn.TxType == tx.Coinbase {
			return errors.New("Coinbase transaction order is incorrect")
		}
		if errCode := tx.VerifyTransaction(txn); errCode != ErrNoError {
			return errors.New("transaction sanity check failed")
		}
		if errCode := tx.VerifyTransactionWithLedger(txn); errCode != ErrNoError {
			return errors.New("transaction history check failed")
		}
	}
	if errCode := tx.VerifyTransactionWithBlock(TransactionArray(block.Transactions)); errCode != ErrNoError {
		return errors.New("transaction block check failed")
	}

	return nil
}

// GetNextBlockSigner gets the next block signer after block height at
// timestamp. Returns next signer's public key, chord ID, winner type, and error
func GetNextBlockSigner(height uint32, timestamp int64) ([]byte, []byte, WinnerType, error) {
	var publicKey []byte
	var chordID []byte

	currentHeight := DefaultLedger.Store.GetHeight()
	// Fixme Useless compare as the height get from the same place, except some race case?
	if height > currentHeight {
		return nil, nil, 0, fmt.Errorf("Height %d is higher than current height %d", height, currentHeight)
	}

	hdrHash := DefaultLedger.Store.GetHeaderHashByHeight(height)
	hdr, err := DefaultLedger.Store.GetHeader(hdrHash)
	if err != nil {
		return nil, nil, 0, err
	}
	// Fixme, Not match with the tolerence time
	if timestamp <= hdr.Timestamp {
		return nil, nil, 0, fmt.Errorf("timestamp %d is earlier than previous block timestamp %d",
			timestamp, hdr.Timestamp)
	}

	winnerType := hdr.WinnerType
	timeSinceLastBlock := timestamp - hdr.Timestamp
	proposerTimeout := int64(config.ProposerChangeTime / time.Second)
	if timeSinceLastBlock < proposerTimeout {
		switch winnerType {
		case GenesisSigner:
			genesisBlockHash, err := DefaultLedger.Store.GetBlockHash(0)
			if err != nil {
				return nil, nil, 0, err
			}

			genesisBlock, err := DefaultLedger.Store.GetBlock(genesisBlockHash)
			if err != nil {
				return nil, nil, 0, err
			}

			publicKey, chordID, err = genesisBlock.GetSigner()
			if err != nil {
				return nil, nil, 0, err
			}
		case TxnSigner:
			txn, err := DefaultLedger.Store.GetTransaction(hdr.WinnerHash)
			if err != nil {
				return nil, nil, 0, err
			}
			payload, ok := txn.Payload.(*payload.Commit)
			if !ok {
				return nil, nil, 0, errors.New("invalid transaction type")
			}
			sigchain := &por.SigChain{}
			proto.Unmarshal(payload.SigChain, sigchain)

			publicKey, chordID, err = sigchain.GetMiner()
			if err != nil {
				return nil, nil, 0, err
			}
		case TimeOutTxnSigner:
			winnerType = TxnSigner
			txn, err := DefaultLedger.Store.GetTransaction(hdr.WinnerHash)
			if err != nil {
				return nil, nil, 0, err
			}
			payload, ok := txn.Payload.(*payload.Commit)
			if !ok {
				return nil, nil, 0, errors.New("invalid transaction type")
			}
			sigchain := &por.SigChain{}
			proto.Unmarshal(payload.SigChain, sigchain)

			publicKey, chordID, err = sigchain.GetNextMiner(hdrHash)
			if err != nil {
				return nil, nil, 0, err
			}

		}
	} else {
		winnerType = TimeOutTxnSigner
		// FiXME the txn not be package/blocklization successfully and always keeps in the por server ??
		// TODO add aging time for signature chain to avoid the dead node send a txn without proposal block
		sigChain := por.GetPorServer().GetMiningSigChain(height)
		if (sigChain == nil) {
			log.Warningf("No valid sigchain found when timeout for height ", height)
			return nil, nil, 0, err
		}
		publicKey, chordID, err = sigChain.GetMiner()
		if err != nil {
			return nil, nil, 0, err
		}
	}

	return publicKey, chordID, winnerType, nil
}

// GetWinner returns the winner hash and winner type of a block height using
// sigchain from PoR server.
func GetNextMiningSigChainTxn(height uint32) (*tx.Transaction, WinnerType, error) {
	height = height - 1
	hdrHash := DefaultLedger.Store.GetHeaderHashByHeight(height)
	hdr, err := DefaultLedger.Store.GetHeader(hdrHash)
	if err != nil {
		log.Warning("Not found hdr hash for height: ", height)
		return nil, 0, err
	}

	if height < NumGenesisBlocks {
		return nil, GenesisSigner, nil
	}

	txn, err := por.GetPorServer().GetMiningSigChainTxn(height)
	if err != nil {
		return nil, TxnSigner, err
	}

	if txn == nil {
		return nil, BlockSigner, errors.New("Couldn't find valid sigChain")
	}

	winnerType := TxnSigner
	timestamp := time.Now().Unix()
	timeSinceLastBlock := timestamp - hdr.Timestamp
	proposerTimeout := int64(config.ProposerChangeTime / time.Second)
	if timeSinceLastBlock >= proposerTimeout {
		winnerType = TimeOutTxnSigner
	}

	return txn, winnerType, nil
}

// // GetWinner returns the winner hash and winner type of a block height using
// // sigchain from PoR server.
// func GetNextMiningSigChainTxnHash(height uint32) (Uint256, WinnerType, error) {
// 	height = height - 1
// 	hdrHash := DefaultLedger.Store.GetHeaderHashByHeight(height)
// 	hdr, err := DefaultLedger.Store.GetHeader(hdrHash)
// 	if err != nil {
// 		log.Warning("Not found hdr hash for height: ", height)
// 		return EmptyUint256, 0, err
// 	}

// 	if height < NumGenesisBlocks {
// 		return EmptyUint256, GenesisSigner, nil
// 	}

// 	txn, err := por.GetPorServer().GetMiningSigChainTxn(height)
// 	if err != nil {
// 		return EmptyUint256, TxnSigner, err
// 	}

// 	if txn == nil {
// 		return EmptyUint256, BlockSigner, errors.New("Couldn't find valid sigChain")
// 	}

// 	winnerType := TxnSigner
// 	timestamp := time.Now().Unix()
// 	timeSinceLastBlock := timestamp - hdr.Timestamp
// 	proposerTimeout := int64(config.ProposerChangeTime / time.Second)
// 	if timeSinceLastBlock >= proposerTimeout {
// 		winnerType = TimeOutTxnSigner
// 	}

// 	return txnHash, winnerType, nil
// }


func SignerCheck(header *Header) error {
	currentHeight := DefaultLedger.Store.GetHeight()
	publicKey, chordID, _, err := GetNextBlockSigner(currentHeight, header.Timestamp)
	if err != nil {
		return err
	}

	if !bytes.Equal(header.Signer, publicKey) {
		return fmt.Errorf("invalid block signer public key %x, should be %x", header.Signer, publicKey)
	}

	if len(chordID) > 0 && !bytes.Equal(header.ChordID, chordID) {
		return fmt.Errorf("invalid block signer chord ID %x, should be %x", header.ChordID, chordID)
	}

	rawPubKey, err := crypto.DecodePoint(publicKey)
	if err != nil {
		return err
	}
	err = crypto.Verify(*rawPubKey, signature.GetHashForSigning(header), header.Signature)
	if err != nil {
		return err
	}

	return nil
}

func HeaderCheck(header *Header) error {
	if header.Height == 0 {
		return nil
	}

	expectedHeight := DefaultLedger.Store.GetHeight() + 1
	if header.Height != expectedHeight {
		return fmt.Errorf("Block height %d is different from expected height %d", header.Height, expectedHeight)
	}

	err := SignerCheck(header)
	if err != nil {
		return err
	}

	currentHash := DefaultLedger.Store.GetCurrentBlockHash()
	if header.PrevBlockHash != currentHash {
		return errors.New("invalid prev header")
	}

	prevHeader, err := DefaultLedger.Blockchain.GetHeader(currentHash)
	if err != nil {
		return err
	}
	if prevHeader == nil {
		return errors.New("cannot get prev header")
	}

	if prevHeader.Timestamp >= header.Timestamp {
		return errors.New("invalid header timestamp")
	}

	if header.WinnerType == GenesisSigner && header.Height >= NumGenesisBlocks {
		return errors.New("invalid winning hash type")
	}

	return nil
}

func TimestampCheck(timestamp int64) error {
	t := time.Unix(timestamp, 0) // Handle negative
	now := time.Now()
	earliest := now.Add(-TimestampTolerance)
	latest := now.Add(TimestampTolerance)

	if t.Before(earliest) || t.After(latest) {
		return fmt.Errorf("timestamp %d exceed my tolerance [%d, %d]", timestamp, earliest.Unix(), latest.Unix())
	}

	return nil
}

func NextBlockProposerCheck(block *Block) error {
	winnerTxn, winnerType, err := GetNextMiningSigChainTxn(block.Header.Height)
	if err != nil {
		return err
	}

	winnerHash := EmptyUint256
	if winnerTxn != nil {
		winnerHash = winnerTxn.Hash()
	}
	if winnerHash == EmptyUint256 && block.Header.WinnerHash != EmptyUint256 {
		for _, txn := range block.Transactions {
			if txn.Hash() == block.Header.WinnerHash {
				_, err = por.NewPorPackage(txn)
				return err
			}
		}
		return fmt.Errorf("mining sigchain txn %s not found in block", block.Header.WinnerHash.ToHexString())
	}

	if winnerType != block.Header.WinnerType {
		return fmt.Errorf("Winner type should be %v instead of %v", winnerType, block.Header.WinnerType)
	}

	if winnerHash != block.Header.WinnerHash {
		return fmt.Errorf("Winner hash should be %s instead of %s", winnerHash.ToHexString(), block.Header.WinnerHash.ToHexString())
	}

	if block.Header.WinnerHash != EmptyUint256 {
		found := false
		for _, txn := range block.Transactions {
			if txn.Hash() == block.Header.WinnerHash {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("mining sigchain txn %s not found in block", block.Header.WinnerHash.ToHexString())
		}
	}

	return nil
}

func CanVerifyHeight(height uint32) bool {
	return height == DefaultLedger.Store.GetHeight()+1
}
