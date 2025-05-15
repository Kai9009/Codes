package chaincode

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract
type SmartContract struct {
	contractapi.Contract
}

// CipherBlock
type CipherBlock struct {
	FileIndex int    `json:"fileIndex"` 
	Content   string `json:"content"`   
	Timestamp string `json:"timestamp"` 
}

// MerkleRecord
type MerkleRecord struct {
	RootHash    string       `json:"rootHash"`    
	CipherBlocks []CipherBlock `json:"cipherBlocks"` 
	LeafHashes  []string      `json:"leafHashes"`  
}

// InitLedger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	return nil
}

// StoreCipherBlocks
func (s *SmartContract) StoreCipherBlocks(ctx contractapi.TransactionContextInterface, fileID string, cipherBlocksJSON string) (string, error) {
	// 1. 
	existing, err := ctx.GetStub().GetState(fileID)
	if err != nil {
		return "", fmt.Errorf("failed to check existing record: %v", err)
	}
	if existing != nil {
		return "", fmt.Errorf("file with ID %s already exists", fileID)
	}

	// 2. 
	var blocks []CipherBlock
	if err := json.Unmarshal([]byte(cipherBlocksJSON), &blocks); err != nil {
		return "", fmt.Errorf("failed to unmarshal cipher blocks: %v", err)
	}

	// 3. 
	txTime := time.Now().Format(time.RFC3339)
	for i := range blocks {
		blocks[i].Timestamp = txTime
	}

	// 4. 
	var leafHashes []string
	for _, block := range blocks {
		hash := sha256.Sum256([]byte(block.Content))
		leafHashes = append(leafHashes, hex.EncodeToString(hash[:]))
	}

	// 5. 
	rootHash, err := s.buildMerkleTree(leafHashes)
	if err != nil {
		return "", fmt.Errorf("failed to build merkle tree: %v", err)
	}

	// 6. 
	record := MerkleRecord{
		RootHash:    rootHash,
		CipherBlocks: blocks,
		LeafHashes:  leafHashes,
	}

	// 7. 
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("failed to marshal record: %v", err)
	}

	if err := ctx.GetStub().PutState(fileID, recordJSON); err != nil {
		return "", fmt.Errorf("failed to put state: %v", err)
	}

	return rootHash, nil
}

// buildMerkleTree 
func (s *SmartContract) buildMerkleTree(hashes []string) (string, error) {
	if len(hashes) == 0 {
		return "", fmt.Errorf("empty hashes list")
	}

	currentLevel := hashes
	for len(currentLevel) > 1 {
		var nextLevel []string
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			right := left
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			}

			combined := left + right
			hash := sha256.Sum256([]byte(combined))
			nextLevel = append(nextLevel, hex.EncodeToString(hash[:]))
		}
		currentLevel = nextLevel
	}

	return currentLevel[0], nil
}

// GetCipherBlocks 
func (s *SmartContract) GetCipherBlocks(ctx contractapi.TransactionContextInterface, fileID string) (*MerkleRecord, error) {
	recordJSON, err := ctx.GetStub().GetState(fileID)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if recordJSON == nil {
		return nil, fmt.Errorf("record for %s does not exist", fileID)
	}

	var record MerkleRecord
	if err := json.Unmarshal(recordJSON, &record); err != nil {
		return nil, err
	}

	return &record, nil
}

// VerifyIntegrity 
func (s *SmartContract) VerifyIntegrity(ctx contractapi.TransactionContextInterface, fileID string) (bool, error) {
	start := time.Now()
	defer func() {
		fmt.Printf("VerifyIntegrity took %s\n", time.Since(start))
	}()


	record, err := s.GetCipherBlocks(ctx, fileID)
	if err != nil {
		return false, err
	}

	// 
	recomputedRoot, err := s.buildMerkleTree(record.LeafHashes)
	if err != nil {
		return false, err
	}

	return recomputedRoot == record.RootHash, nil
}
