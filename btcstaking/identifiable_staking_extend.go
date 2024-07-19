package btcstaking

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type PayloadOpReturnData struct {
	ChainID                     []byte
	ChainIdUserAddress          []byte
	ChainIdSmartContractAddress []byte
	Amount                      uint32
}

func NewPayloadOpReturnData(
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	amount []byte,
) (*PayloadOpReturnData, error) {
	if len(chainID) != chainIdBytes {
		return nil, fmt.Errorf("invalid chain id length: %d, expected: %d", len(chainID), chainIdBytes)
	}
	if len(chainIdUserAddress) != ChainIdUserAddressBytes {
		return nil, fmt.Errorf("invalid chain id user address length: %d, expected: %d", len(chainIdUserAddress), ChainIdUserAddressBytes)
	}
	if len(chainIdSmartContractAddress) != ChainIdSmartContractAddressBytes {
		return nil, fmt.Errorf("invalid chain id smart contract address length: %d, expected: %d", len(chainIdSmartContractAddress), ChainIdSmartContractAddressBytes)
	}
	if len(amount) != AmountBytes {
		return nil, fmt.Errorf("invalid amount length: %d, expected: %d", len(amount), AmountBytes)
	}
	amount_uint32 := binary.BigEndian.Uint32(amount)
	return NewPayloadOpReturnDataFromParsed(chainID, chainIdUserAddress, chainIdSmartContractAddress, amount_uint32)
}

func NewPayloadOpReturnDataFromParsed(
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	Amount uint32,
) (*PayloadOpReturnData, error) {
	return &PayloadOpReturnData{
		ChainID:                     chainID,
		ChainIdUserAddress:          chainIdUserAddress,
		ChainIdSmartContractAddress: chainIdSmartContractAddress,
		Amount:                      Amount,
	}, nil
}

func NewPayloadOpReturnDataFromBytes(b []byte) (*PayloadOpReturnData, error) {
	if len(b) != PayloadOpReturnDataSize {
		return nil, fmt.Errorf("invalid payload op return data length: %d, expected: %d", len(b), PayloadOpReturnDataSize)
	}
	chainID := b[:chainIdBytes]
	chainIdUserAddress := b[chainIdBytes : chainIdBytes+ChainIdUserAddressBytes]
	chainIdSmartContractAddress := b[chainIdBytes+ChainIdUserAddressBytes : chainIdBytes+ChainIdUserAddressBytes+ChainIdSmartContractAddressBytes]
	amount := b[chainIdBytes+ChainIdUserAddressBytes+ChainIdSmartContractAddressBytes:]
	return NewPayloadOpReturnData(chainID, chainIdUserAddress, chainIdSmartContractAddress, amount)
}

func getPayloadOPReturnBytes(out *wire.TxOut) ([]byte, error) {
	if out == nil {
		return nil, fmt.Errorf("nil tx output")
	}

	// We are adding `+3` as each op return has additional 3 for:
	// 1. OP_RETURN opcode - which signalizes that data is provably unspendable
	// 2. OP_PUSHDATA1 opcode - which pushes the next byte contains the number of bytes to be pushed onto the stack.
	// 3. 0x50 - we define that in code is OP_80 which is the bytes number to be pushed onto the stack
	if len(out.PkScript) != PayloadOpReturnDataSize+3 {
		return nil, fmt.Errorf("invalid op return data length: %d, expected: %d", len(out.PkScript), PayloadOpReturnDataSize+3)
	}
	if !txscript.IsNullData(out.PkScript) {
		return nil, fmt.Errorf("invalid op return script")
	}
	return out.PkScript[3:], nil
}

func NewPayloadOpReturnDataFromTxOutput(out *wire.TxOut) (*PayloadOpReturnData, error) {
	data, err := getPayloadOPReturnBytes(out)

	if err != nil {
		return nil, fmt.Errorf("cannot parse payload op return data: %w", err)
	}

	return NewPayloadOpReturnDataFromBytes(data)
}

type ParsedV0MintingTx struct {
	MintingOutput       *wire.TxOut
	MintingOutputIdx    int
	OpReturnOutput      *wire.TxOut
	OpReturnOutputIdx   int
	OpReturnData        *V0OpReturnData
	PayloadOutput       *wire.TxOut
	PayloadOutputIdx    int
	PayloadOpReturnData *PayloadOpReturnData
}

// ParseV0MintingTx takes a btc transaction and checks whether it is a staking transaction and if so parses it
// for easy data retrieval.
// It does all necessary checks to ensure that the transaction is valid staking transaction.
func ParseV0MintingTx(
	tx *wire.MsgTx,
	expectedTag []byte,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	net *chaincfg.Params,
) (*ParsedV0MintingTx, error) {
	// 1. Basic arguments checks
	if tx == nil {
		return nil, fmt.Errorf("nil tx")
	}
	if len(expectedTag) != TagLen {
		return nil, fmt.Errorf("invalid tag length: %d, expected: %d", len(expectedTag), TagLen)
	}
	if len(covenantKeys) == 0 {
		return nil, fmt.Errorf("no covenant keys specified")
	}
	if covenantQuorum > uint32(len(covenantKeys)) {
		return nil, fmt.Errorf("covenant quorum is greater than the number of covenant keys")
	}

	// 2. Identify whether the transaction has expected shape
	if len(tx.TxOut) != 4 {
		return nil, fmt.Errorf("staking tx must have 4 outputs")
	}

	// opReturnData, opReturnOutputIdx, err := tryToGetOpReturnDataFromOutputs(tx.TxOut)

	opReturnData, err := NewV0OpReturnDataFromTxOutput(tx.TxOut[1])

	if err != nil {
		return nil, fmt.Errorf("cannot parse v0 op return staking transaction: %w", err)
	}

	if opReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected v0 op return output")
	}

	PayloadOpReturnData, err := NewPayloadOpReturnDataFromTxOutput(tx.TxOut[2])

	if err != nil {
		return nil, fmt.Errorf("cannot parse payload op return data: %w", err)
	}

	if PayloadOpReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected payload op return output")
	}

	// at this point we know that transaction has op return output which seems to match
	// the expected shape. Check the tag and version.
	if !bytes.Equal(opReturnData.Tag, expectedTag) {
		return nil, fmt.Errorf("unexpected tag: %s, expected: %s",
			hex.EncodeToString(opReturnData.Tag),
			hex.EncodeToString(expectedTag),
		)
	}

	if opReturnData.Version != 0 {
		return nil, fmt.Errorf("unexpcted version: %d, expected: %d", opReturnData.Version, 0)
	}

	// 3. Op return seems to be valid V0 op return output. Now, we need to check whether
	// the staking output exists and is valid.
	mintingInfo, err := BuildMintingInfo(
		opReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{opReturnData.FinalityProviderPublicKey.PubKey},
		covenantKeys,
		covenantQuorum,
		// we can pass 0 here, as staking amount is not used when creating taproot address
		0,
		net,
	)
	if err != nil {
		return nil, fmt.Errorf("cannot build minting info: %w", err)
	}
	// mintingOutput, mintingOutputIdx, err := tryToGetMintingOutput(tx.TxOut, mintingInfo.MintingOutput.PkScript)
	if !bytes.Equal(tx.TxOut[0].PkScript, mintingInfo.MintingOutput.PkScript) {
		return nil, fmt.Errorf("transaction does not have expected minting output with format at index 0")
	}
	mintingOutput := tx.TxOut[0]
	mintingOutputIdx := 0
	if err != nil {
		return nil, fmt.Errorf("cannot parse minting transaction: %w", err)
	}
	if mintingOutput == nil {
		return nil, fmt.Errorf("staking output not found in potential staking transaction")
	}
	return &ParsedV0MintingTx{
		MintingOutput:       mintingOutput,
		MintingOutputIdx:    mintingOutputIdx,
		OpReturnOutput:      tx.TxOut[1],
		OpReturnOutputIdx:   1,
		OpReturnData:        opReturnData,
		PayloadOutput:       tx.TxOut[2],
		PayloadOutputIdx:    2,
		PayloadOpReturnData: PayloadOpReturnData,
	}, nil
}

// IsPossibleV0MintingTx checks whether transaction may be a valid staking transaction
// checks:
// 1. Whether the transaction must have 4 outputs
// 2. have an 2 op return output
// 3. first op return output must the same as IsPossibleV0StakingTx but remove staking time
// 4. second op return output must be a valid payload
// This function is much faster than ParseV0StakingTx, as it does not perform
// all necessary checks.
func IsPossibleV0MintingTx(tx *wire.MsgTx, expectedTag []byte) bool {
	if len(expectedTag) != TagLen {
		return false
	}

	if len(tx.TxOut) != 4 {
		return false
	}

	data, err := getV0OpReturnBytes(tx.TxOut[1])

	if err != nil {
		return false
	}

	if !bytes.Equal(data[:TagLen], expectedTag) {
		// this is not the op return output we are looking for as tag do not match
		return false
	}

	if data[TagLen] != 0 {
		// this is not the v0 op return output
		return false
	}
	data, err = getPayloadOPReturnBytes(tx.TxOut[2])

	if err != nil {
		return false
	}

	return true
}
