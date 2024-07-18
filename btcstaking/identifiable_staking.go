package btcstaking

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	// length of tag prefix indentifying minting transactions
	TagLen = 4
	// 4 bytes tag + 1 byte version + 32 bytes staker public key + 32 bytes finality provider public key + 2 bytes minting time
	V0OpReturnDataSize = 71

	v0OpReturnCreationErrMsg = "cannot create V0 op_return data"

	PayloadOpReturnDataSize          = 80
	chainIdBytes                     = 8
	ChainIdUserAddressBytes          = 20
	ChainIdSmartContractAddressBytes = 20
	AmountBytes                      = 32
)

type IdentifiableMintingInfo struct {
	MintingOutput                 *wire.TxOut
	scriptHolder                  *taprootScriptHolder
	burnPathLeafHash              chainhash.Hash
	slashingOrLostKeyPathLeafHash chainhash.Hash
	burnWithoutDAppPathLeafHash   chainhash.Hash
	V0OpReturnOutput              *wire.TxOut
	PayloadOpReturnOutput         *wire.TxOut
}

func uint16ToBytes(v uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return buf[:]
}

func uint16FromBytes(b []byte) (uint16, error) {
	if len(b) != 2 {
		return 0, fmt.Errorf("invalid uint16 bytes length: %d", len(b))
	}

	return binary.BigEndian.Uint16(b), nil
}

// V0OpReturnData represents the data that is embedded in the OP_RETURN output
// It marshalls to exactly 71 bytes
type V0OpReturnData struct {
	Tag             []byte
	Version         byte
	StakerPublicKey *XonlyPubKey
	dAppPublicKey   *XonlyPubKey
}

type PayloadOpReturnData struct {
	ChainID                     []byte
	ChainIdUserAddress          []byte
	ChainIdSmartContractAddress []byte
	Amount                      uint32
}

func NewV0OpReturnData(
	tag []byte,
	stakerPublicKey []byte,
	dAppPublicKey []byte,
) (*V0OpReturnData, error) {
	if len(tag) != TagLen {
		return nil, fmt.Errorf("%s:invalid tag length: %d, expected: %d", v0OpReturnCreationErrMsg, len(tag), TagLen)
	}

	stakerKey, err := XOnlyPublicKeyFromBytes(stakerPublicKey)

	if err != nil {
		return nil, fmt.Errorf("%s:invalid staker public key:%w", v0OpReturnCreationErrMsg, err)
	}

	fpKey, err := XOnlyPublicKeyFromBytes(dAppPublicKey)

	if err != nil {
		return nil, fmt.Errorf("%s:invalid dApp public key:%w", v0OpReturnCreationErrMsg, err)
	}

	return NewV0OpReturnDataFromParsed(tag, stakerKey.PubKey, fpKey.PubKey)
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

func NewV0OpReturnDataFromParsed(
	tag []byte,
	stakerPublicKey *btcec.PublicKey,
	dAppPublicKey *btcec.PublicKey,
) (*V0OpReturnData, error) {
	if len(tag) != TagLen {
		return nil, fmt.Errorf("%s:invalid tag length: %d, expected: %d", v0OpReturnCreationErrMsg, len(tag), TagLen)
	}

	if stakerPublicKey == nil {
		return nil, fmt.Errorf("%s:nil staker public key", v0OpReturnCreationErrMsg)
	}

	if dAppPublicKey == nil {
		return nil, fmt.Errorf("%s: nil dApp public key", v0OpReturnCreationErrMsg)
	}

	return &V0OpReturnData{
		Tag:             tag,
		Version:         0,
		StakerPublicKey: &XonlyPubKey{stakerPublicKey},
		dAppPublicKey:   &XonlyPubKey{dAppPublicKey},
	}, nil
}

func NewPayloadOpReturnDataFromParsed(
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	Amount uint32,
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
	return &PayloadOpReturnData{
		ChainID:                     chainID,
		ChainIdUserAddress:          chainIdUserAddress,
		ChainIdSmartContractAddress: chainIdSmartContractAddress,
		Amount:                      Amount,
	}, nil
}

func NewV0OpReturnDataFromBytes(b []byte) (*V0OpReturnData, error) {
	if len(b) != V0OpReturnDataSize {
		return nil, fmt.Errorf("invalid v0 op return data length: %d, expected: %d", len(b), V0OpReturnDataSize)
	}
	tag := b[:TagLen]

	version := b[TagLen]

	if version != 0 {
		return nil, fmt.Errorf("invalid op return version: %d, expected: %d", version, 0)
	}

	stakerPublicKey := b[TagLen+1 : TagLen+1+schnorr.PubKeyBytesLen]
	dAppPublicKey := b[TagLen+1+schnorr.PubKeyBytesLen:]
	return NewV0OpReturnData(tag, stakerPublicKey, dAppPublicKey)
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

func getV0OpReturnBytes(out *wire.TxOut) ([]byte, error) {
	if out == nil {
		return nil, fmt.Errorf("nil tx output")
	}

	// We are adding `+2` as each op return has additional 2 for:
	// 1. OP_RETURN opcode - which signalizes that data is provably unspendable
	// 2. OP_DATA_71 opcode - which pushes 71 bytes of data to the stack
	if len(out.PkScript) != V0OpReturnDataSize+2 {
		return nil, fmt.Errorf("invalid op return data length: %d, expected: %d", len(out.PkScript), V0OpReturnDataSize+2)
	}

	if !txscript.IsNullData(out.PkScript) {
		return nil, fmt.Errorf("invalid op return script")
	}

	return out.PkScript[2:], nil
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

func NewV0OpReturnDataFromTxOutput(out *wire.TxOut) (*V0OpReturnData, error) {
	data, err := getV0OpReturnBytes(out)

	if err != nil {
		return nil, fmt.Errorf("cannot parse v0 op return data: %w", err)
	}

	return NewV0OpReturnDataFromBytes(data)
}

func NewPayloadOpReturnDataFromTxOutput(out *wire.TxOut) (*PayloadOpReturnData, error) {
	data, err := getPayloadOPReturnBytes(out)

	if err != nil {
		return nil, fmt.Errorf("cannot parse payload op return data: %w", err)
	}

	return NewPayloadOpReturnDataFromBytes(data)
}

func (d *V0OpReturnData) V0Marshall() []byte {
	var data []byte
	data = append(data, d.Tag...)
	data = append(data, d.Version)
	data = append(data, d.StakerPublicKey.Marshall()...)
	data = append(data, d.dAppPublicKey.Marshall()...)
	return data
}

func (d *PayloadOpReturnData) PayloadMarshall() []byte {
	var data []byte
	data = append(data, d.ChainID...)
	data = append(data, d.ChainIdUserAddress...)
	data = append(data, d.ChainIdSmartContractAddress...)
	amount := make([]byte, 8)
	binary.BigEndian.PutUint32(amount, d.Amount)
	data = append(data, amount...)
	return data
}

func (d *V0OpReturnData) V0DataToTxOutput() (*wire.TxOut, error) {
	dataScript, err := txscript.NullDataScript(d.V0Marshall())
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(0, dataScript), nil
}

func (d *PayloadOpReturnData) PayloadDataToTxOutput() (*wire.TxOut, error) {
	dataScript, err := txscript.NullDataScript(d.PayloadMarshall())
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(0, dataScript), nil
}

// BuildV0IdentifiableMintingOutputs creates outputs which every minting transaction must have
func BuildV0IdentifiableMintingOutputs(
	tag []byte,
	stakerKey *btcec.PublicKey,
	dAppKey *btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	amount btcutil.Amount,
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	mintingAmount uint32,
	net *chaincfg.Params,
) (*IdentifiableMintingInfo, error) {
	info, err := BuildMintingInfo(
		stakerKey,
		[]*btcec.PublicKey{dAppKey},
		covenantKeys,
		covenantQuorum,
		amount,
		net,
	)
	if err != nil {
		return nil, err
	}

	V0OpReturnData, err := NewV0OpReturnDataFromParsed(tag, stakerKey, dAppKey)

	if err != nil {
		return nil, err
	}

	V0DataOutput, err := V0OpReturnData.V0DataToTxOutput()

	if err != nil {
		return nil, err
	}

	PayloadOpReturnData, err := NewPayloadOpReturnDataFromParsed(chainID, chainIdUserAddress, chainIdSmartContractAddress, mintingAmount)

	if err != nil {
		return nil, err
	}

	PayloadDataOutput, err := PayloadOpReturnData.PayloadDataToTxOutput()

	if err != nil {
		return nil, err
	}

	return &IdentifiableMintingInfo{
		MintingOutput:                 info.MintingOutput,
		scriptHolder:                  info.scriptHolder,
		burnPathLeafHash:              info.burnPathLeafHash,
		slashingOrLostKeyPathLeafHash: info.slashingOrLostKeyPathLeafHash,
		burnWithoutDAppPathLeafHash:   info.burnWithoutDAppPathLeafHash,
		V0OpReturnOutput:              V0DataOutput,
		PayloadOpReturnOutput:         PayloadDataOutput,
	}, nil
}

// BuildV0IdentifiableMintingOutputsAndTx creates outputs which every minting transaction must have and
// returns the not-funded transaction with these outputs
func BuildV0IdentifiableMintingOutputsAndTx(
	tag []byte,
	stakerKey *btcec.PublicKey,
	fpKey *btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	amount btcutil.Amount,
	chainID []byte,
	chainIdUserAddress []byte,
	chainIdSmartContractAddress []byte,
	mintingAmount uint32,
	net *chaincfg.Params,
) (*IdentifiableMintingInfo, *wire.MsgTx, error) {
	info, err := BuildV0IdentifiableMintingOutputs(
		tag,
		stakerKey,
		fpKey,
		covenantKeys,
		covenantQuorum,
		amount,
		chainID,
		chainIdUserAddress,
		chainIdSmartContractAddress,
		mintingAmount,
		net,
	)
	if err != nil {
		return nil, nil, err
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(info.MintingOutput)
	tx.AddTxOut(info.V0OpReturnOutput)
	tx.AddTxOut(info.PayloadOpReturnOutput)
	return info, tx, nil
}

func (i *IdentifiableMintingInfo) BurnPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burnPathLeafHash)
}

func (i *IdentifiableMintingInfo) slashingOrLostKeyPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.slashingOrLostKeyPathLeafHash)
}

func (i *IdentifiableMintingInfo) burnWithoutDAppPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.burnWithoutDAppPathLeafHash)
}

type ParsedV0MintingTx struct {
	MintingOutput            *wire.TxOut
	MintingOutputIdx         int
	V0OpReturnOutput         *wire.TxOut
	V0OpReturnOutputIdx      int
	V0OpReturnData           *V0OpReturnData
	PayloadOpReturnOutput    *wire.TxOut
	PayloadOpReturnOutputIdx int
	PayloadOpReturnData      *PayloadOpReturnData
}

func tryToGetOpReturnDataFromOutputs(outputs []*wire.TxOut) (*V0OpReturnData, int, error) {
	// lack of outputs is not an error
	if len(outputs) == 0 {
		return nil, -1, nil
	}

	var opReturnData *V0OpReturnData
	var opReturnOutputIdx int

	for i, o := range outputs {
		output := o
		d, err := NewV0OpReturnDataFromTxOutput(output)

		if err != nil {
			// this is not an op return output recognized by Babylon, move forward
			continue
		}
		// this case should not happen as standard bitcoin node propagation rules
		// disallow multiple op return outputs in a single transaction. However, miner could
		// include multiple op return outputs in a single transaction. In such case, we should
		// return an error.
		if opReturnData != nil {
			return nil, -1, fmt.Errorf("multiple op return outputs found")
		}

		opReturnData = d
		opReturnOutputIdx = i
	}

	return opReturnData, opReturnOutputIdx, nil
}

func tryToGetMintingOutput(outputs []*wire.TxOut, mintingOutputPkScript []byte) (*wire.TxOut, int, error) {
	// lack of outputs is not an error
	if len(outputs) == 0 {
		return nil, -1, nil
	}

	var mintingOutput *wire.TxOut
	var mintingOutputIdx int

	for i, o := range outputs {
		output := o

		if !bytes.Equal(output.PkScript, mintingOutputPkScript) {
			// this is not the minting output we are looking for
			continue
		}

		if mintingOutput != nil {
			// we only allow for one minting output per transaction
			return nil, -1, fmt.Errorf("multiple minting outputs found")
		}

		mintingOutput = output
		mintingOutputIdx = i
	}

	return mintingOutput, mintingOutputIdx, nil
}

// ParseV0MintingTx takes a btc transaction and checks whether it is a minting transaction and if so parses it
// for easy data retrieval.
// It does all necessary checks to ensure that the transaction is valid minting transaction.
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
	if len(tx.TxOut) < 3 {
		return nil, fmt.Errorf("minting tx must have at least 3 outputs")
	}

	// opReturnData, opReturnOutputIdx, err := tryToGetOpReturnDataFromOutputs(tx.TxOut)

	V0OpReturnData, err := NewV0OpReturnDataFromTxOutput(tx.TxOut[1])
	PayloadOpReturnData, err := NewPayloadOpReturnDataFromTxOutput(tx.TxOut[2])

	if err != nil {
		return nil, fmt.Errorf("cannot parse minting transaction: %w", err)
	}

	if V0OpReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected v0 op return output")
	}

	if PayloadOpReturnData == nil {
		return nil, fmt.Errorf("transaction does not have expected payload op return output")
	}

	// at this point we know that transaction has op return output which seems to match
	// the expected shape. Check the tag and version.
	if !bytes.Equal(V0OpReturnData.Tag, expectedTag) {
		return nil, fmt.Errorf("unexpected tag: %s, expected: %s",
			hex.EncodeToString(V0OpReturnData.Tag),
			hex.EncodeToString(expectedTag),
		)
	}

	if V0OpReturnData.Version != 0 {
		return nil, fmt.Errorf("unexpcted version: %d, expected: %d", V0OpReturnData.Version, 0)
	}

	// 3. Op return seems to be valid V0 op return output. Now, we need to check whether
	// the minting output exists and is valid.
	mintingInfo, err := BuildMintingInfo(
		V0OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{V0OpReturnData.dAppPublicKey.PubKey},
		covenantKeys,
		covenantQuorum,
		// we can pass 0 here, as minting amount is not used when creating taproot address
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

	return &ParsedV0MintingTx{
		MintingOutput:            mintingOutput,
		MintingOutputIdx:         mintingOutputIdx,
		V0OpReturnOutput:         tx.TxOut[1],
		V0OpReturnOutputIdx:      1,
		V0OpReturnData:           V0OpReturnData,
		PayloadOpReturnOutput:    tx.TxOut[2],
		PayloadOpReturnOutputIdx: 2,
		PayloadOpReturnData:      PayloadOpReturnData,
	}, nil
}

// IsPossibleV0MintingTx checks whether transaction may be a valid minting transaction
// checks:
// 1. Whether the transaction has at least 3 outputs
// 2. have an op return output at index 1,2
// 3. op_return at index 1 have tag and version
// 4. op_return at index 2 have 80 bytes
// This function is much faster than ParseV0MintingTx, as it does not perform
// all necessary checks.
func IsPossibleV0MintingTx(tx *wire.MsgTx, expectedTag []byte) bool {
	if len(expectedTag) != TagLen {
		return false
	}

	if len(tx.TxOut) < 3 {
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
