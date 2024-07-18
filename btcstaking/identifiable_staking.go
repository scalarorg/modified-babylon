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
	// length of tag prefix indentifying staking transactions
	TagLen = 4
	// 4 bytes tag + 1 byte version + 32 bytes staker public key + 32 bytes finality provider public key + 2 bytes staking time
	V0OpReturnDataSize = 71

	v0OpReturnCreationErrMsg = "cannot create V0 op_return data"

	PayloadOpReturnDataSize          = 80
	chainIdBytes                     = 8
	ChainIdUserAddressBytes          = 20
	ChainIdSmartContractAddressBytes = 20
	AmountBytes                      = 32
)

type IdentifiableStakingInfo struct {
	StakingOutput         *wire.TxOut
	scriptHolder          *taprootScriptHolder
	timeLockPathLeafHash  chainhash.Hash
	unbondingPathLeafHash chainhash.Hash
	slashingPathLeafHash  chainhash.Hash
	OpReturnOutput        *wire.TxOut
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

func (d *V0OpReturnData) Marshall() []byte {
	var data []byte
	data = append(data, d.Tag...)
	data = append(data, d.Version)
	data = append(data, d.StakerPublicKey.Marshall()...)
	data = append(data, d.FinalityProviderPublicKey.Marshall()...)
	data = append(data, uint16ToBytes(d.StakingTime)...)
	return data
}

func (d *V0OpReturnData) ToTxOutput() (*wire.TxOut, error) {
	dataScript, err := txscript.NullDataScript(d.Marshall())
	if err != nil {
		return nil, err
	}
	return wire.NewTxOut(0, dataScript), nil
}

// BuildV0IdentifiableStakingOutputs creates outputs which every staking transaction must have
func BuildV0IdentifiableStakingOutputs(
	tag []byte,
	stakerKey *btcec.PublicKey,
	fpKey *btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	stakingTime uint16,
	stakingAmount btcutil.Amount,
	net *chaincfg.Params,
) (*IdentifiableStakingInfo, error) {
	info, err := BuildMintingInfo(
		stakerKey,
		[]*btcec.PublicKey{fpKey},
		covenantKeys,
		covenantQuorum,
		stakingTime,
		stakingAmount,
		net,
	)
	if err != nil {
		return nil, err
	}

	opReturnData, err := NewV0OpReturnDataFromParsed(tag, stakerKey, fpKey, stakingTime)

	if err != nil {
		return nil, err
	}

	dataOutput, err := opReturnData.ToTxOutput()

	if err != nil {
		return nil, err
	}

	return &IdentifiableStakingInfo{
		StakingOutput:         info.StakingOutput,
		scriptHolder:          info.scriptHolder,
		timeLockPathLeafHash:  info.timeLockPathLeafHash,
		unbondingPathLeafHash: info.unbondingPathLeafHash,
		slashingPathLeafHash:  info.slashingPathLeafHash,
		OpReturnOutput:        dataOutput,
	}, nil
}

// BuildV0IdentifiableStakingOutputsAndTx creates outputs which every staking transaction must have and
// returns the not-funded transaction with these outputs
func BuildV0IdentifiableStakingOutputsAndTx(
	tag []byte,
	stakerKey *btcec.PublicKey,
	fpKey *btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	stakingTime uint16,
	stakingAmount btcutil.Amount,
	net *chaincfg.Params,
) (*IdentifiableStakingInfo, *wire.MsgTx, error) {
	info, err := BuildV0IdentifiableStakingOutputs(
		tag,
		stakerKey,
		fpKey,
		covenantKeys,
		covenantQuorum,
		stakingTime,
		stakingAmount,
		net,
	)
	if err != nil {
		return nil, nil, err
	}

	tx := wire.NewMsgTx(2)
	tx.AddTxOut(info.StakingOutput)
	tx.AddTxOut(info.OpReturnOutput)
	return info, tx, nil
}

func (i *IdentifiableStakingInfo) TimeLockPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.timeLockPathLeafHash)
}

func (i *IdentifiableStakingInfo) UnbondingPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.unbondingPathLeafHash)
}

func (i *IdentifiableStakingInfo) SlashingPathSpendInfo() (*SpendInfo, error) {
	return i.scriptHolder.scriptSpendInfoByName(i.slashingPathLeafHash)
}

type ParsedV0StakingTx struct {
	StakingOutput     *wire.TxOut
	StakingOutputIdx  int
	OpReturnOutput    *wire.TxOut
	OpReturnOutputIdx int
	OpReturnData      *V0OpReturnData
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

func tryToGetStakingOutput(outputs []*wire.TxOut, stakingOutputPkScript []byte) (*wire.TxOut, int, error) {
	// lack of outputs is not an error
	if len(outputs) == 0 {
		return nil, -1, nil
	}

	var stakingOutput *wire.TxOut
	var stakingOutputIdx int

	for i, o := range outputs {
		output := o

		if !bytes.Equal(output.PkScript, stakingOutputPkScript) {
			// this is not the staking output we are looking for
			continue
		}

		if stakingOutput != nil {
			// we only allow for one staking output per transaction
			return nil, -1, fmt.Errorf("multiple staking outputs found")
		}

		stakingOutput = output
		stakingOutputIdx = i
	}

	return stakingOutput, stakingOutputIdx, nil
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
) (*ParsedV0StakingTx, error) {
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
		return nil, fmt.Errorf("staking tx must have at least 3 outputs")
	}

	// opReturnData, opReturnOutputIdx, err := tryToGetOpReturnDataFromOutputs(tx.TxOut)

	V0OpReturnData, err := NewV0OpReturnDataFromTxOutput(tx.TxOut[1])
	PayloadOpReturnData, err := NewPayloadOpReturnDataFromTxOutput(tx.TxOut[2])

	if err != nil {
		return nil, fmt.Errorf("cannot parse staking transaction: %w", err)
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
	// the staking output exists and is valid.
	stakingInfo, err := BuildMintingInfo(
		V0OpReturnData.StakerPublicKey.PubKey,
		[]*btcec.PublicKey{V0OpReturnData.dAppPublicKey.PubKey},
		covenantKeys,
		covenantQuorum,
		// we can pass 0 here, as staking amount is not used when creating taproot address
		0,
		net,
	)

	if err != nil {
		return nil, fmt.Errorf("cannot build staking info: %w", err)
	}

	stakingOutput, stakingOutputIdx, err := tryToGetStakingOutput(tx.TxOut, stakingInfo.StakingOutput.PkScript)

	if err != nil {
		return nil, fmt.Errorf("cannot parse staking transaction: %w", err)
	}

	if stakingOutput == nil {
		return nil, fmt.Errorf("staking output not found in potential staking transaction")
	}

	return &ParsedV0StakingTx{
		StakingOutput:     stakingOutput,
		StakingOutputIdx:  stakingOutputIdx,
		OpReturnOutput:    tx.TxOut[opReturnOutputIdx],
		OpReturnOutputIdx: opReturnOutputIdx,
		OpReturnData:      opReturnData,
	}, nil
}

// IsPossibleV0MintingTx checks whether transaction may be a valid staking transaction
// checks:
// 1. Whether the transaction has at least 3 outputs
// 2. have an op return output at index 1,2
// 3. op_return at index 1 have 69 bytes
// 4. op_return at index 2 have 80 bytes
// This function is much faster than ParseV0StakingTx, as it does not perform
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
