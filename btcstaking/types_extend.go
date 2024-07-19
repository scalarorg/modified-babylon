package btcstaking

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

var (
	errBuildingMintingInfo = fmt.Errorf("error building minting info")
)

type scalarScriptPaths struct {
	// burnPathScript is the script path for normal burning
	// <Minter_PK> OP_CHECKSIGVERIFY
	// <dApp_PK> OP_CHECKSIGVERIFY
	// <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_NUMEQUAL
	burnPathScript []byte
	// slashingOrLostKeyPathScript is the script path for slashing or minter lost key
	// <Minter_PK> OP_CHECKSIGVERIFY
	// <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_GREATERTHANOREQUAL
	slashingOrLostKeyPathScript []byte
	// burnWithoutDAppPathScript is the script path for burning without dApp
	// <Minter_PK> OP_CHECKSIGVERIFY
	// <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_GREATERTHANOREQUAL
	burnWithoutDAppPathScript []byte
}

func newScalarScriptPaths(
	stakerKey *btcec.PublicKey,
	fpKeys []*btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
) (*scalarScriptPaths, error) {
	if stakerKey == nil {
		return nil, fmt.Errorf("staker key is nil")
	}

	if err := checkForDuplicateKeys(stakerKey, fpKeys, covenantKeys); err != nil {
		return nil, fmt.Errorf("error building scripts: %w", err)
	}

	covenantMultisigScript, err := buildMultiSigScript(
		covenantKeys,
		covenantQuorum,
		// covenant multisig is always last in script so we do not run verify and leave
		// last value on the stack. If we do not leave at least one element on the stack
		// script will always error
		false,
	)

	if err != nil {
		return nil, err
	}

	stakerSigScript, err := buildSingleKeySigScript(stakerKey, true)

	if err != nil {
		return nil, err
	}

	fpMultisigScript, err := buildMultiSigScript(
		fpKeys,
		// we always require only one dApp provider to sign
		1,
		// we need to run verify to clear the stack, as finality provider multisig is in the middle of the script
		true,
	)

	if err != nil {
		return nil, err
	}

	burningPathScript := aggregateScripts(
		stakerSigScript,
		fpMultisigScript,
		covenantMultisigScript,
	)

	slashingOrLostKeyPathScript := aggregateScripts(
		fpMultisigScript,
		covenantMultisigScript,
	)

	burningWithoutDAppPathScript := aggregateScripts(
		stakerSigScript,
		covenantMultisigScript,
	)

	return &scalarScriptPaths{
		burnPathScript:              burningPathScript,
		slashingOrLostKeyPathScript: slashingOrLostKeyPathScript,
		burnWithoutDAppPathScript:   burningWithoutDAppPathScript,
	}, nil
}

type MintingInfo struct {
	MintingOutput                 *wire.TxOut
	scriptHolder                  *taprootScriptHolder
	burnPathLeafHash              chainhash.Hash
	slashingOrLostKeyPathLeafHash chainhash.Hash
	burnWithoutDAppPathLeafHash   chainhash.Hash
}

func BuildMintingInfo(
	stakerKey *btcec.PublicKey,
	fpKeys []*btcec.PublicKey,
	covenantKeys []*btcec.PublicKey,
	covenantQuorum uint32,
	stakingAmount btcutil.Amount,
	net *chaincfg.Params,
) (*MintingInfo, error) {
	unspendableKeyPathKey := unspendableKeyPathInternalPubKey()

	scalarScripts, err := newScalarScriptPaths(
		stakerKey,
		fpKeys,
		covenantKeys,
		covenantQuorum,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingMintingInfo, err)
	}

	var unbondingPaths [][]byte
	unbondingPaths = append(unbondingPaths, scalarScripts.burnPathScript)
	unbondingPaths = append(unbondingPaths, scalarScripts.slashingOrLostKeyPathScript)
	unbondingPaths = append(unbondingPaths, scalarScripts.burnWithoutDAppPathScript)

	burnPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.burnPathScript).TapHash()
	slashingOrLostKeyPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.slashingOrLostKeyPathScript).TapHash()
	burnWithoutDAppPathLeafHash := txscript.NewBaseTapLeaf(scalarScripts.burnWithoutDAppPathScript).TapHash()

	sh, err := newTaprootScriptHolder(
		&unspendableKeyPathKey,
		unbondingPaths,
	)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingMintingInfo, err)
	}

	taprootPkScript, err := sh.taprootPkScript(net)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", errBuildingMintingInfo, err)
	}

	stakingOutput := wire.NewTxOut(int64(stakingAmount), taprootPkScript)

	return &MintingInfo{
		MintingOutput:                 stakingOutput,
		scriptHolder:                  sh,
		burnPathLeafHash:              burnPathLeafHash,
		slashingOrLostKeyPathLeafHash: slashingOrLostKeyPathLeafHash,
		burnWithoutDAppPathLeafHash:   burnWithoutDAppPathLeafHash,
	}, nil
}
