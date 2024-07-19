package btcstaking_test

import (
	"math/rand"

	"github.com/modified-babylon/btcstaking"

	"github.com/btcsuite/btcd/wire"

	"github.com/babylonchain/babylon/testutil/datagen"
)

func mintingGenerateTxFromOutputs(r *rand.Rand, info *btcstaking.IdentifiableStakingInfo) (*wire.MsgTx, int, int) {
	numOutputs := r.Int31n(18) + 2

	stakingOutputIdx := int(r.Int31n(numOutputs))
	opReturnOutputIdx := int(datagen.RandomIntOtherThan(r, int(stakingOutputIdx), int(numOutputs)))

	tx := wire.NewMsgTx(2)
	for i := 0; i < int(numOutputs); i++ {
		if i == stakingOutputIdx {
			tx.AddTxOut(info.StakingOutput)
		} else if i == opReturnOutputIdx {
			tx.AddTxOut(info.OpReturnOutput)
		} else {
			tx.AddTxOut(wire.NewTxOut((r.Int63n(1000000000) + 10000), datagen.GenRandomByteArray(r, 32)))
		}
	}

	return tx, stakingOutputIdx, opReturnOutputIdx
}
