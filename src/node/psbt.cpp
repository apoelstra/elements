// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <coins.h>
#include <consensus/tx_verify.h>
#include <node/psbt.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <tinyformat.h>

#include <numeric>

PSBTAnalysis AnalyzePSBT(PartiallySignedTransaction psbtx)
{
    // Go through each input and build status
    PSBTAnalysis result;

    bool calc_fee = true;
    CAmountMap in_amts;

    result.inputs.resize(psbtx.tx->vin.size());

    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInput& input = psbtx.inputs[i];
        PSBTInputAnalysis& input_analysis = result.inputs[i];

        // We set next role here and ratchet backwards as required
        input_analysis.next = PSBTRole::EXTRACTOR;

        // Check for a UTXO
        CTxOut utxo;
        if (psbtx.GetInputUTXO(utxo, i)) {
            //TODO(gwillen) do PSBT inputs always have explicit assets & amounts?
            if (!MoneyRange(utxo.nValue.GetAmount()) || !MoneyRange(in_amts[utxo.nAsset.GetAsset()] + utxo.nValue.GetAmount())) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u has invalid value", i));
                return result;
            }
            in_amts[utxo.nAsset.GetAsset()] += utxo.nValue.GetAmount();
            input_analysis.has_utxo = true;
        } else {
            if (input.non_witness_utxo && psbtx.tx->vin[i].prevout.n >= input.non_witness_utxo->vout.size()) {
                result.SetInvalid(strprintf("PSBT is not valid. Input %u specifies invalid prevout", i));
                return result;
            }
            input_analysis.has_utxo = false;
            input_analysis.is_final = false;
            input_analysis.next = PSBTRole::UPDATER;
            calc_fee = false;
        }

        if (!utxo.IsNull() && utxo.scriptPubKey.IsUnspendable()) {
            result.SetInvalid(strprintf("PSBT is not valid. Input %u spends unspendable output", i));
            return result;
        }

        // Check if it is final
        if (!utxo.IsNull() && !PSBTInputSigned(input)) {
            input_analysis.is_final = false;

            // Figure out what is missing
            SignatureData outdata;
            bool complete = SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, 1, &outdata);

            // Things are missing
            if (!complete) {
                input_analysis.missing_pubkeys = outdata.missing_pubkeys;
                input_analysis.missing_redeem_script = outdata.missing_redeem_script;
                input_analysis.missing_witness_script = outdata.missing_witness_script;
                input_analysis.missing_sigs = outdata.missing_sigs;

                // If we are only missing signatures and nothing else, then next is signer
                if (outdata.missing_pubkeys.empty() && outdata.missing_redeem_script.IsNull() && outdata.missing_witness_script.IsNull() && !outdata.missing_sigs.empty()) {
                    input_analysis.next = PSBTRole::SIGNER;
                } else {
                    input_analysis.next = PSBTRole::UPDATER;
                }
            } else {
                input_analysis.next = PSBTRole::FINALIZER;
            }
        } else if (!utxo.IsNull()){
            input_analysis.is_final = true;
        }
    }

    // Calculate next role for PSBT by grabbing "minimum" PSBTInput next role
    result.next = PSBTRole::EXTRACTOR;
    for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
        PSBTInputAnalysis& input_analysis = result.inputs[i];
        result.next = std::min(result.next, input_analysis.next);
    }
    assert(result.next > PSBTRole::CREATOR);

    if (calc_fee) {
        // Get the output amount
        CAmountMap out_amts = std::accumulate(psbtx.tx->vout.begin(), psbtx.tx->vout.end(), CAmountMap(),
            [](CAmountMap a, const CTxOut& b) {
                CAmount acc = a[b.nAsset.GetAsset()];
                CAmount add = b.nValue.GetAmount();

                if (!MoneyRange(acc) || !MoneyRange(add) || !MoneyRange(acc + add)) {
                    CAmountMap invalid;
                    invalid[::policyAsset] = CAmount(-1);
                    return invalid;
                }
                a[b.nAsset.GetAsset()] += add;
                return a;
            }
        );
        if (!MoneyRange(out_amts)) {
            result.SetInvalid(strprintf("PSBT is not valid. Output amount invalid"));
            return result;
        }

        // Get the fee
        CAmountMap fee = in_amts - out_amts;
        result.fee = fee;

        // Estimate the size
        CMutableTransaction mtx(*psbtx.tx);
        CCoinsView view_dummy;
        CCoinsViewCache view(&view_dummy);
        bool success = true;

        for (unsigned int i = 0; i < psbtx.tx->vin.size(); ++i) {
            PSBTInput& input = psbtx.inputs[i];
            Coin newcoin;

            if (!SignPSBTInput(DUMMY_SIGNING_PROVIDER, psbtx, i, 1, nullptr, true) || !psbtx.GetInputUTXO(newcoin.out, i)) {
                success = false;
                break;
            } else {
                mtx.vin[i].scriptSig = input.final_script_sig;
                mtx.witness.vtxinwit[i].scriptWitness = input.final_script_witness;
                newcoin.nHeight = 1;
                view.AddCoin(psbtx.tx->vin[i].prevout, std::move(newcoin), true);
            }
        }

        if (success) {
            CTransaction ctx = CTransaction(mtx);
            size_t size = GetVirtualTransactionSize(ctx, GetTransactionSigOpCost(ctx, view, STANDARD_SCRIPT_VERIFY_FLAGS));
            result.estimated_vsize = size;
            // Estimate fee rate
            CFeeRate feerate(fee[::policyAsset], size);
            result.estimated_feerate = feerate;
        }

    }

    return result;
}

