// Copyright (c) 2022 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>

#include <issuance.h>
#include <primitives/transaction.h>
#include <wallet/blind.h>
#include <wallet/coinselection.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

namespace Blinding {

/** Helper for computing a rangeproof size from an output type */
static size_t rangeproof_size(RangeproofType ty) {
    switch (ty) {
    case RangeproofType::NO_RANGEPROOF: return 0;
    case RangeproofType::RANGEPROOF_FULL:
        return secp256k1_rangeproof_max_size(secp256k1_blind_context, MAX_MONEY, gArgs.GetArg("-ct_bits", 52));
    case RangeproofType::RANGEPROOF_MINIMAL:
        return secp256k1_rangeproof_max_size(secp256k1_blind_context, 0, 3);
    case RangeproofType::RANGEPROOF_SINGLE:
        return 73; // FIXME don't hardcode this
    }
    assert(0);
    return 0;
}

static size_t surjectionproof_size(size_t n_inputs) {
    // FIXME move this into libsecp-zkp
    return 2 + 32 * (1 + std::min(n_inputs, (size_t) 3)) + (n_inputs + 7) / 8;
}

void TxData::PushDummyOutput() {
    CTxOut txout(policyAsset, 0, CScript() << OP_RETURN);
    OutputData output_data = {
        .blinding_key = CPubKey(),
        .blind_amount = RangeproofType::RANGEPROOF_SINGLE,
        .blind_asset = false,
        .ty = OutputType::OUTPUT_DUMMY,
    };

    m_tx.vout.emplace_back(txout);
    m_output_data.emplace_back(output_data);
}

void TxData::MaybePushDummyOutput() {
    size_t blind_count = 0;
    for (const auto& outdata : m_output_data) {
        if (outdata.ty == OutputType::OUTPUT_DUMMY) {
            // If we already have a dummy don't add another one.
            return;
        }
        if (outdata.blind_amount != RangeproofType::NO_RANGEPROOF) {
            blind_count++; 
        }
        if (outdata.blind_asset) {
            blind_count++; 
        }
    }
    for (const auto& asset_txout_data : m_change_data) {
        if (asset_txout_data.second.second.blind_amount != RangeproofType::NO_RANGEPROOF) {
            blind_count++; 
        }
        if (asset_txout_data.second.second.blind_asset) {
            blind_count++; 
        }
    }
    // If we think we'll have no blinding factors on the output side, push a
    // dummy in case we have blinded inputs and need to balance them.
    // If we think we'll have just *one* blinding factor on the output side,
    // also push a dummy, in case we have no blinded inputs but need to balance
    // the sole other output bf.
    if (blind_count < 2) {
        PushDummyOutput();
    }
}

void TxData::PushFeeOutput() {
std::cout << "PUshing a fee output" << std::endl;
    CTxOut txout(policyAsset, 0, CScript());
    OutputData output_data = {
        .blinding_key = CPubKey(),
        .blind_amount = RangeproofType::NO_RANGEPROOF,
        .blind_asset = false,
        .ty = OutputType::OUTPUT_FEE,
    };

    m_tx.vout.emplace_back(txout);
    m_output_data.emplace_back(output_data);
}

void TxData::PushRecipientOutput(const CRecipient& recipient) {
    CTxOut txout(recipient.asset, recipient.nAmount, recipient.scriptPubKey);

    bool should_blind = recipient.confidentiality_key.IsFullyValid();
    OutputData output_data = {
        .blinding_key = recipient.confidentiality_key,
        .blind_amount = should_blind ? RangeproofType::RANGEPROOF_FULL : RangeproofType::NO_RANGEPROOF,
        .blind_asset = should_blind,
        .ty = OutputType::OUTPUT_RECIPIENT,
    };

    m_tx.vout.emplace_back(txout);
    m_output_data.emplace_back(output_data);
}

void TxData::PushChangeOutput(const CAsset asset, CAmount amount, const CScript& script, const std::optional<CPubKey> blinding_key) {
    CTxOut txout(CAsset(), 0, script);

    OutputData output_data;
    if (blinding_key) {
        output_data = {
            .blinding_key = *blinding_key,
            .blind_amount = RangeproofType::RANGEPROOF_FULL,
            .blind_asset = true,
            .ty = asset == policyAsset ? OutputType::OUTPUT_CHANGE_POLICY : OutputType::OUTPUT_CHANGE_NONPOLICY,
        };
        txout.nAsset.vchCommitment.resize(33);
        txout.nValue.vchCommitment.resize(33);
        txout.nNonce.vchCommitment.resize(33);
    } else {
        output_data = {
            .blinding_key = CPubKey(),
            .blind_amount = RangeproofType::NO_RANGEPROOF,
            .blind_asset = false,
            .ty = asset == policyAsset ? OutputType::OUTPUT_CHANGE_POLICY : OutputType::OUTPUT_CHANGE_NONPOLICY,
        };
        txout.nAsset.vchCommitment.resize(33);
        txout.nValue.vchCommitment.resize(9);
        txout.nNonce.vchCommitment.clear();
    }

    m_change_data[asset] = std::pair(txout, output_data);
}

static size_t output_weight(const CTxOut& txout, const OutputData& output_data) {
    size_t weight = 0;
    if (output_data.ty != OutputType::OUTPUT_RECIPIENT) {
        // non-CT weight of recipient outputs is already accounted for in CreateTransactionInternal
        weight += ::GetSerializeSize(txout, PROTOCOL_VERSION) * WITNESS_SCALE_FACTOR;
    }

    weight += 1 + rangeproof_size(output_data.blind_amount);
    if (output_data.blind_asset) {
        weight += DEFAULT_SURJECTIONPROOF_SIZE;
    }
    return weight;
}

void TxData::AdjustCoinSelectionParameters(CoinSelectionParams& coin_selection_params) {
    // Early return: if we're not in Elements mode we not only have no blinding,
    //  but we also have no asset/nonce in outputs, no fee outputs, etc., so there
    //  is nothing to adjust.
    if (!g_con_elementsmode) {
        return;
    }

    // Early return: if we are in "subtract fee from output" mode, we basically
    //  don't set the coin selection parameters. (This is true in Core as well.)
    if (coin_selection_params.m_subtract_fee_outputs) {
        return;
    }

    MaybePushDummyOutput();
    PushFeeOutput();

    // Weight for each output
    assert(m_output_data.size() == m_tx.vout.size());
    for (unsigned int i = 0; i < m_output_data.size(); i++) {
        size_t weight = output_weight(m_tx.vout[i], m_output_data[i]);
        coin_selection_params.tx_noinputs_size += (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
    }
    for (const auto& it : m_change_data) {
        size_t weight = output_weight(it.second.first, it.second.second);
        if (it.second.second.ty == OutputType::OUTPUT_CHANGE_POLICY) {
            coin_selection_params.change_output_size = (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
        } else {
            coin_selection_params.tx_noinputs_size += (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
        }
    }
}

bool TxData::RandomizeAndSetChange(const CAmountMap& change_map, std::optional<size_t>& policy_pos_in_out, bilingual_str& error) {
    assert(m_output_data.size() == m_tx.vout.size());
    assert(m_change_data.size() == change_map.size());

    // n_fixed is an accounting var to reduce the range of output indices into
    // which we slot change. We want to ensure that the fee and dummy come at
    // the end, because otherwise anything after them would be clearly change.
    const size_t n_fixed = 1
        + (m_output_data.size() > 1 && m_output_data[m_output_data.size() - 2].ty == OutputType::OUTPUT_DUMMY);
    size_t zero_change_count = 0;
    for (const auto& asset_change : change_map) {
        if (asset_change.first != policyAsset && asset_change.second == 0) {
            zero_change_count++;
        }
    }

    // Uniformly randomly place change outputs for all assets, except that the policy-asset
    // change may have a fixed position.
    std::vector<std::optional<CAsset>> change_pos{m_tx.vout.size() + m_change_data.size() - zero_change_count};
    if (policy_pos_in_out) {
        if (*policy_pos_in_out >= change_pos.size()) {
            error = _("Change index out of range");
            return false;
        }
        change_pos[*policy_pos_in_out] = policyAsset;
    } // else randomly set policyasset change position

    for (const auto& asset_change : change_map) {
        // No need to randomly set the policyAsset change if has been set manually
        if (policy_pos_in_out && asset_change.first == policyAsset) {
            continue;
        }
        if (asset_change.second == 0) {
            if (asset_change.first == policyAsset) {
                // 0-valued change in the policy asset will be dropped in CreateTransactionInternal
                // by Core logic that we want to keep around. In the meantime though we should
                // unblind it to make sure it doesn't mess up our blinding logic
                m_change_data[asset_change.first].second.blind_amount = RangeproofType::NO_RANGEPROOF;
                m_change_data[asset_change.first].second.blind_asset = false;
                MaybePushDummyOutput();
            } else {
                // For non-policy zero change, simply drop it
                continue;
            }
        }

        size_t index;
        do {
            index = GetRandInt(change_pos.size() - n_fixed);
        } while (change_pos[index]);

        change_pos[index] = asset_change.first;
        if (asset_change.first == policyAsset) {
            *policy_pos_in_out = index;
        }
    }

    // Create all the change outputs in their respective places, inserting them
    // in increasing order so that none of them affect each others' indices
    for (unsigned int i = 0; i < change_pos.size(); i++) {
        if (!change_pos[i]) {
            continue;
        }

        if (!m_change_data.count(*change_pos[i])) {
            error = _("No change output for asset");
            return false;
        }

        const auto&& pair = std::move(m_change_data[*change_pos[i]]);

        m_tx.vout.insert(m_tx.vout.begin() + i, pair.first);
        m_output_data.insert(m_output_data.begin() + i, pair.second);
    }
    m_change_data.clear();
    return true;
}

void TxData::PushInput(const CInputCoin& coin, uint32_t sequence) {
    InputData input_data = {
        .value = coin.value,
        .asset = coin.asset,
        .is_blinded = coin.txout.nValue.IsCommitment() || coin.txout.nAsset.IsCommitment(),
        .bf_asset = coin.bf_asset,
        .bf_net = uint256{},
    };
    int res = secp256k1_netbf_compute(secp256k1_blind_context, input_data.bf_net.data(), coin.value, coin.bf_value.data(), coin.bf_asset.data());
    assert(res); /* blinding factors should not overflow */

    m_tx.vin.emplace_back(CTxIn(coin.outpoint, CScript(), sequence));
    m_input_data.emplace_back(input_data);
}

void TxData::AddIssuanceDetails(const IssuanceDetails* issuance_details) {
std::cout << "ADDING ISSUANCE DATA1" << std::endl;
    assert(m_tx.vin.size() > 0);
    if (!issuance_details) {
        return;
    }
std::cout << "ADDING ISSUANCE DATA2" << std::endl;

    // Locate issuance/token outputs
    std::optional<size_t> asset_index = std::nullopt;
    std::optional<size_t> token_index = std::nullopt;
    for (unsigned int i = 0; i < m_tx.vout.size(); i++) {
        if (m_tx.vout[i].nAsset.IsExplicit() && m_tx.vout[i].nAsset.GetAsset() == CAsset(uint256S("1"))) {
            asset_index = i;
        } else if (m_tx.vout[i].nAsset.IsExplicit() && m_tx.vout[i].nAsset.GetAsset() == CAsset(uint256S("2"))) {
            token_index = i;
        }
    }

    if (!asset_index && !token_index) {
        return;
    }
std::cout << "ADDING ISSUANCE DATA3" << std::endl;

    std::optional<IssuanceData> asset_data = std::nullopt;
    std::optional<IssuanceData> token_data = std::nullopt;

    // Initial issuance request
    if (issuance_details->reissuance_asset.IsNull() && issuance_details->reissuance_token.IsNull()) {
        uint256 entropy;
        CAsset asset;
        CAsset token;
        // Initial issuance always uses vin[0]
        GenerateAssetEntropy(entropy, m_tx.vin[0].prevout, issuance_details->contract_hash);
        CalculateAsset(asset, entropy);
        CalculateReissuanceToken(token, entropy, issuance_details->blind_issuance);
        m_tx.vin[0].assetIssuance.assetEntropy = issuance_details->contract_hash;

        // We're making asset outputs, fill out asset type and issuance input
        if (asset_index) {
            asset_data = IssuanceData {
                .input_idx = 0,
                .is_token = false,
                .value = m_tx.vout[*asset_index].nValue.GetAmount(),
                .asset = asset,
                .blind_amount = issuance_details->blind_issuance ? RangeproofType::RANGEPROOF_FULL : RangeproofType::NO_RANGEPROOF,
            };
        }
        // We're making reissuance token outputs
        if (token_index) {
            token_data = IssuanceData {
                .input_idx = 0,
                .is_token = true,
                .value = m_tx.vout[*token_index].nValue.GetAmount(),
                .asset = token,
                .blind_amount = issuance_details->blind_issuance ? RangeproofType::RANGEPROOF_FULL : RangeproofType::NO_RANGEPROOF,
            };
            // If we're blinding a token issuance and no assets, we must make
            // the asset issuance a blinded commitment to 0. We assume the
            // user wants to make this 0 visible, so use an explicit-value
            // rangeproof on it to save transaction space.
            if (issuance_details->blind_issuance && !asset_index) {
                asset_data = IssuanceData {
                    .input_idx = 0,
                    .is_token = false,
                    .value = 0,
                    .asset = asset,
                    .blind_amount = RangeproofType::RANGEPROOF_SINGLE,
                };
            }
        }
    // Asset being reissued with explicitly named asset/token
    } else if (asset_index) {
        std::optional<size_t> reissuance_index = std::nullopt;
        for (unsigned int i = 0; i< m_input_data.size(); i++) {
            if (m_input_data[i].asset == issuance_details->reissuance_asset) {
                reissuance_index = i;
                break;
            }
        }
        assert(reissuance_index);

        // Fill in output with issuance
        m_tx.vout[*asset_index].nAsset = issuance_details->reissuance_asset;
        // Fill in issuance
        // Blinding revealing underlying asset
        m_tx.vin[*reissuance_index].assetIssuance.assetBlindingNonce = m_input_data[*reissuance_index].bf_asset;
        m_tx.vin[*reissuance_index].assetIssuance.assetEntropy = issuance_details->entropy;
        m_tx.vin[*reissuance_index].assetIssuance.nAmount = m_tx.vout[*asset_index].nValue;

        // If blinded token derivation, blind the issuance regardless of what the user requested
        // FIXME shouldn't we return an error here?
        CAsset temp_token;
        CalculateReissuanceToken(temp_token, issuance_details->entropy, true);
        token_data = IssuanceData {
            .input_idx = *reissuance_index,
            .is_token = true,
            .value = m_tx.vout[*asset_index].nValue.GetAmount(),
            .asset = issuance_details->reissuance_token,
            .blind_amount = temp_token == issuance_details->reissuance_token ? RangeproofType::RANGEPROOF_FULL : RangeproofType::NO_RANGEPROOF,
        };
    }

    if (asset_data) {
        m_tx.vin[asset_data->input_idx].assetIssuance.nAmount = asset_data->value;
        m_tx.vout[*asset_index].nAsset = asset_data->asset;
        m_issuance_data.emplace_back(*asset_data);
    }
    if (token_data) {
        m_tx.vin[token_data->input_idx].assetIssuance.nInflationKeys = token_data->value;
        m_tx.vout[*token_index].nAsset = token_data->asset;
        m_issuance_data.emplace_back(*token_data);
    }
}

// Note for reviewers of this function: I (Andrew) ran the functional tests with
// an assert() checking that the resulting transaction sizes matched the sizes
// obtained by fully running BlindTransaction. In the cases that there were
// mismatches I confirmed that the new behavior was intentional and resulted
// in a smaller transaction.
void TxData::DummyBlindTx(void) {
    // Analyze transaction to decide what to do with e.g. dummy outputs
    size_t n_blinded_inputs = 0;
    size_t n_blinded_outputs = 0;
    for (const auto& inp : m_input_data) {
        if (inp.is_blinded) {
            n_blinded_inputs++;
        }
    }
    for (const auto& iss : m_issuance_data) {
        if (iss.IsBlinded()) {
            n_blinded_inputs++;
        }
    }
    // Count blinded outputs. Note that we are counting something different
    // for inputs than for outputs!! For inputs we are just counting how
    // many outputs are blinded at all (and we really only care if this number
    // is nonzero); for outputs we're counting how many amounts and how many
    // assets are blinded.
    std::optional<size_t> dummy_idx = std::nullopt;
    for (size_t i = 0; i < m_output_data.size(); i++) {
        if (m_output_data[i].blind_amount != RangeproofType::NO_RANGEPROOF) {
std::cout << "Dummy Blinding counting value for " << OutputTypeToString(m_output_data[i].ty) << std::endl;
            n_blinded_outputs++;
        }
        if (m_output_data[i].blind_asset) {
std::cout << "Dummy Blinding counting asset for " << OutputTypeToString(m_output_data[i].ty) << std::endl;
            n_blinded_outputs++; 
        }
        if (m_output_data[i].ty == OutputType::OUTPUT_DUMMY) {
            assert(!dummy_idx);
            dummy_idx = i;
        }
    }
std::cout << "Dummy Blinding dummy " << !!dummy_idx << std::endl;
std::cout << "Dummy Blinding see " << n_blinded_outputs << " blinded outputs, and " << n_blinded_inputs << " blinded inputs" << std::endl;
    // First: if there is more than one fully-blinded output, including our dummy, drop the dummy
    if (n_blinded_outputs > 2 && dummy_idx) {
        m_tx.vout.erase(m_tx.vout.begin() + *dummy_idx);
        m_output_data.erase(m_output_data.begin() + *dummy_idx);
        dummy_idx = std::nullopt;
        n_blinded_outputs -= 1;
    }
std::cout << "Dummy Blinding dummy " << !!dummy_idx << std::endl;
std::cout << "Dummy Blind222 see " << n_blinded_outputs << " blinded outputs, and " << n_blinded_inputs << " blinded inputs" << std::endl;
    // Next: if there are no blinded inputs but a dummy output, drop it
    if (n_blinded_inputs == 0 && n_blinded_outputs == 1) {
        assert(dummy_idx); // impossible due to logic in AdjustCoinSelectionParameters
        m_tx.vout.erase(m_tx.vout.begin() + *dummy_idx);
        m_output_data.erase(m_output_data.begin() + *dummy_idx);
        dummy_idx = std::nullopt;
        n_blinded_outputs -= 1;
    }
    assert (n_blinded_inputs != 0 || n_blinded_outputs != 1);
    // Next: no blinded inputs and one blinded output (or two partially blinded outputs).
    if (n_blinded_inputs == 0 && n_blinded_outputs == 2) {
        for (size_t i = 0; i < m_output_data.size(); i++) {
            if (m_output_data[i].IsBlinded()) {
                switch(m_output_data[i].ty) {
                // For recipient outputs there are a couple of cases:
                //     * it is fully blinded; in this case reduce the rangeproof to minimal
                //       so that the recipient wallet's logic still sees a valid rangeproof
                //       with sidechannel data etc
                //     * its value is blinded, but not the asset, and the dummy is present;
                //       again, the blinding serves no purpose so minimize it
                //     * its value is blinded alongside a non-dummy asset; in this case it
                //       might be helpful (specifically if the other output also has a blinded
                //       value, and its explicit asset is equal to this one). To avoid further
                //       case analysis on an already-obscure edge case, just keep the blinding
                //     * the value is not blinded; there is nothing to minimize so do nothing
                case OutputType::OUTPUT_RECIPIENT:
                    if (m_output_data[i].blind_amount == RangeproofType::RANGEPROOF_FULL
                        && (m_output_data[i].blind_asset || dummy_idx)) {
                        m_output_data[i].blind_amount = RangeproofType::RANGEPROOF_MINIMAL;
                    }
                    break;
                // If it's our own change just unblind it.
                case OutputType::OUTPUT_CHANGE_NONPOLICY:
                case OutputType::OUTPUT_CHANGE_POLICY:
                    // assert that both counts of blindedness came from this output
                    assert(m_output_data[i].blind_amount != RangeproofType::NO_RANGEPROOF);
                    assert(m_output_data[i].blind_asset);
                    m_output_data[i].blind_amount = RangeproofType::NO_RANGEPROOF;
                    m_output_data[i].blind_asset = false;
                    n_blinded_outputs -= 2;
                    break;
                // If we're looking at our dummy output, leave it alone
                case OutputType::OUTPUT_DUMMY:
                    break;
                // Finally, fees are never blinded
                case OutputType::OUTPUT_FEE:
                    assert(0);
                    break;
                }
                break;
            }
        }
    }
std::cout << "Dummy Blinding dummy " << !!dummy_idx << std::endl;
std::cout << "Dummy Bl333322 see " << n_blinded_outputs << " blinded outputs, and " << n_blinded_inputs << " blinded inputs" << std::endl;

    // Okay, done. Fill in blinding data with dummies
    m_tx.witness.vtxinwit.resize(m_tx.vin.size());
    m_tx.witness.vtxoutwit.resize(m_tx.vout.size());
    for (size_t i = 0; i < m_tx.vout.size(); i++) {
        if (m_output_data[i].blind_amount == RangeproofType::NO_RANGEPROOF) {
            m_tx.vout[i].nValue.vchCommitment.resize(9);
            m_tx.vout[i].nNonce.vchCommitment.clear();
        } else {
            m_tx.vout[i].nValue.vchCommitment.resize(33);
            m_tx.vout[i].nNonce.vchCommitment.resize(33);
        }
        m_tx.witness.vtxoutwit[i].vchRangeproof.resize(rangeproof_size(m_output_data[i].blind_amount));
        if (m_output_data[i].blind_asset) {
            m_tx.witness.vtxoutwit[i].vchSurjectionproof.resize(surjectionproof_size(m_tx.vin.size() + m_issuance_data.size()));
        } else {
            assert(m_tx.witness.vtxoutwit[i].vchSurjectionproof.empty());
        }
    }
    for (const auto& data : m_issuance_data) {
std::cout << "ISSUANCE DATA" << std::endl;
        auto& rangeproof = data.is_token
            ? m_tx.witness.vtxinwit[data.input_idx].vchIssuanceAmountRangeproof
            : m_tx.witness.vtxinwit[data.input_idx].vchInflationKeysRangeproof;
        auto& commit = data.is_token
            ? m_tx.vin[data.input_idx].assetIssuance.nAmount
            : m_tx.vin[data.input_idx].assetIssuance.nInflationKeys;
        if (data.blind_amount == RangeproofType::NO_RANGEPROOF) {
            if (data.value == 0) {
                commit.vchCommitment.clear();
            } else {
                commit.vchCommitment.resize(9);
assert(!m_tx.vin[data.input_idx].assetIssuance.IsNull());
            }
        } else {
            commit.vchCommitment.resize(33);
assert(!m_tx.vin[data.input_idx].assetIssuance.IsNull());
        }
        rangeproof.resize(rangeproof_size(data.blind_amount));
    }
}

void TxData::DropChangeOutput(void) {
    for (unsigned int i = 0; i < m_output_data.size(); i++) {
        if (m_output_data[i].ty == OutputType::OUTPUT_CHANGE_POLICY) {
            m_output_data.erase(m_output_data.begin() + i);
            m_tx.vout.erase(m_tx.vout.begin() + i);
        }
    }
    MaybePushDummyOutput();
}

}

