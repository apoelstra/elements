// Copyright (c) 2022 The Elements Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <secp256k1_rangeproof.h>
#include <primitives/transaction.h>
#include <wallet/coinselection.h>
#include <wallet/wallet.h>

#include <util/translation.h>

namespace Blinding {

enum class ErrorType {
    /** The transaction has blinded inputs but no blinded outputs so cannot be balanced */
    BlindInputsNoOutputs,
    /** The transaction as a whole failed "inputs = outputs" */
    TxUnbalanced,
    /** An output or (re)issuance has a confidential amount but no rangeproof */
    BadValueCommitment,
    /** An output or (re)issuance has a confidential amount but no rangeproof */
    MissingRangeproof,
    /** An output or (re)issuance has a bad rangeproof */
    InvalidRangeproof,
    /** An output or (re)issuance has a confidential asset but no surjection proof */
    MissingSurjectionProof,
    /** An output or (re)issuance has a bad surjection proof */
    InvalidSurjectionProof,
    /** A confidential output asset ID is identical to an input one; this will not validate */
    OutputAssetIdMatchesInput,
    /** Tried to blind an output or (re)issuance but had no key with which to ECDH */
    MissingBlindingKey,
    /** Tried to create a surjection proof but there were more than 255 inputs */
    TooManyInputs,
};

/** A single error related to CT/transaction blinding */
struct Error {
    /** The high-level type of the error.
     *
     * The remaining fields only have meaning depending on the value of this one. */
    ErrorType err;
    /** The index of the offending input, if any */
    size_t input_idx;
    /** The index of the offending output, if any */
    size_t output_idx;
    /** Quantity related to the error (e.g. an input count) */
    size_t count;
    /** Amount related to the error (e.g. an output amount or discrepancy), if any */
    int64_t amount;
    /** Blob related to the error (e.g. a blinding factor), if any */
    unsigned char data32[32];
    /** Asset ID related to the error, if any */
    secp256k1_generator asset_id;
    /** A freeform error string for user output */
    bilingual_str errstr;
};

enum class RangeproofType {
    /** Construct a "full" rangeproof according to the user's ct_bits and ct_exponent setting
     *
     * If these settings are incompatible with Elements (e.g. ct_bits is set to 2 so that
     * the resulting proofs  */
    RANGEPROOF_FULL,
    /** Construct a "small" rangeproof which proves only 3 bits
     *
     * This rangeproof is too small to provide any meaningful hiding of the amount, but is
     * large enough to contain the sidechannel data needed by the recipient. Used for
     * "dummy outputs" which are required by the CT math to be blinded and too large
     * to be burned. */
    RANGEPROOF_MINIMAL,
    /** Construct a single-value rangeproof which hides the blinding factor but not the value.
     *
     * Too small to provide meaningful hiding *or* to encode data. Used for 0-valued or
     * dust outputs which are required by the CT math but will be burned. */
    RANGEPROOF_SINGLE,
    /* Do not blind this amount at all */
    NO_RANGEPROOF,
};

//
enum class OutputType {
    /** Output is going somewhere useful
     *
     * This output type is special because CreateTransactionInternal has logic to account
     * for its cost, except for its CT data. This logic can't be removed without breaking
     * non-g_con_elemnetsmode tests, and increasing the diff with Bitcoin Core.
     */
    OUTPUT_RECIPIENT,
    /** Change output (not policy asset) 
     *
     * These are Elements-specific outputs which may be removed, but only if their value
     * would be exactly zero. SelectCoins does not understand this so their weight is
     * accounted for by coin_selection_params.tx_noinputs_size. */
    OUTPUT_CHANGE_NONPOLICY,
    /** Change output (policy asset)
     *
     * This is a single output which SelectCoins will attempt to minimize; if its value
     * is below the dust threshold it will be dropped. SelectCoins has special logic
     * for this so it is *not* accounted for in coin_selection_params.tx_noinputs_size
     * but instead in coin_selection_params.change_output_size and .change_spend_size. */
    OUTPUT_CHANGE_POLICY,
    /** Dummy output
     *
     * An Elements-specific output type which only exists to make the CT equation balance.
     * It will be a 0-valued OP_RETURN output with an unblinded (policy) asset type and
     * blinded but explicitly-proven value. */
    OUTPUT_DUMMY,
    /** Fee output
     *
     * Elements-specific output which must be unblinded and which has an empty scriptPubKey. */
    OUTPUT_FEE,
};

static const char* OutputTypeToString(OutputType ty) {
    switch(ty) {
    case OutputType::OUTPUT_RECIPIENT: return "OUTPUT_RECIPIENT";
    case OutputType::OUTPUT_CHANGE_NONPOLICY: return "OUTPUT_CHANGE_NONPOLICY";
    case OutputType::OUTPUT_CHANGE_POLICY: return "OUTPUT_CHANGE_POLICY";
    case OutputType::OUTPUT_DUMMY: return "OUTPUT_DUMMY";
    case OutputType::OUTPUT_FEE: return "OUTPUT_FEE";
    default: return "UNKNOWN";
    }
}


struct OutputData {
    /** The wallet's blinding key used to derive the ECDH key, i.e. "nonce", for the rangeproof
     *
     * Used when blinding the amount for spendable outputs; otherwise unneeded */
    CPubKey blinding_key;
    /** Whether the amount of this output should be blinded */
    RangeproofType blind_amount;
    /** Whether the asset of this output should be blinded */
    bool blind_asset;
    /** Whether this output is a policy change output (which is treated specially
     *  by the fee estimation logic, since it may be dropped). */
    OutputType ty;

    /** For CT accounting, whether this output is blinded */
    bool IsBlinded(void) const {
        return blind_amount != RangeproofType::NO_RANGEPROOF || blind_asset;
    }
};

struct IssuanceData {
    /** The index of the input this issuance is attached to */
    size_t input_idx;
    /** Whether this asset is a (reissuance) token or a issuance */
    bool is_token;
    /** The unblinded amount */
    CAmount value;
    /** The unblinded asset */
    CAsset asset;
    /** Whether the amount of this issuance should be blinded */
    RangeproofType blind_amount;

    /** For CT accounting, whether this output is blinded */
    bool IsBlinded(void) const {
        return blind_amount != RangeproofType::NO_RANGEPROOF;
    }
};

struct InputData {
    /** The unblinded amount */
    CAmount value;
    /** The unblinded asset */
    CAsset asset;
    /** Whether this input is blinded, for purposes of CT calculations */
    bool is_blinded;
    /** The asset blinding factor of the input, which may be needed for reissuance  */
    uint256 bf_asset;
    /** The "net blinding factor" for a confidential amount
     *
     * Typically a confidential amount is committed as vA' + rG, where A' is a
     * blinded asset and r is a blinding factor. However, this value r is only
     * really useful for computing a rangeproof. For transaction balancing we
     * need to consider that A' = A + sG, where A is the actual asset (in the
     * `asset` member variable above) and s is another blinding factor.
     *
     * This member variable contains (vs + r), which is the quantity needed
     * for transaction-balancing calculations. If the amount is unblinded then
     * r will be 0; if the asset is unblinded then s will be 0. */
    uint256 bf_net;
};

/** A structure containing all the data necessary to track blinding */
class TxData {
private:
    /** The underlying transaction */
    CMutableTransaction m_tx;
    /** Data associated with each output */
    std::vector<OutputData> m_output_data;
    /** Data associated with each asset (re)issuance */
    std::vector<IssuanceData> m_issuance_data;
    /** Data associated with each input */
    std::vector<InputData> m_input_data;

    /** Change outputs, which are stored separately until they are all known */
    std::map<CAsset, std::pair<CTxOut, OutputData> > m_change_data;

    /** Pushes a dummy output (0 value, single-value rangeproof, explicit policy asset)
     *
     * This method is private since dummy outputs should only be added as part of
     * the blinding logic. */
    void PushDummyOutput(void);

    /** Pushes a dummy output if there are no other blinded outputs */
    void MaybePushDummyOutput(void);

    /** Pushes a fee output (explicit asset/value, no scriptPubKey)
     *
     * This method is private since fee outputs should only be added as part of
     * the blinding logic. */
    void PushFeeOutput(void);

public:
    /** Pushes an output onto the transaction, recording its blinding data */
    void PushRecipientOutput(const CRecipient& recipient);

    /** Pushes a change output, along with blinding key if this output should be blinded */
    void PushChangeOutput(const CAsset asset, CAmount amount, const CScript& script, const std::optional<CPubKey> blinding_key);

    /** Adjusts coin-selection parameters from the upstream Bitcoin values prior to coin selection
     *
     * This does adjustments for blinding, naturally, but also adjusts tranasction
     * parameters for assets and fee outputs. It may also add a dummy output if
     * it believes one may be necessary (in the case that there is only one blinded
     * output).
     *
     * Much of this function logically belongs inline in CreateTransactionInternal
     * in wallet.cpp, but to minimize merge conflicts and keep all the "Elements
     * stuff" in one place, we do it here.
     *
     * It should be called BEFORE SelectCoins and AFTER all outputs have been added. */
    void AdjustCoinSelectionParameters(CoinSelectionParams& coin_selection_params);

    /** Sets the change values for all assets and repositions them uniformly randomly
     *
     * If `policy_pos` is set then the change output of the policy output is placed
     * in that position rather than uniformly randomly.
     *
     * Returns the (new) position of the policy change output */
    bool RandomizeAndSetChange(const CAmountMap& change_map, std::optional<size_t>& policy_pos, bilingual_str& error);

    /** Adds an input to the transaction */
    void PushInput(const CInputCoin& coin, uint32_t sequence);

    /** Attaches issuances to the appropriate inputs */
    void AddIssuanceDetails(const IssuanceDetails* issuance_details);

    /** Put dummy blinding data into the transaction for the purpose of fee estimation */
    void DummyBlindTx(void);

    /** Drop the policy change output of the transaction, possibly putting a dummy output
     *  in its place if one would be needed for blinding. */
    void DropChangeOutput(void);
 
    /** Read-only accessor for the underlying transaction */
    const CMutableTransaction& GetTx(void) const { return m_tx; }

    /** Read-only accessor for the policy change output of the underlying transaction */
    const CTxOut& GetChangeOutput(void) const {
        for (unsigned int i = 0; i < m_output_data.size(); i++) {
            if (m_output_data[i].ty == OutputType::OUTPUT_CHANGE_POLICY) {
                return m_tx.vout[i];
            }
        }
        assert(0);
        return m_tx.vout[0];
    }
};

}

