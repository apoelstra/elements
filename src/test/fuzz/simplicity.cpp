// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <span.h>
#include <primitives/transaction.h>
extern "C" {
#include <simplicity/cmr.h>
#include <simplicity/elements/env.h>
#include <simplicity/elements/exec.h>
}
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

extern "C" void *seed_data_new(void);
extern "C" void seed_data_delete(void *);

extern "C" unsigned char *seed_data_tx_data(void*);
extern "C" size_t seed_data_tx_len(void*);
extern "C" unsigned char *seed_data_prog_data(void*);
extern "C" size_t seed_data_prog_len(void*);
extern "C" unsigned char *seed_data_wit_data(void*);
extern "C" size_t seed_data_wit_len(void*);
extern "C" unsigned char *seed_data_cmr(void*);
extern "C" unsigned char *seed_data_amr(void*);

extern "C" size_t seed_data_read_tx(void *, unsigned char *, size_t);
extern "C" size_t seed_data_read_program(void *, unsigned char *, size_t);

uint256 GENESIS_HASH;

CConfidentialAsset INPUT_ASSET_UNCONF{};
CConfidentialAsset INPUT_ASSET_CONF{};
CConfidentialValue INPUT_VALUE_UNCONF{};
CConfidentialValue INPUT_VALUE_CONF{};
CScript TAPROOT_SCRIPT_PUB_KEY{};
std::vector<unsigned char> TAPROOT_CONTROL{};
std::vector<unsigned char> TAPROOT_ANNEX{99, 0x50};
//CMutableTransaction MTX_TEMPLATE{};

void initialize_simplicity()
{
    g_con_elementsmode = true;

    GENESIS_HASH = uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206");

    INPUT_VALUE_UNCONF.SetToAmount(12345678);
    INPUT_VALUE_CONF.vchCommitment = {
        0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    };

    INPUT_ASSET_UNCONF.vchCommitment = INPUT_VALUE_CONF.vchCommitment;
    INPUT_ASSET_UNCONF.vchCommitment[0] = 0x01;
    INPUT_ASSET_CONF.vchCommitment = INPUT_VALUE_CONF.vchCommitment;
    INPUT_ASSET_CONF.vchCommitment[0] = 0x0a;

    XOnlyPubKey intkey = XOnlyPubKey{uint256::ONE};
    XOnlyPubKey extkey = XOnlyPubKey{uint256::ONE};
    TAPROOT_SCRIPT_PUB_KEY = CScript{} << OP_1 << std::vector<unsigned char>(extkey.begin(), extkey.end());
    // TODO have control block of nontrivial path length
    TAPROOT_CONTROL.push_back(TAPROOT_LEAF_TAPSIMPLICITY | 1); // 1 is parity
    TAPROOT_CONTROL.insert(TAPROOT_CONTROL.end(), intkey.begin(), intkey.end());
}

FUZZ_TARGET_INIT(simplicity, initialize_simplicity)
{
    uint32_t budget;
    simplicity_err error;

    // 1. Initialize seed data by reading from the fuzzer input. This is the
    //    only block of code in which we should be reading fuzzer input.
    std::vector<unsigned char> tx_bytes;
    std::vector<unsigned char> prog_bytes;
    std::vector<unsigned char> wit_bytes;
    unsigned char cmr[32];
    unsigned char amr[32];
    {
        CDataStream ds(buffer, SER_NETWORK, INIT_PROTO_VERSION);
        std::vector<unsigned char> prog_input;
        std::vector<unsigned char> tx_input;

        try {
            ds >> budget;
            ds >> tx_input;
            ds >> prog_input;
        } catch (const std::ios_base::failure&) {
            return;
        }

        if (tx_input.size() == 0 || prog_input.size() == 0) {
            return;
        }

        void* seed_data = seed_data_new();
        if (seed_data_read_tx(seed_data, tx_input.data(), tx_input.size()) == 0) {
            seed_data_delete(seed_data);
            return;
        }
        if (seed_data_read_program(seed_data, prog_input.data(), prog_input.size()) == 0) {
            seed_data_delete(seed_data);
            return;
        }

        tx_bytes.assign(
            seed_data_tx_data(seed_data),
            seed_data_tx_data(seed_data) + seed_data_tx_len(seed_data)
        );
        prog_bytes.assign(
            seed_data_prog_data(seed_data),
            seed_data_prog_data(seed_data) + seed_data_prog_len(seed_data)
        );
        wit_bytes.assign(
            seed_data_wit_data(seed_data),
            seed_data_wit_data(seed_data) + seed_data_wit_len(seed_data)
        );
        memcpy(amr, seed_data_amr(seed_data), 32);

        // Compute CMR and do some sanity checks on it (and the program)
        assert (prog_bytes.size() > 0);
        assert(simplicity_computeCmr(&error, cmr, prog_bytes.data(), prog_bytes.size()));
        if (error == SIMPLICITY_NO_ERROR) {
            assert(!memcmp(cmr, seed_data_cmr(seed_data), 32));
        } else {
            assert(error == SIMPLICITY_ERR_FAIL_CODE);
            memset(cmr, 0, 32);
        }

        seed_data_delete(seed_data);
    }

    // 2. Construct transaction.
    CMutableTransaction mtx;
    {

        CDataStream txds{tx_bytes, SER_NETWORK, INIT_PROTO_VERSION};
        txds >> mtx;
        mtx.witness.vtxinwit.resize(mtx.vin.size());
        mtx.witness.vtxoutwit.resize(mtx.vout.size());
    }

    // 3. Construct `nIn` and `spent_outs` array.
    //
    // Here we extract data from the first input's txid, since the fuzzer already
    // produced that as a random string which has no other meaning. So to avoid
    // complicating our seed encoding beyond "transaction then simplicity code"
    // we just use it as a random source.
    //
    // We do skip the first byte since that has pegin/issuance flag in it and
    // therefore already has semantic information.
    size_t nIn = mtx.vin[0].prevout.hash.data()[1] % mtx.vin.size();
    std::vector<CTxOut> spent_outs{};
    for (unsigned int i = 0; i < mtx.vin.size(); i++) {
        // Null asset or value would assert in the interpreter, and are impossible
        // to hit in real transactions. Nonces are not included in the UTXO set and
        // therefore don't matter.
        CConfidentialValue value = i & 1 ? INPUT_VALUE_CONF : INPUT_VALUE_UNCONF;
        CConfidentialAsset asset = i & 2 ? INPUT_ASSET_CONF : INPUT_ASSET_UNCONF;
        CScript scriptPubKey;
        if (i != nIn) {
            // For scriptPubKeys we can use arbitrary scripts. We include the empty
            // script even though in a real transaction this would be impossible,
            // because it shouldn't break anything.
            for (unsigned int j = 0; j < i; j++) {
                scriptPubKey << OP_TRUE;
            }
        } else {
            scriptPubKey = TAPROOT_SCRIPT_PUB_KEY;
        }

        spent_outs.push_back(CTxOut{asset, value, scriptPubKey});
    }
    assert(spent_outs.size() == mtx.vin.size());

    // 4. Set up witness data
    mtx.witness.vtxinwit[nIn].scriptWitness.stack.clear();
    mtx.witness.vtxinwit[nIn].scriptWitness.stack.push_back(prog_bytes);
    mtx.witness.vtxinwit[nIn].scriptWitness.stack.push_back(TAPROOT_CONTROL);
    if (mtx.vin[0].prevout.hash.data()[2] & 1) {
       mtx.witness.vtxinwit[nIn].scriptWitness.stack.push_back(TAPROOT_ANNEX);
    }

    // 5. Set up Simplicity environment and tx environment
    rawTapEnv simplicityRawTap;
    simplicityRawTap.controlBlock = TAPROOT_CONTROL.data();
    simplicityRawTap.pathLen = (TAPROOT_CONTROL.size() - TAPROOT_CONTROL_BASE_SIZE) / TAPROOT_CONTROL_NODE_SIZE;
    simplicityRawTap.scriptCMR = cmr;

    PrecomputedTransactionData txdata{GENESIS_HASH};
    std::vector<CTxOut> spent_outs_copy{spent_outs};
    txdata.Init(mtx, std::move(spent_outs_copy));
    assert(txdata.m_simplicity_tx_data != NULL);

    // 4. Main test
    unsigned char imr_out[32];
    unsigned char *imr = mtx.vin[0].prevout.hash.data()[2] & 2 ? imr_out : NULL;

    const transaction* tx = txdata.m_simplicity_tx_data;
    tapEnv* taproot = simplicity_elements_mallocTapEnv(&simplicityRawTap);
    simplicity_elements_execSimplicity(&error, imr, tx, nIn, taproot, GENESIS_HASH.data(), budget, amr, prog_bytes.data(), prog_bytes.size(), wit_bytes.data(), wit_bytes.size());

    // 5. Secondary test -- try flipping a bunch of bits and check that this doesn't mess things up
    for (size_t j = 0; j < 8 * prog_bytes.size(); j++) {
        if (j > 32 && j % 23 != 0) continue; // skip most bits so this test doesn't overwhelm the fuzz time
        prog_bytes.data()[j / 8] ^= (1 << (j % 8));
        simplicity_elements_execSimplicity(&error, imr, tx, nIn, taproot, GENESIS_HASH.data(), budget, amr, prog_bytes.data(), prog_bytes.size(), wit_bytes.data(), wit_bytes.size());
    }

    // 6. Cleanup
    free(taproot);
}
