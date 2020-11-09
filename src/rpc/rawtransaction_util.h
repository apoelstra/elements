// Copyright (c) 2017-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_RAWTRANSACTION_UTIL_H
#define BITCOIN_RPC_RAWTRANSACTION_UTIL_H

#include <map>
#include <vector>

#include <merkleblock.h>
#include <primitives/bitcoin/merkleblock.h>
#include <primitives/bitcoin/transaction.h>
#include <primitives/transaction.h>
#include <pubkey.h>

class FillableSigningProvider;
class UniValue;
struct CMutableTransaction;
class Coin;
class COutPoint;
class SigningProvider;

/**
 * Sign a transaction with the given keystore and previous transactions
 *
 * @param  mtx           The transaction to-be-signed
 * @param  keystore      Temporary keystore containing signing keys
 * @param  coins         Map of unspent outputs
 * @param  hashType      The signature hash type
 * @returns JSON object with details of signed transaction
 */
UniValue SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, const UniValue& hashType);

/**
  * Parse a prevtxs UniValue array and get the map of coins from it
  *
  * @param  prevTxs       Array of previous txns outputs that tx depends on but may not yet be in the block chain
  * @param  keystore      A pointer to the temprorary keystore if there is one
  * @param  coins         Map of unspent outputs - coins in mempool and current chain UTXO set, may be extended by previous txns outputs after call
  */
void ParsePrevouts(const UniValue& prevTxsUnival, FillableSigningProvider* keystore, std::map<COutPoint, Coin>& coins);

/** Create a transaction from univalue parameters. If (and only if)
    output_pubkeys_out is null, the "nonce hack" of storing Confidential
    Assets output pubkeys in nonces will be used. */
CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, bool rbf, const UniValue& assets_in, std::vector<CPubKey>* output_pubkeys_out = nullptr, bool allow_peg_in = true);

/** Create a peg-in input */
void CreatePegInInput(CMutableTransaction& mtx, uint32_t input_idx, CTransactionRef& tx_btc, CMerkleBlock& merkle_block, const std::set<CScript>& claim_scripts, const std::vector<unsigned char>& txData, const std::vector<unsigned char>& txOutProofData);
void CreatePegInInput(CMutableTransaction& mtx, uint32_t input_idx, Sidechain::Bitcoin::CTransactionRef& tx_btc, Sidechain::Bitcoin::CMerkleBlock& merkle_block, const std::set<CScript>& claim_scripts, const std::vector<unsigned char>& txData, const std::vector<unsigned char>& txOutProofData);

#endif // BITCOIN_RPC_RAWTRANSACTION_UTIL_H
