// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <validation.h>
#include <httpserver.h>
#include <key_io.h>
#include <node/context.h>
#include <outputtype.h>
#include <pegins.h>
#include <rpc/blockchain.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <scheduler.h>
#include <script/descriptor.h>
#include <util/check.h>
#include <util/message.h> // For MessageSign(), MessageVerify()
#include <util/strencodings.h>
#include <util/system.h>

#include <stdint.h>
#include <tuple>
#ifdef HAVE_MALLOC_INFO
#include <malloc.h>
#endif

#include <univalue.h>

#include <assetsdir.h>

static UniValue validateaddress(const JSONRPCRequest& request)
{
            RPCHelpMan{"validateaddress",
                "\nReturn information about the given bitcoin address.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to validate"},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "isvalid", "If the address is valid or not. If not, this is the only property returned."},
                        {RPCResult::Type::BOOL, "isvalid_parent", "If the address is valid or not for parent chain. Valid or not, no additional details will be appended unlike `isvalid`"},
                        {RPCResult::Type::STR, "address", "The address validated"},
                        {RPCResult::Type::STR_HEX, "scriptPubKey", "The hex-encoded scriptPubKey generated by the address"},
                        {RPCResult::Type::BOOL, "isscript", "If the key is a script"},
                        {RPCResult::Type::BOOL, "iswitness", "If the address is a witness address"},
                        {RPCResult::Type::NUM, "witness_version", /* optional */ true, "The version number of the witness program"},
                        {RPCResult::Type::STR_HEX, "witness_program", /* optional */ true, "The hex value of the witness program"},
                        {RPCResult::Type::STR_HEX, "confidential_key", "the raw blinding public key for that address, if any. \"\" if none"},
                        {RPCResult::Type::STR, "unconfidential", "The address without confidentiality key"},
                        {RPCResult::Type::OBJ, "parent_address_info", "If the address isvalid_parent, this object contains details about the parent address type",
                        {
                            {RPCResult::Type::STR, "address", ""},
                            {RPCResult::Type::STR_HEX, "scriptPubKey", ""},
                        }},
                    }
                },
                RPCExamples{
                    HelpExampleCli("validateaddress", EXAMPLE_ADDRESS) +
                    HelpExampleRpc("validateaddress", EXAMPLE_ADDRESS)
                },
            }.Check(request);

    CTxDestination dest = DecodeDestination(request.params[0].get_str());
    CTxDestination parent_dest = DecodeParentDestination(request.params[0].get_str());
    bool isValid = IsValidDestination(dest);
    bool is_valid_parent = IsValidDestination(parent_dest);
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("isvalid", isValid);
    ret.pushKV("isvalid_parent", is_valid_parent);
    if (isValid)
    {
        std::string currentAddress = EncodeDestination(dest);
        ret.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

        UniValue detail = DescribeAddress(dest);
        ret.pushKVs(detail);
        UniValue blind_detail = DescribeBlindAddress(dest);
        ret.pushKVs(blind_detail);
    }
    if (is_valid_parent) {
        UniValue parent_info(UniValue::VOBJ);
        std::string currentAddress = EncodeParentDestination(parent_dest);
        parent_info.pushKV("address", currentAddress);

        CScript scriptPubKey = GetScriptForDestination(parent_dest);
        parent_info.pushKV("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end()));

        UniValue detail = DescribeAddress(parent_dest);
        parent_info.pushKVs(detail);
        UniValue blind_detail = DescribeBlindAddress(parent_dest);
        parent_info.pushKVs(blind_detail);
        ret.pushKV("parent_address_info", parent_info);
    }
    return ret;
}

static UniValue createmultisig(const JSONRPCRequest& request)
{
            RPCHelpMan{"createmultisig",
                "\nCreates a multi-signature address with n signature of m keys required.\n"
                "It returns a json object with the address and redeemScript.\n",
                {
                    {"nrequired", RPCArg::Type::NUM, RPCArg::Optional::NO, "The number of required signatures out of the n keys."},
                    {"keys", RPCArg::Type::ARR, RPCArg::Optional::NO, "A json array of hex-encoded public keys.",
                        {
                            {"key", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, "The hex-encoded public key"},
                        }},
                    {"address_type", RPCArg::Type::STR, /* default */ "legacy", "The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\"."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR, "address", "The value of the new multisig address."},
                        {RPCResult::Type::STR_HEX, "redeemScript", "The string value of the hex-encoded redemption script."},
                        {RPCResult::Type::STR, "descriptor", "The descriptor for this multisig"},
                    }
                },
                RPCExamples{
            "\nCreate a multisig address from 2 public keys\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"")
                },
            }.Check(request);

    int required = request.params[0].get_int();

    // Get the public keys
    const UniValue& keys = request.params[1].get_array();
    std::vector<CPubKey> pubkeys;
    for (unsigned int i = 0; i < keys.size(); ++i) {
        if (IsHex(keys[i].get_str()) && (keys[i].get_str().length() == 66 || keys[i].get_str().length() == 130)) {
            pubkeys.push_back(HexToPubKey(keys[i].get_str()));
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid public key: %s\n.", keys[i].get_str()));
        }
    }

    // Get the output type
    OutputType output_type = OutputType::LEGACY;
    if (!request.params[2].isNull()) {
        if (!ParseOutputType(request.params[2].get_str(), output_type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Unknown address type '%s'", request.params[2].get_str()));
        }
    }

    // Construct using pay-to-script-hash:
    FillableSigningProvider keystore;
    CScript inner;
    const CTxDestination dest = AddAndGetMultisigDestination(required, pubkeys, output_type, keystore, inner);

    // Make the descriptor
    std::unique_ptr<Descriptor> descriptor = InferDescriptor(GetScriptForDestination(dest), keystore);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(dest));
    result.pushKV("redeemScript", HexStr(inner.begin(), inner.end()));
    result.pushKV("descriptor", descriptor->ToString());

    return result;
}

UniValue getdescriptorinfo(const JSONRPCRequest& request)
{
            RPCHelpMan{"getdescriptorinfo",
            {"\nAnalyses a descriptor.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
            },
            RPCResult{
                RPCResult::Type::OBJ, "", "",
                {
                    {RPCResult::Type::STR, "descriptor", "The descriptor in canonical form, without private keys"},
                    {RPCResult::Type::STR, "checksum", "The checksum for the input descriptor"},
                    {RPCResult::Type::BOOL, "isrange", "Whether the descriptor is ranged"},
                    {RPCResult::Type::BOOL, "issolvable", "Whether the descriptor is solvable"},
                    {RPCResult::Type::BOOL, "hasprivatekeys", "Whether the input descriptor contained at least one private key"},
                }
            },
            RPCExamples{
                "Analyse a descriptor\n" +
                HelpExampleCli("getdescriptorinfo", "\"wpkh([d34db33f/84h/0h/0h]0279be667ef9dcbbac55a06295Ce870b07029Bfcdb2dce28d959f2815b16f81798)\"")
            }}.Check(request);

    RPCTypeCheck(request.params, {UniValue::VSTR});

    FlatSigningProvider provider;
    std::string error;
    auto desc = Parse(request.params[0].get_str(), provider, error);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("descriptor", desc->ToString());
    result.pushKV("checksum", GetDescriptorChecksum(request.params[0].get_str()));
    result.pushKV("isrange", desc->IsRange());
    result.pushKV("issolvable", desc->IsSolvable());
    result.pushKV("hasprivatekeys", provider.keys.size() > 0);
    return result;
}

UniValue deriveaddresses(const JSONRPCRequest& request)
{
            RPCHelpMan{"deriveaddresses",
            {"\nDerives one or more addresses corresponding to an output descriptor.\n"
            "Examples of output descriptors are:\n"
            "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
            "    wpkh(<pubkey>)                       Native segwit P2PKH outputs for the given pubkey\n"
            "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
            "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
            "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an xpub/xprv optionally followed by one\n"
            "or more path elements separated by \"/\", where \"h\" represents a hardened child key.\n"
            "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n"},
            {
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor."},
                {"range", RPCArg::Type::RANGE, RPCArg::Optional::OMITTED_NAMED_ARG, "If a ranged descriptor is used, this specifies the end or the range (in [begin,end] notation) to derive."},
            },
            RPCResult{
                RPCResult::Type::ARR, "", "",
                {
                    {RPCResult::Type::STR, "address", "the derived addresses"},
                }
            },
            RPCExamples{
                "First three native segwit receive addresses\n" +
                HelpExampleCli("deriveaddresses", "\"wpkh([d34db33f/84h/0h/0h]xpub6DJ2dNUysrn5Vt36jH2KLBT2i1auw1tTSSomg8PhqNiUtx8QX2SvC9nrHu81fT41fvDUnhMjEzQgXnQjKEu3oaqMSzhSrHMxyyoEAmUHQbY/0/*)#cjjspncu\" \"[0,2]\"")
            }}.Check(request);

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValueType()}); // Range argument is checked later
    const std::string desc_str = request.params[0].get_str();

    int64_t range_begin = 0;
    int64_t range_end = 0;

    if (request.params.size() >= 2 && !request.params[1].isNull()) {
        std::tie(range_begin, range_end) = ParseDescriptorRange(request.params[1]);
    }

    FlatSigningProvider key_provider;
    std::string error;
    auto desc = Parse(desc_str, key_provider, error, /* require_checksum = */ true);
    if (!desc) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    if (!desc->IsRange() && request.params.size() > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range should not be specified for an un-ranged descriptor");
    }

    if (desc->IsRange() && request.params.size() == 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Range must be specified for a ranged descriptor");
    }

    UniValue addresses(UniValue::VARR);

    for (int i = range_begin; i <= range_end; ++i) {
        FlatSigningProvider provider;
        std::vector<CScript> scripts;
        if (!desc->Expand(i, key_provider, scripts, provider)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys"));
        }

        for (const CScript &script : scripts) {
            CTxDestination dest;
            if (!ExtractDestination(script, dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Descriptor does not have a corresponding address"));
            }

            addresses.push_back(EncodeDestination(dest));
        }
    }

    // This should not be possible, but an assert seems overkill:
    if (addresses.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, "Unexpected empty result");
    }

    return addresses;
}

static UniValue verifymessage(const JSONRPCRequest& request)
{
            RPCHelpMan{"verifymessage",
                "\nVerify a signed message\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The bitcoin address to use for the signature."},
                    {"signature", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature provided by the signer in base 64 encoding (see signmessage)."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message that was signed."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "If the signature is verified or not."
                },
                RPCExamples{
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"")
                },
            }.Check(request);

    LOCK(cs_main);

    std::string strAddress  = request.params[0].get_str();
    std::string strSign     = request.params[1].get_str();
    std::string strMessage  = request.params[2].get_str();

    switch (MessageVerify(strAddress, strSign, strMessage)) {
    case MessageVerificationResult::ERR_INVALID_ADDRESS:
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");
    case MessageVerificationResult::ERR_ADDRESS_NO_KEY:
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");
    case MessageVerificationResult::ERR_MALFORMED_SIGNATURE:
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");
    case MessageVerificationResult::ERR_PUBKEY_NOT_RECOVERED:
    case MessageVerificationResult::ERR_NOT_SIGNED:
        return false;
    case MessageVerificationResult::OK:
        return true;
    }

    return false;
}

static UniValue signmessagewithprivkey(const JSONRPCRequest& request)
{
            RPCHelpMan{"signmessagewithprivkey",
                "\nSign a message with the private key of an address\n",
                {
                    {"privkey", RPCArg::Type::STR, RPCArg::Optional::NO, "The private key to sign the message with."},
                    {"message", RPCArg::Type::STR, RPCArg::Optional::NO, "The message to create a signature of."},
                },
                RPCResult{
                    RPCResult::Type::STR, "signature", "The signature of the message encoded in base 64"
                },
                RPCExamples{
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
                },
            }.Check(request);

    std::string strPrivkey = request.params[0].get_str();
    std::string strMessage = request.params[1].get_str();

    CKey key = DecodeSecret(strPrivkey);
    if (!key.IsValid()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    }

    std::string signature;

    if (!MessageSign(key, strMessage, signature)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");
    }

    return signature;
}

static UniValue setmocktime(const JSONRPCRequest& request)
{
            RPCHelpMan{"setmocktime",
                "\nSet the local time to given timestamp (-regtest only)\n",
                {
                    {"timestamp", RPCArg::Type::NUM, RPCArg::Optional::NO, UNIX_EPOCH_TIME + "\n"
            "   Pass 0 to go back to using the system time."},
                },
                RPCResults{},
                RPCExamples{""},
            }.Check(request);

    if (!Params().IsMockableChain()) {
        throw std::runtime_error("setmocktime is for regression testing (-regtest mode) only");
    }

    // For now, don't change mocktime if we're in the middle of validation, as
    // this could have an effect on mempool time-based eviction, as well as
    // IsCurrentForFeeEstimation() and IsInitialBlockDownload().
    // TODO: figure out the right way to synchronize around mocktime, and
    // ensure all call sites of GetTime() are accessing this safely.
    LOCK(cs_main);

    RPCTypeCheck(request.params, {UniValue::VNUM});
    SetMockTime(request.params[0].get_int64());

    return NullUniValue;
}

static UniValue mockscheduler(const JSONRPCRequest& request)
{
    RPCHelpMan{"mockscheduler",
        "\nBump the scheduler into the future (-regtest only)\n",
        {
            {"delta_time", RPCArg::Type::NUM, RPCArg::Optional::NO, "Number of seconds to forward the scheduler into the future." },
        },
        RPCResults{},
        RPCExamples{""},
    }.Check(request);

    if (!Params().IsMockableChain()) {
        throw std::runtime_error("mockscheduler is for regression testing (-regtest mode) only");
    }

    // check params are valid values
    RPCTypeCheck(request.params, {UniValue::VNUM});
    int64_t delta_seconds = request.params[0].get_int64();
    if ((delta_seconds <= 0) || (delta_seconds > 3600)) {
        throw std::runtime_error("delta_time must be between 1 and 3600 seconds (1 hr)");
    }

    // protect against null pointer dereference
    CHECK_NONFATAL(g_rpc_node);
    CHECK_NONFATAL(g_rpc_node->scheduler);
    g_rpc_node->scheduler->MockForward(boost::chrono::seconds(delta_seconds));

    return NullUniValue;
}

static UniValue RPCLockedMemoryInfo()
{
    LockedPool::Stats stats = LockedPoolManager::Instance().stats();
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("used", uint64_t(stats.used));
    obj.pushKV("free", uint64_t(stats.free));
    obj.pushKV("total", uint64_t(stats.total));
    obj.pushKV("locked", uint64_t(stats.locked));
    obj.pushKV("chunks_used", uint64_t(stats.chunks_used));
    obj.pushKV("chunks_free", uint64_t(stats.chunks_free));
    return obj;
}

#ifdef HAVE_MALLOC_INFO
static std::string RPCMallocInfo()
{
    char *ptr = nullptr;
    size_t size = 0;
    FILE *f = open_memstream(&ptr, &size);
    if (f) {
        malloc_info(0, f);
        fclose(f);
        if (ptr) {
            std::string rv(ptr, size);
            free(ptr);
            return rv;
        }
    }
    return "";
}
#endif

static UniValue getmemoryinfo(const JSONRPCRequest& request)
{
    /* Please, avoid using the word "pool" here in the RPC interface or help,
     * as users will undoubtedly confuse it with the other "memory pool"
     */
            RPCHelpMan{"getmemoryinfo",
                "Returns an object containing information about memory usage.\n",
                {
                    {"mode", RPCArg::Type::STR, /* default */ "\"stats\"", "determines what kind of information is returned.\n"
            "  - \"stats\" returns general statistics about memory usage in the daemon.\n"
            "  - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc 2.10+)."},
                },
                {
                    RPCResult{"mode \"stats\"",
                        RPCResult::Type::OBJ, "", "",
                        {
                            {RPCResult::Type::OBJ, "locked", "Information about locked memory manager",
                            {
                                {RPCResult::Type::NUM, "used", "Number of bytes used"},
                                {RPCResult::Type::NUM, "free", "Number of bytes available in current arenas"},
                                {RPCResult::Type::NUM, "total", "Total number of bytes managed"},
                                {RPCResult::Type::NUM, "locked", "Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk."},
                                {RPCResult::Type::NUM, "chunks_used", "Number allocated chunks"},
                                {RPCResult::Type::NUM, "chunks_free", "Number unused chunks"},
                            }},
                        }
                    },
                    RPCResult{"mode \"mallocinfo\"",
                        RPCResult::Type::STR, "", "\"<malloc version=\"1\">...\""
                    },
                },
                RPCExamples{
                    HelpExampleCli("getmemoryinfo", "")
            + HelpExampleRpc("getmemoryinfo", "")
                },
            }.Check(request);

    std::string mode = request.params[0].isNull() ? "stats" : request.params[0].get_str();
    if (mode == "stats") {
        UniValue obj(UniValue::VOBJ);
        obj.pushKV("locked", RPCLockedMemoryInfo());
        return obj;
    } else if (mode == "mallocinfo") {
#ifdef HAVE_MALLOC_INFO
        return RPCMallocInfo();
#else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "mallocinfo is only available when compiled with glibc 2.10+");
#endif
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown mode " + mode);
    }
}

static void EnableOrDisableLogCategories(UniValue cats, bool enable) {
    cats = cats.get_array();
    for (unsigned int i = 0; i < cats.size(); ++i) {
        std::string cat = cats[i].get_str();

        bool success;
        if (enable) {
            success = LogInstance().EnableCategory(cat);
        } else {
            success = LogInstance().DisableCategory(cat);
        }

        if (!success) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown logging category " + cat);
        }
    }
}

UniValue logging(const JSONRPCRequest& request)
{
            RPCHelpMan{"logging",
            "Gets and sets the logging configuration.\n"
            "When called without an argument, returns the list of categories with status that are currently being debug logged or not.\n"
            "When called with arguments, adds or removes categories from debug logging and return the lists above.\n"
            "The arguments are evaluated in order \"include\", \"exclude\".\n"
            "If an item is both included and excluded, it will thus end up being excluded.\n"
            "The valid logging categories are: " + ListLogCategories() + "\n"
            "In addition, the following are available as category names with special meanings:\n"
            "  - \"all\",  \"1\" : represent all logging categories.\n"
            "  - \"none\", \"0\" : even if other logging categories are specified, ignore all of them.\n"
            ,
                {
                    {"include", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "A json array of categories to add debug logging",
                        {
                            {"include_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                    {"exclude", RPCArg::Type::ARR, RPCArg::Optional::OMITTED_NAMED_ARG, "A json array of categories to remove debug logging",
                        {
                            {"exclude_category", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "the valid logging category"},
                        }},
                },
                RPCResult{
                    RPCResult::Type::OBJ_DYN, "", "keys are the logging categories, and values indicates its status",
                    {
                        {RPCResult::Type::BOOL, "category", "if being debug logged or not. false:inactive, true:active"},
                    }
                },
                RPCExamples{
                    HelpExampleCli("logging", "\"[\\\"all\\\"]\" \"[\\\"http\\\"]\"")
            + HelpExampleRpc("logging", "[\"all\"], [\"libevent\"]")
                },
            }.Check(request);

    uint32_t original_log_categories = LogInstance().GetCategoryMask();
    if (request.params[0].isArray()) {
        EnableOrDisableLogCategories(request.params[0], true);
    }
    if (request.params[1].isArray()) {
        EnableOrDisableLogCategories(request.params[1], false);
    }
    uint32_t updated_log_categories = LogInstance().GetCategoryMask();
    uint32_t changed_log_categories = original_log_categories ^ updated_log_categories;

    // Update libevent logging if BCLog::LIBEVENT has changed.
    // If the library version doesn't allow it, UpdateHTTPServerLogging() returns false,
    // in which case we should clear the BCLog::LIBEVENT flag.
    // Throw an error if the user has explicitly asked to change only the libevent
    // flag and it failed.
    if (changed_log_categories & BCLog::LIBEVENT) {
        if (!UpdateHTTPServerLogging(LogInstance().WillLogCategory(BCLog::LIBEVENT))) {
            LogInstance().DisableCategory(BCLog::LIBEVENT);
            if (changed_log_categories == BCLog::LIBEVENT) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "libevent logging cannot be updated when using libevent before v2.1.1.");
            }
        }
    }

    UniValue result(UniValue::VOBJ);
    std::vector<CLogCategoryActive> vLogCatActive = ListActiveLogCategories();
    for (const auto& logCatActive : vLogCatActive) {
        result.pushKV(logCatActive.category, logCatActive.active);
    }

    return result;
}

static UniValue echo(const JSONRPCRequest& request)
{
    if (request.fHelp)
        throw std::runtime_error(
            RPCHelpMan{"echo|echojson ...",
                "\nSimply echo back the input arguments. This command is for testing.\n"
                "\nIt will return an internal bug report when exactly 100 arguments are passed.\n"
                "\nThe difference between echo and echojson is that echojson has argument conversion enabled in the client-side table in "
                "the CLI and the GUI. There is no server-side difference.",
                {},
                RPCResults{},
                RPCExamples{""},
            }.ToString()
        );

    CHECK_NONFATAL(request.params.size() != 100);

    return request.params;
}

//
// ELEMENTS CALLS

UniValue tweakfedpegscript(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            RPCHelpMan{"tweakfedpegscript",
                "\nReturns a tweaked fedpegscript.\n",
                {
                    {"claim_script", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Script to tweak the fedpegscript with. For example obtained as a result of getpeginaddress."},
                    {"fedpegscript", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED_NAMED_ARG, "Fedpegscript to be used with the claim_script. By default this is the current fedpegscript."},
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::STR_HEX, "script", "The fedpegscript tweaked with claim_script"},
                        {RPCResult::Type::STR, "address", "The address corresponding to the tweaked fedpegscript"},
                    }
                },
                RPCExamples{""},
            }.ToString());

    if (!IsHex(request.params[0].get_str())) {
        throw JSONRPCError(RPC_TYPE_ERROR, "the first argument must be a hex string");
    }

    CScript fedpegscript = GetValidFedpegScripts(::ChainActive().Tip(), Params().GetConsensus(), true /* nextblock_validation */).front().second;

    if (!request.params[1].isNull()) {
        if (IsHex(request.params[1].get_str())) {
            std::vector<unsigned char> fedpeg_byte = ParseHex(request.params[1].get_str());
            fedpegscript = CScript(fedpeg_byte.begin(), fedpeg_byte.end());
        } else {
            throw JSONRPCError(RPC_TYPE_ERROR, "fedpegscript must be a hex string");
        }
    }

    std::vector<unsigned char> scriptData = ParseHex(request.params[0].get_str());
    CScript claim_script = CScript(scriptData.begin(), scriptData.end());

    CScript tweaked_script = calculate_contract(fedpegscript, claim_script);
    CTxDestination parent_addr(ScriptHash(GetScriptForWitness(tweaked_script)));

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("script", HexStr(tweaked_script));
    ret.pushKV("address", EncodeParentDestination(parent_addr));

    return ret;
}

UniValue FormatPAKList(CPAKList &paklist) {
    UniValue paklist_value(UniValue::VOBJ);
    std::vector<std::vector<unsigned char> > offline_keys;
    std::vector<std::vector<unsigned char> > online_keys;
    paklist.ToBytes(offline_keys, online_keys);

    UniValue retOnline(UniValue::VARR);
    UniValue retOffline(UniValue::VARR);
    for (unsigned int i = 0; i < offline_keys.size(); i++) {
        retOffline.push_back(HexStr(offline_keys[i]));
        retOnline.push_back(HexStr(online_keys[i]));

    }
    paklist_value.pushKV("online", retOnline);
    paklist_value.pushKV("offline", retOffline);
    paklist_value.pushKV("reject", retOffline.empty());
    return paklist_value;
}

UniValue getpakinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            RPCHelpMan{"getpakinfo",
                "\nReturns relevant pegout authorization key (PAK) information about this node, both from blockchain data.\n",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ARR, "block_paklist", "The PAK list loaded from latest epoch",
                        {
                            {RPCResult::Type::ELISION, "", ""}
                        }},
                    }
                },
                RPCExamples{""},
            }.ToString());

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);
    CPAKList paklist = GetActivePAKList(::ChainActive().Tip(), Params().GetConsensus());
    ret.pushKV("block_paklist", FormatPAKList(paklist));

    return ret;
}

UniValue calcfastmerkleroot(const JSONRPCRequest& request)
{
    std::vector<uint256> leaves;
    for (const UniValue& leaf : request.params[0].get_array().getValues()) {
        uint256 l;
        l.SetHex(leaf.get_str());
        leaves.push_back(l);
    }

    uint256 root = ComputeFastMerkleRoot(leaves);

    UniValue ret(UniValue::VOBJ);
    ret.setStr(root.GetHex());
    return ret;
}

UniValue dumpassetlabels(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            RPCHelpMan{"dumpassetlabels",
                "\nLists all known asset id/label pairs in this wallet. This list can be modified with `-assetdir` configuration argument.\n",
                {},
                RPCResults{},
                RPCExamples{
                    HelpExampleCli("dumpassetlabels", "" )
            + HelpExampleRpc("dumpassetlabels", "" )
                },
            }.ToString());

    UniValue obj(UniValue::VOBJ);
    for (const auto& as : gAssetsDir.GetKnownAssets()) {
        obj.pushKV(gAssetsDir.GetLabel(as), as.GetHex());
    }
    return obj;
}

class BlindingPubkeyAdderVisitor : public boost::static_visitor<>
{
public:
    CPubKey blind_key;
    explicit BlindingPubkeyAdderVisitor(const CPubKey& blind_key_in) : blind_key(blind_key_in) {}

    void operator()(const CNoDestination& dest) const {}

    void operator()(PKHash& keyID) const
    {
        keyID.blinding_pubkey = blind_key;
    }

    void operator()(ScriptHash& scriptID) const
    {
        scriptID.blinding_pubkey = blind_key;
    }

    void operator()(WitnessV0KeyHash& id) const
    {
        id.blinding_pubkey = blind_key;
    }

    void operator()(WitnessV0ScriptHash& id) const
    {
        id.blinding_pubkey = blind_key;
    }

    void operator()(WitnessUnknown& id) const
    {
        id.blinding_pubkey = blind_key;
    }

    void operator()(const NullData& id) const {}
};


UniValue createblindedaddress(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            RPCHelpMan{"createblindedaddress",
                "\nCreates a blinded address using the provided blinding key.\n",
                {
                    {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The unblinded address to be blinded."},
                    {"blinding_key", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The blinding public key. This can be obtained for a given address using `validateaddress`."},
                },
                RPCResult{
                    RPCResult::Type::STR, "blinded_address", "The blinded address"
                },
                RPCExamples{
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createblindedaddress", "HEZk3iQi1jC49bxUriTtynnXgWWWdAYx16 ec09811118b6febfa5ebe68642e5091c418fbace07e655da26b4a845a691fc2d") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createblindedaddress", "HEZk3iQi1jC49bxUriTtynnXgWWWdAYx16, ec09811118b6febfa5ebe68642e5091c418fbace07e655da26b4a845a691fc2d")
                },
            }.ToString());

    CTxDestination address = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(address)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address or script");
    }
    if (IsBlindDestination(address)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Not an unblinded address");
    }

    if (!IsHex(request.params[1].get_str())) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid hexadecimal for key");
    }
    std::vector<unsigned char> keydata = ParseHex(request.params[1].get_str());
    if (keydata.size() != 33) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid hexadecimal key length, must be length 66.");
    }

    CPubKey key;
    key.Set(keydata.begin(), keydata.end());

    // Append blinding key and return
    boost::apply_visitor(BlindingPubkeyAdderVisitor(key), address);
    return EncodeDestination(address);
}


// END ELEMENTS CALLS
//

// clang-format off

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         argNames
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getmemoryinfo",          &getmemoryinfo,          {"mode"} },
    { "control",            "logging",                &logging,                {"include", "exclude"}},
    { "util",               "validateaddress",        &validateaddress,        {"address"} },
    { "util",               "createmultisig",         &createmultisig,         {"nrequired","keys","address_type"} },
    { "util",               "deriveaddresses",        &deriveaddresses,        {"descriptor", "range"} },
    { "util",               "getdescriptorinfo",      &getdescriptorinfo,      {"descriptor"} },
    { "util",               "verifymessage",          &verifymessage,          {"address","signature","message"} },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, {"privkey","message"} },
    // ELEMENTS:
    { "util",               "getpakinfo",             &getpakinfo,             {}},
    { "util",               "tweakfedpegscript",      &tweakfedpegscript,      {"claim_script", "fedpegscript"} },
    { "util",               "createblindedaddress",   &createblindedaddress,   {"address", "blinding_key"}},
    { "util",               "dumpassetlabels",        &dumpassetlabels,        {}},
    { "hidden",             "calcfastmerkleroot",     &calcfastmerkleroot,     {"leaves"} },

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            {"timestamp"}},
    { "hidden",             "mockscheduler",          &mockscheduler,          {"delta_time"}},
    { "hidden",             "echo",                   &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
    { "hidden",             "echojson",               &echo,                   {"arg0","arg1","arg2","arg3","arg4","arg5","arg6","arg7","arg8","arg9"}},
};
// clang-format on

void RegisterMiscRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
