// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



#include "base58.h"
#include "bitcoinrpc.h"
#include "init.h"
#include "net.h"
#include "uint256.h"
#include "wallet.h"
#include "script.h"

#include <stdint.h>
#include <string>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>

#include <boost/assign/list_of.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include "json/json_spirit_utils.h"
#include "json/json_spirit_value.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;

void ScriptPubKeyToJSON(const CScript& scriptPubKey, Object& out, bool fIncludeHex)
{
    txnouttype type;
    vector<CTxDestination> addresses;
    int nRequired;

    out.push_back(Pair("asm", scriptPubKey.ToString()));
    if (fIncludeHex)
        out.push_back(Pair("hex", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired))
    {
        out.push_back(Pair("type", GetTxnOutputType(type)));
        return;
    }

    out.push_back(Pair("reqSigs", nRequired));
    out.push_back(Pair("type", GetTxnOutputType(type)));

    Array a;
    BOOST_FOREACH(const CTxDestination& addr, addresses)
        a.push_back(CBitcoinAddress(addr).ToString());
    out.push_back(Pair("addresses", a));
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, Object& entry)
{
    entry.push_back(Pair("txid", tx.GetHash().GetHex()));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("locktime", (boost::int64_t)tx.nLockTime));
    Array vin;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        Object in;
        if (tx.IsCoinBase())
            in.push_back(Pair("coinbase", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
        else
        {
            in.push_back(Pair("txid", txin.prevout.hash.GetHex()));
            in.push_back(Pair("vout", (boost::int64_t)txin.prevout.n));
            Object o;
            o.push_back(Pair("asm", txin.scriptSig.ToString()));
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("sequence", (boost::int64_t)txin.nSequence));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    Array vout;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        Object out;
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (boost::int64_t)i));
        Object o;
        ScriptPubKeyToJSON(txout.scriptPubKey, o, false);
        out.push_back(Pair("scriptPubKey", o));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if (hashBlock != 0)
    {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
        {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex))
            {
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", (boost::int64_t)pindex->nTime));
                entry.push_back(Pair("blocktime", (boost::int64_t)pindex->nTime));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

Value getrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getrawtransaction \"txid\" ( verbose )\n"
            "\nReturn the raw transaction data.\n"
            "\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
            "If verbose is non-zero, returns an Object with information about 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

            "\nResult (if verbose is not set or set to 0):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

            "\nResult (if verbose > 0):\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) \n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n      (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [              (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in btc\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"bitcoinaddress\"        (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
        );

    
    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    string strHex = HexStr(ssTx.begin(), ssTx.end());

    if (!fVerbose)
        return strHex;

    Object result;
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

Value listunspent(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "listunspent ( minconf maxconf  [\"address\",...] )\n"
            "\nReturns array of unspent transaction outputs\n"
            "with between minconf and maxconf (inclusive) confirmations.\n"
            "Optionally filter to only include txouts paid to specified addresses.\n"
            "Results are an array of Objects, each of which has:\n"
            "{txid, vout, scriptPubKey, amount, confirmations}\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmationsi to filter\n"
            "2. maxconf          (numeric, optional, default=9999999) The maximum confirmations to filter\n"
            "3. \"addresses\"    (string) A json array of bitcoin addresses to filter\n"
            "    [\n"
            "      \"address\"   (string) bitcoin address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"txid\" : \"txid\",        (string) the transaction id \n"
            "    \"vout\" : n,               (numeric) the vout value\n"
            "    \"address\" : \"address\",  (string) the bitcoin address\n"
            "    \"account\" : \"account\",  (string) The associated account, or \"\" for the default account\n"
            "    \"scriptPubKey\" : \"key\", (string) the script key\n"
            "    \"amount\" : x.xxx,         (numeric) the transaction amount in btc\n"
            "    \"confirmations\" : n       (numeric) The number of confirmations\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n"
            + HelpExampleCli("listunspent", "")
            + HelpExampleCli("listunspent", "6 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
            + HelpExampleRpc("listunspent", "6, 9999999 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
        );

    RPCTypeCheck(params, list_of(int_type)(int_type)(array_type));

    int nMinDepth = 1;
    if (params.size() > 0)
        nMinDepth = params[0].get_int();

    int nMaxDepth = 9999999;
    if (params.size() > 1)
        nMaxDepth = params[1].get_int();

    set<CBitcoinAddress> setAddress;
    if (params.size() > 2)
    {
        Array inputs = params[2].get_array();
        BOOST_FOREACH(Value& input, inputs)
        {
            CBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+input.get_str());
            if (setAddress.count(address))
                throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.get_str());
           setAddress.insert(address);
        }
    }

    Array results;
    vector<COutput> vecOutputs;
    assert(pwalletMain != NULL);
    pwalletMain->AvailableCoins(vecOutputs, false);
    BOOST_FOREACH(const COutput& out, vecOutputs)
    {
        if (out.nDepth < nMinDepth || out.nDepth > nMaxDepth)
            continue;

        if (setAddress.size())
        {
            CTxDestination address;
            if (!ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
                continue;

            if (!setAddress.count(address))
                continue;
        }

        int64_t nValue = out.tx->vout[out.i].nValue;
        const CScript& pk = out.tx->vout[out.i].scriptPubKey;
        Object entry;
        entry.push_back(Pair("txid", out.tx->GetHash().GetHex()));
        entry.push_back(Pair("vout", out.i));
        CTxDestination address;
        if (ExtractDestination(out.tx->vout[out.i].scriptPubKey, address))
        {
            entry.push_back(Pair("address", CBitcoinAddress(address).ToString()));
            if (pwalletMain->mapAddressBook.count(address))
                entry.push_back(Pair("account", pwalletMain->mapAddressBook[address].name));
        }
        entry.push_back(Pair("scriptPubKey", HexStr(pk.begin(), pk.end())));
        if (pk.IsPayToScriptHash())
        {
            CTxDestination address;
            if (ExtractDestination(pk, address))
            {
                const CScriptID& hash = boost::get<const CScriptID&>(address);
                CScript redeemScript;
                if (pwalletMain->GetCScript(hash, redeemScript))
                    entry.push_back(Pair("redeemScript", HexStr(redeemScript.begin(), redeemScript.end())));
            }
        }
        entry.push_back(Pair("amount",ValueFromAmount(nValue)));
        entry.push_back(Pair("confirmations",out.nDepth));
        results.push_back(entry);
    }

    return results;
}

Value createrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,...}\n"
            "\nCreate a transaction spending the given inputs and sending to the given addresses.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"transactions\"        (string, required) A json array of json objects\n"
            "     [\n"
            "       {\n"
            "         \"txid\":\"id\",  (string, required) The transaction id\n"
            "         \"vout\":n        (numeric, required) The output number\n"
            "       }\n"
            "       ,...\n"
            "     ]\n"
            "2. \"addresses\"           (string, required) a json object with addresses as keys and amounts as values\n"
            "    {\n"
            "      \"address\": x.xxx   (numeric, required) The key is the bitcoin address, the value is the btc amount\n"
            "      ,...\n"
            "    }\n"

            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n"

            "\nExamples\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"{\\\"address\\\":0.01}\"")
            + HelpExampleRpc("createrawtransaction", "\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"{\\\"address\\\":0.01}\"")
        );

    RPCTypeCheck(params, list_of(array_type)(obj_type));

    Array inputs = params[0].get_array();
    Object sendTo = params[1].get_obj();

    CTransaction rawTx;

    BOOST_FOREACH(const Value& input, inputs)
    {
        const Object& o = input.get_obj();

        uint256 txid = ParseHashO(o, "txid");

        const Value& vout_v = find_value(o, "vout");
        if (vout_v.type() != int_type)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.get_int();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout must be positive");

        CTxIn in(COutPoint(txid, nOutput));
        rawTx.vin.push_back(in);
    }

    set<CBitcoinAddress> setAddress;
    BOOST_FOREACH(const Pair& s, sendTo)
    {
        CBitcoinAddress address(s.name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Bitcoin address: ")+s.name_);

        if (setAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+s.name_);
        setAddress.insert(address);

        CScript scriptPubKey;
        scriptPubKey.SetDestination(address.Get());
        int64_t nAmount = AmountFromValue(s.value_);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;
    return HexStr(ss.begin(), ss.end());
}

Value decoderawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction hex string\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"data\",       (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",        (string) The transaction id (same as provided)\n"
            "  \"version\" : n,          (numeric) The version\n"
            "  \"locktime\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [               (array of json objects)\n"
            "     {\n"
            "       \"txid\": \"id\",    (string) The transaction id\n"
            "       \"vout\": n,         (numeric) The output number\n"
            "       \"scriptSig\": {     (json object) The script\n"
            "         \"asm\": \"asm\",  (string) asm\n"
            "         \"hex\": \"hex\"   (string) hex\n"
            "       },\n"
            "       \"sequence\": n     (numeric) The script sequence number\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [             (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,            (numeric) The value in btc\n"
            "       \"n\" : n,                    (numeric) index\n"
            "       \"scriptPubKey\" : {          (json object)\n"
            "         \"asm\" : \"asm\",          (string) the asm\n"
            "         \"hex\" : \"hex\",          (string) the hex\n"
            "         \"reqSigs\" : n,            (numeric) The required sigs\n"
            "         \"type\" : \"pubkeyhash\",  (string) The type, eg 'pubkeyhash'\n"
            "         \"addresses\" : [           (json array of string)\n"
            "           \"12tvKAXCxZjSmdNbao16dKXC8tRWfcF5oc\"   (string) bitcoin address\n"
            "           ,...\n"
            "         ]\n"
            "       }\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
        );

    vector<unsigned char> txData(ParseHexV(params[0], "argument"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    Object result;
    TxToJSON(tx, 0, result);

    return result;
}

Value decodescript(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "decodescript \"hex\"\n"
            "\nDecode a hex-encoded script.\n"
            "\nArguments:\n"
            "1. \"hex\"     (string) the hex encoded script\n"
            "\nResult:\n"
            "{\n"
            "  \"asm\":\"asm\",   (string) Script public key\n"
            "  \"hex\":\"hex\",   (string) hex encoded public key\n"
            "  \"type\":\"type\", (string) The output type\n"
            "  \"reqSigs\": n,    (numeric) The required signatures\n"
            "  \"addresses\": [   (json array of string)\n"
            "     \"address\"     (string) bitcoin address\n"
            "     ,...\n"
            "  ],\n"
            "  \"p2sh\",\"address\" (string) script address\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodescript", "\"hexstring\"")
            + HelpExampleRpc("decodescript", "\"hexstring\"")
        );

    RPCTypeCheck(params, list_of(str_type));

    Object r;
    CScript script;
    if (params[0].get_str().size() > 0){
        vector<unsigned char> scriptData(ParseHexV(params[0], "argument"));
        script = CScript(scriptData.begin(), scriptData.end());
    } else {
        // Empty scripts are valid
    }
    ScriptPubKeyToJSON(script, r, false);

    r.push_back(Pair("p2sh", CBitcoinAddress(script.GetID()).ToString()));
    return r;
}

Value signrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 4)
        throw runtime_error(
            "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
            + HelpRequiringPassphrase() + "\n"

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
            "2. \"prevtxs\"       (string, optional) An json array of previous dependent transaction outputs\n"
            "     [               (json array of json objects)\n"
            "       {\n"
            "         \"txid\":\"id\",             (string, required) The transaction id\n"
            "         \"vout\":n,                  (numeric, required) The output number\n"
            "         \"scriptPubKey\": \"hex\",   (string, required) script key\n"
            "         \"redeemScript\": \"hex\"    (string, required) redeem script\n"
            "       }\n"
            "       ,...\n"
            "    ]\n"
            "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
            "    [                  (json array of strings)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "4. \"sighashtype\"     (string, optional, default=ALL) The signature has type. Must be one of\n"
            "       \"ALL\"\n"
            "       \"NONE\"\n"
            "       \"SINGLE\"\n"
            "       \"ALL|ANYONECANPAY\"\n"
            "       \"NONE|ANYONECANPAY\"\n"
            "       \"SINGLE|ANYONECANPAY\"\n"

            "\nResult:\n"
            "{\n"
            "  \"hex\": \"value\",   (string) The raw transaction with signature(s) (hex-encoded string)\n"
            "  \"complete\": n       (numeric) if transaction has a complete set of signature (0 if not)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("signrawtransaction", "\"myhex\"")
        );

    RPCTypeCheck(params, list_of(str_type)(array_type)(array_type)(str_type), true);

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    vector<CTransaction> txVariants;
    while (!ssData.empty())
    {
        try {
            CTransaction tx;
            ssData >> tx;
            txVariants.push_back(tx);
        }
        catch (std::exception &e) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    if (txVariants.empty())
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Missing transaction");

    // mergedTx will end up with all the signatures; it
    // starts as a clone of the rawtx:
    CTransaction mergedTx(txVariants[0]);
    bool fComplete = true;

    // Fetch previous transactions (inputs):
    CCoinsView viewDummy;
    CCoinsViewCache view(viewDummy);
    {
        LOCK(mempool.cs);
        CCoinsViewCache &viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(viewChain, mempool);
        view.SetBackend(viewMempool); // temporarily switch cache backend to db+mempool view

        BOOST_FOREACH(const CTxIn& txin, mergedTx.vin) {
            const uint256& prevHash = txin.prevout.hash;
            CCoins coins;
            view.GetCoins(prevHash, coins); // this is certainly allowed to fail
        }

        view.SetBackend(viewDummy); // switch back to avoid locking mempool for too long
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && params[2].type() != null_type)
    {
        fGivenKeys = true;
        Array keys = params[2].get_array();
        BOOST_FOREACH(Value k, keys)
        {
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            tempKeystore.AddKey(key);
        }
    }
    else
        EnsureWalletIsUnlocked();

    // Add previous txouts given in the RPC call:
    if (params.size() > 1 && params[1].type() != null_type)
    {
        Array prevTxs = params[1].get_array();
        BOOST_FOREACH(Value& p, prevTxs)
        {
            if (p.type() != obj_type)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");

            Object prevOut = p.get_obj();

            RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type));

            uint256 txid = ParseHashO(prevOut, "txid");

            int nOut = find_value(prevOut, "vout").get_int();
            if (nOut < 0)
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout must be positive");

            vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            CCoins coins;
            if (view.GetCoins(txid, coins)) {
                if (coins.IsAvailable(nOut) && coins.vout[nOut].scriptPubKey != scriptPubKey) {
                    string err("Previous output scriptPubKey mismatch:\n");
                    err = err + coins.vout[nOut].scriptPubKey.ToString() + "\nvs:\n"+
                        scriptPubKey.ToString();
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                // what todo if txid is known, but the actual output isn't?
            }
            if ((unsigned int)nOut >= coins.vout.size())
                coins.vout.resize(nOut+1);
            coins.vout[nOut].scriptPubKey = scriptPubKey;
            coins.vout[nOut].nValue = 0; // we don't know the actual output value
            view.SetCoins(txid, coins);

            // if redeemScript given and not using the local wallet (private keys
            // given), add redeemScript to the tempKeystore so it can be signed:
            if (fGivenKeys && scriptPubKey.IsPayToScriptHash())
            {
                RPCTypeCheck(prevOut, map_list_of("txid", str_type)("vout", int_type)("scriptPubKey", str_type)("redeemScript",str_type));
                Value v = find_value(prevOut, "redeemScript");
                if (!(v == Value::null))
                {
                    vector<unsigned char> rsData(ParseHexV(v, "redeemScript"));
                    CScript redeemScript(rsData.begin(), rsData.end());
                    tempKeystore.AddCScript(redeemScript);
                }
            }
        }
    }

    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);

    int nHashType = SIGHASH_ALL;
    if (params.size() > 3 && params[3].type() != null_type)
    {
        static map<string, int> mapSigHashValues =
            boost::assign::map_list_of
            (string("ALL"), int(SIGHASH_ALL))
            (string("ALL|ANYONECANPAY"), int(SIGHASH_ALL|SIGHASH_ANYONECANPAY))
            (string("NONE"), int(SIGHASH_NONE))
            (string("NONE|ANYONECANPAY"), int(SIGHASH_NONE|SIGHASH_ANYONECANPAY))
            (string("SINGLE"), int(SIGHASH_SINGLE))
            (string("SINGLE|ANYONECANPAY"), int(SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
            ;
        string strHashType = params[3].get_str();
        if (mapSigHashValues.count(strHashType))
            nHashType = mapSigHashValues[strHashType];
        else
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid sighash param");
    }

    bool fHashSingle = ((nHashType & ~SIGHASH_ANYONECANPAY) == SIGHASH_SINGLE);

    // Sign what we can:
    for (unsigned int i = 0; i < mergedTx.vin.size(); i++)
    {
        CTxIn& txin = mergedTx.vin[i];
        CCoins coins;
        if (!view.GetCoins(txin.prevout.hash, coins) || !coins.IsAvailable(txin.prevout.n))
        {
            fComplete = false;
            continue;
        }
        const CScript& prevPubKey = coins.vout[txin.prevout.n].scriptPubKey;

        txin.scriptSig.clear();
        // Only sign SIGHASH_SINGLE if there's a corresponding output:
        if (!fHashSingle || (i < mergedTx.vout.size()))
            SignSignature(keystore, prevPubKey, mergedTx, i, nHashType);

        // ... and merge in other signatures:
        BOOST_FOREACH(const CTransaction& txv, txVariants)
        {
            txin.scriptSig = CombineSignatures(prevPubKey, mergedTx, i, txin.scriptSig, txv.vin[i].scriptSig);
        }
        if (!VerifyScript(txin.scriptSig, prevPubKey, mergedTx, i, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC, 0))
            fComplete = false;
    }

    Object result;
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << mergedTx;
    result.push_back(Pair("hex", HexStr(ssTx.begin(), ssTx.end())));
    result.push_back(Pair("complete", fComplete));

    return result;
}

Value sendrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "sendrawtransaction \"hexstring\" ( allowhighfees )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":0.01}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
        );


    // parse hex string from parameter
    vector<unsigned char> txData(ParseHexV(params[0], "parameter"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;

    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    // deserialize binary data stream
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    uint256 hashTx = tx.GetHash();

    bool fHave = false;
    CCoinsViewCache &view = *pcoinsTip;
    CCoins existingCoins;
    {
        fHave = view.GetCoins(hashTx, existingCoins);
        if (!fHave) {
            // push to local node
            CValidationState state;
            if (!AcceptToMemoryPool(mempool, state, tx, false, NULL, !fOverrideFees))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX rejected"); // TODO: report validation state
        }
    }
    if (fHave) {
        if (existingCoins.nHeight < 1000000000)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "transaction already in block chain");
        // Not in block, but already in the memory pool; will drop
        // through to re-relay it.
    } else {
        SyncWithWallets(hashTx, tx, NULL);
    }
    RelayTransaction(tx, hashTx);

    return hashTx.GetHex();
}

vector<char *> getsignaturevalues(CTransaction tx, unsigned int input, bool needk) {
    
    //Prepare error message for convinence
    std::ostringstream errmsg;
    errmsg << tx.GetHash().ToString() << ":" <<  input << " - ";
    
    //Store results to return
    vector<char *> values;
    
    if (input >= tx.vin.size()) {
        errmsg << " the input does not exist.";
        throw runtime_error(errmsg.str());
    }
    
    
    unsigned int i = input;
    vector<vector<unsigned char> > stack;
    
    //Fill stack with scriptsig + pub key
    EvalScript(stack, tx.vin[i].scriptSig, tx, i, false, 0);
    
    CTxIn& txin = tx.vin[i];
    CTransaction txprev;
    uint256 hashBlock = 0;
    if (!GetTransaction(txin.prevout.hash, txprev, hashBlock, true)) {
        errmsg << " cannot find this transaction. Remember to use -txindex.";
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg.str());
    }

    const CTxOut& txout = txprev.vout[txin.prevout.n];
    
    vector<unsigned char> vchSig;
    vector<unsigned char> vchPubKey;
    vchSig= stack.front();
    vchPubKey = stack.back();
    
    std::string t(vchSig.begin(), vchSig.end());
    
    //Evaluate signature and public key
    EvalScript(stack, txout.scriptPubKey, tx, i, false, 0);
    
    
    //Get script instructions
    CScript scriptSig(tx.vin[i].scriptSig.begin(), tx.vin[i].scriptSig.end());
    CScript scriptPubKey(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
    
    //Remove signature from the script - cannot sign a signature
    scriptPubKey.FindAndDelete(CScript(vchSig));
    
    //Get signature hash
    uint256 sighash = SignatureHash(scriptPubKey, tx, i, 1);
    
    //Time to get the R & S values
    ECDSA_SIG *sig = ECDSA_SIG_new();
    const unsigned char *sigbuf = &vchSig[0];
    d2i_ECDSA_SIG(&sig, &sigbuf, vchSig.size()
                  );
    
    // Lets make sure we found a signature (this implementation relies on script-to-pubkey-hash.. can be extended to multi-sig and p2sh)
    if(sig == NULL) {
        errmsg << " signature cannot be found.";
        
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg.str());
    }
    
    char *r = BN_bn2dec(sig->r);
    char *s = BN_bn2dec(sig->s);
    
    values.push_back(r);
    values.push_back(s);
    
    if(needk) {

        //Get private key
        const CKeyStore& keystore = *pwalletMain;
        CKey key;
        CKeyID keyID = CPubKey(vchPubKey).GetID();
        if(!keystore.GetKey(keyID, key)) {
            errmsg << " could not fetch the private key.";
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, errmsg.str());
        } else {
            char *k = key.GetK((unsigned char*)&sighash, sizeof(sighash), r, s);
            values.push_back(k);
        }
    }
    
    return values;
}

void hashlength(SHA_CTX *sha, size_t l)
{
    unsigned char b[2];
    
    OPENSSL_assert(l <= 0xffff);
    b[0] = l >> 8;
    b[1] = l&0xff;
    SHA1_Update(sha, b, 2);
}


void hashstring(SHA_CTX *sha, const char *string)
{
    size_t l = strlen(string);
    
    hashlength(sha, l);
    SHA1_Update(sha, string, l);
}

void hashbn(SHA_CTX *sha, const BIGNUM *bn)
{
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = (unsigned char*) malloc(l);
    
    hashlength(sha, l);
    BN_bn2bin(bn, bin);
    SHA1_Update(sha, bin, l);
    OPENSSL_free(bin);
}

void hashpoint(const EC_GROUP *group, SHA_CTX *sha, const EC_POINT *point)
{

    BIGNUM *bn = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    //Convert EC_POINT to number
    EC_POINT_point2bn(group, point, POINT_CONVERSION_UNCOMPRESSED, bn, ctx);
    
    //Get size of EC_POINT
    size_t l = BN_num_bytes(bn);
    unsigned char *bin = (unsigned char*) malloc(l);
    
    //Create hash for a given point
    hashlength(sha, l);
    
    BN_bn2bin(bn, bin);

    SHA1_Update(sha, bin, l);

    OPENSSL_free(bin);
}

Value calculateSharedKey(char *k, char *x, char *y)
{
    /*
     * Using our secret 'k' and Bob's (x,y) co-ordinates
     * we are going to generate a shared secret using the formula:
     * ---> k . (x',y') = (x'',y'')
     *
     */
    BIGNUM *alice_k = NULL;
    BIGNUM *bob_x = NULL;
    BIGNUM *bob_y = NULL;
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *bob_point = NULL;
    EC_POINT *result_point = NULL;
    BIGNUM *result_x = BN_new();
    BIGNUM *result_y = BN_new();
    
    //Converting alice and bob's values to OpenSSL bignums
    BN_dec2bn(&alice_k, k);
    BN_dec2bn(&bob_x, x);
    BN_dec2bn(&bob_y, y);
    
    //Sort out the EC environment
    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group;
    group = EC_KEY_get0_group(pkey);
    
    //Lets make sure we are using compressed co-ordinates
    if(BN_is_zero(bob_y) || BN_is_one(bob_y)) {
        
        //Set bob's point on the curve
        bob_point = EC_POINT_new(group);
        EC_POINT_set_compressed_coordinates_GFp(group, bob_point,
                                                bob_x,
                                                atoi(y), NULL);
        
        result_point = EC_POINT_new(group);
        
        //Scalar multiplication with Alice's k and Bob's point on the curve
        EC_POINT_mul(group, result_point, NULL, bob_point, alice_k, ctx);
        
        //Lets get the results
        EC_POINT_get_affine_coordinates_GFp(group, result_point, result_x, result_y, ctx);
        
        unsigned char md[SHA_DIGEST_LENGTH];
        SHA_CTX sha;
        
        SHA1_Init(&sha);
        
        hashbn(&sha, result_x);
        
        BIGNUM *h = BN_new();
        
        SHA1_Final(md, &sha);
        BN_bin2bn(md, SHA_DIGEST_LENGTH, h);
        
        return BN_bn2dec(h);
        
    }
    
    return 0;
    
}


/* h=hash(g, g^v, g^x, name) */
void zkp_hash(const EC_GROUP *group, char *p, char *a, char *b, char *g, char *order, BIGNUM *h, EC_POINT *gw, EC_POINT *gv,  BIGNUM *x_coordinate)
{
    unsigned char md[SHA_DIGEST_LENGTH];
    SHA_CTX sha;
    
    SHA1_Init(&sha);
    
    std::stringstream ss;
    ss << p << a << b << g << order;
    
    std::string s = ss.str();
    
    char *full = new char[s.length() + 1];
    strcpy(full, s.c_str());
    
    //Get hash for each parameter and combine them
    hashstring(&sha, full);
    
    hashpoint(group, &sha, gw);
    
    hashbn(&sha, x_coordinate);
    
    hashpoint(group, &sha, gv);

    SHA1_Final(md, &sha);
    BN_bin2bn(md, SHA_DIGEST_LENGTH, h);
}

/*
 * Prove knowledge of x
 * Note that p->gx has already been calculated
 */
BIGNUM *generate_zkp(const EC_GROUP *group, char *p, char *a, char *b, const EC_POINT *g, BIGNUM *v, EC_POINT *gv, BIGNUM *w, EC_POINT *gw, BIGNUM *k, BIGNUM * x_coordinate, BIGNUM *order, BIGNUM *h, const char *txid, BN_CTX *ctx)
{
    BIGNUM *t = BN_new();
    BIGNUM *temp_s = BN_new();
    BIGNUM *bn_g = BN_new();
    BIGNUM *bn_order = BN_new();

    EC_GROUP_get_order(group, bn_order, ctx);
    
    EC_POINT_point2bn(group, g, POINT_CONVERSION_UNCOMPRESSED, bn_g, ctx);
    
    char *char_g = BN_bn2dec(bn_g);
    char *char_order = BN_bn2dec(bn_order);
    
    /* h=hash... */
    zkp_hash(group, p, a, b, char_g, char_order, h, gw, gv, x_coordinate);
    
    /* s = v - w*h */
    BN_mod_mul(t, w, h, order, ctx);
    
    BN_mod_sub(temp_s, v, t, order, ctx);
    
    
    
    return temp_s;

}

int verify_zkp(const EC_GROUP *group, char *p, char *a, char *b, const EC_POINT *g, EC_POINT *gw, EC_POINT *gv, BIGNUM *x_coordinate, BIGNUM *s, const char *txid,
                      BN_CTX *ctx)
{
    BIGNUM *h = BN_new();
    BIGNUM *bn_g = BN_new();
    BIGNUM *bn_order = BN_new();
    
    EC_GROUP_get_order(group, bn_order, ctx);
    
    EC_POINT_point2bn(group, g, POINT_CONVERSION_UNCOMPRESSED, bn_g, ctx);
    
    char *char_g = BN_bn2dec(bn_g);
    char *char_order = BN_bn2dec(bn_order);
    
    EC_POINT *t1 = EC_POINT_new(group);
    EC_POINT *t2 = EC_POINT_new(group);
    EC_POINT *t3 = EC_POINT_new(group);
    int ret = 0;
    
    zkp_hash(group, p, a, b, char_g, char_order, h, gw, gv, x_coordinate);
    
    //Remember, we are proving knowledge of r - lets make sure rG is not a point at infinity
    if(EC_POINT_is_at_infinity(group, gw) == 1) {
        return ret;
    }
    
    //Next lets make sure the x and y co-ordinates of rG are in Fq
    
    //Lets make sure its on the curve
    if(EC_POINT_is_on_curve(group, gw, ctx) == 0) {
        return ret;
    }
    
    //std::cout << "H:" << BN_bn2dec(h) << endl;
    
    /* t1 = g^s */
    EC_POINT_mul(group, t1, NULL, g, s, ctx);
    
    /* t2 = (g^w)^h = g^{hr} */
    EC_POINT_mul(group, t2, NULL, gw, h, ctx);
    
    
    //BN_mod_exp(t2, p->gx, h, ctx->p.p, ctx->ctx);
    /* t3 = t1 + t2 = g^{hr} * g^b = g^{hr+b} = g^w (allegedly) */
    EC_POINT_add(group, t3, t1, t2, ctx);
    
    /* verify t3 == g^v */
    if(EC_POINT_cmp(group, t3, gv, ctx) == 0) {
        ret = 1;
    }

    
    return ret;
}

// Look at the example function ZKPTest
char * getyaksecret(char * p_gw, char *p_gv, char *p_gk, char *p_s, char *p_k, char *p_w, char *p_txid, char *x_coordinate) {
    
    Value res;
    
    //Expecting: g^v, g^w, g^k, s, txid, r, k
    BIGNUM *bn_gw = BN_new();
    BIGNUM *bn_gv = BN_new();
    BIGNUM *bn_gk = BN_new();
    BIGNUM *s = BN_new();
    BIGNUM *w = BN_new();
    BIGNUM *k = BN_new();
    BIGNUM *order = BN_new();
    BIGNUM *bn_x_coordinate = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    //Sort out the EC environment
    EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group;
    group = EC_KEY_get0_group(pkey);
    
    //Get generator
    const EC_POINT *g = EC_GROUP_get0_generator(group);
    
    //Get points ready
    EC_POINT *gw = EC_POINT_new(group);
    EC_POINT *gv = EC_POINT_new(group);
    EC_POINT *gk = EC_POINT_new(group);
    
    //Get all parameters
    BN_dec2bn(&bn_gw, p_gw);
    BN_dec2bn(&bn_gv,  p_gv);
    BN_dec2bn(&bn_gk, p_gk);
    BN_dec2bn(&s, p_s);
    BN_dec2bn(&k,  p_k);
    BN_dec2bn(&w, p_w);
    BN_dec2bn(&bn_x_coordinate, x_coordinate);
    
    //Convert BIGNUM to EC_POINT
    EC_POINT_bn2point(group, bn_gw, gw, ctx);
    EC_POINT_bn2point(group, bn_gv, gv, ctx);
    EC_POINT_bn2point(group, bn_gk, gk, ctx);
    
    //Get curve details for zero knowledge proof
    BIGNUM *p = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    
    EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
    
    char *char_p = BN_bn2dec(p);
    char *char_a = BN_bn2dec(a);
    char *char_b = BN_bn2dec(b);

    //Verify ZKP provided
    if(verify_zkp(group, char_p, char_a, char_b, g, gw, gv, bn_x_coordinate, s, p_txid, ctx)) {
        
        //Prepare to start generating shared secret
        EC_POINT *t1 = EC_POINT_new(group);
        BIGNUM *t2 = BN_new();
        EC_POINT *t3 = EC_POINT_new(group);
        
        //t1 = (g^v' . g^k');
        EC_POINT_add(group, t1, gw, gk, ctx);
        
        //t2 = w+k
        BN_mod_add(t2, w, k, order, ctx);
        
        //t3 = (g^v' . g^k')
        EC_POINT_mul(group, t3, NULL, t1, t2, ctx);
        
        BIGNUM *x1 = BN_new();
        BIGNUM *y1 = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, t3, x1, y1, ctx);
        
        unsigned char md[SHA_DIGEST_LENGTH];
        SHA_CTX sha;
        
        SHA1_Init(&sha);
        
        hashbn(&sha, x1);
        
        BIGNUM *fin = BN_new();
        
        SHA1_Final(md, &sha);
        BN_bin2bn(md, SHA_DIGEST_LENGTH, fin);
        
        return BN_bn2dec(fin);
    } else {
    
        throw runtime_error("Zero knowledge proof provided by your partner was not valid");
    }
    
}

// Look at the example function ZKPTest
vector<char *> getyakzkp(char *txid_a, char *a_input, char *txid_b, char *b_input, int print) {
    
    Value res;

    vector<char *> results;
    
    //Assume first input of transaction
    unsigned int first_input = 0;
    first_input = atoi(a_input);
    unsigned int second_input = 0;
    second_input = atoi(a_input);
        
    //Get transaction ID from parameter
    uint256 hash = ParseHashV(txid_a, "parameter 1");
    uint256 hash_b = ParseHashV(txid_b, "parameter 2");
    
    //Find transaction in client
    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    
    //Returns r,s, optional: k
    vector<char *> first_tx = getsignaturevalues(tx, first_input, true);
    
    //Find transaction in client
    CTransaction tx_b;
    hashBlock = 0;
    if (!GetTransaction(hash_b, tx_b, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    
    
    //Returns r,s, optional: k
    vector<char *> second_tx = getsignaturevalues(tx_b, second_input, false);
    
    //Do we have K?
    if(first_tx.size() == 3) {
        
        //Sort out the EC environment
        EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
        const EC_GROUP *group;
        group = EC_KEY_get0_group(pkey);
        
        //Get generator
        const EC_POINT *g = EC_GROUP_get0_generator(group);
        
        //Get order
        BN_CTX *ctx = BN_CTX_new();
        BIGNUM *order = BN_new();
        EC_GROUP_get_order(group, order, ctx);
        
        //Get K
        BIGNUM *k = BN_new();
        BN_dec2bn(&k, first_tx[2]);

        //Get g^k
        EC_POINT *gk = EC_POINT_new(group);
        
        EC_POINT_mul(group, gk, k, NULL, NULL, ctx);
        
        /*
         * Get our estimated public key (x,+).
         */
        
        BIGNUM *estimated_r = BN_new();
        
        char *compressed_y = "1";
        
        BN_dec2bn(&estimated_r,first_tx[0]);

        
        EC_POINT *estimated_compressed = EC_POINT_new(group);
        EC_POINT_set_compressed_coordinates_GFp(group, estimated_compressed,
                                                estimated_r,
                                                atoi(compressed_y), NULL);
 
        BIGNUM *actual_y = BN_new();
        BIGNUM *actual_x = BN_new();
        BIGNUM *estimated_y = BN_new();
        BIGNUM *estimated_x = BN_new();
        EC_POINT_get_affine_coordinates_GFp(group, estimated_compressed, estimated_x, estimated_y, ctx);
        EC_POINT_get_affine_coordinates_GFp(group, gk, actual_x, actual_y, ctx);
        
        //If they are different - means default gk is Map(x,+) - we want Map(x,-)
        if(BN_cmp(estimated_y, actual_y) == 0) {
            //No worries TODO: Fix
        } else {
            BN_set_negative(k, 1);
            
            gk = estimated_compressed;
        }
    
        /*
         * Let's get an estimated public key for Bob
         */
        
        BIGNUM *r_b = BN_new();
        BN_dec2bn(&r_b, second_tx[0]);
        
        EC_POINT *bob_estimated_compressed = EC_POINT_new(group);
        EC_POINT_set_compressed_coordinates_GFp(group, bob_estimated_compressed,
                                                r_b,
                                                atoi(compressed_y), NULL);
        
        BIGNUM *partner_gk = BN_new();
        EC_POINT_point2bn(group, bob_estimated_compressed, POINT_CONVERSION_UNCOMPRESSED, partner_gk, ctx);
        
        //Get curve details for zero knowledge proof
        BIGNUM *p = BN_new();
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        
        EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
        
        char *char_p = BN_bn2dec(p);
        char *char_a = BN_bn2dec(a);
        char *char_b = BN_bn2dec(b);
        
        /*
         * NOW START THE PROTOCOL
         */
        
        //Generate random v and w
        BIGNUM *w = BN_new();
        BN_rand_range(w, order);
        
        BIGNUM *v = BN_new();
        BN_rand_range(v, order);
        
        //Get g^v and g^w
        EC_POINT *gw = EC_POINT_new(group);
        EC_POINT_mul(group, gw, w, NULL, NULL, ctx);
        
        EC_POINT *gv = EC_POINT_new(group);
        EC_POINT_mul(group, gv, v, NULL, NULL, ctx);
        
        //Get h and s
        BIGNUM *s = BN_new();
        BIGNUM *h = BN_new();
        
        //Create zero knowledge proof
        s = generate_zkp(group, char_p, char_a, char_b, g, v, gv, w, gw, k, estimated_r, order, h, hash.ToString().c_str(), ctx);

        BIGNUM *bn_gw = BN_new();
        BIGNUM *bn_gv = BN_new();
        BIGNUM *bn_gk = BN_new();
        
        EC_POINT_point2bn(group, gw, POINT_CONVERSION_COMPRESSED, bn_gw, ctx);
        EC_POINT_point2bn(group, gv, POINT_CONVERSION_COMPRESSED, bn_gv, ctx);
        EC_POINT_point2bn(group, gk, POINT_CONVERSION_COMPRESSED, bn_gk, ctx);
    
        results.push_back(BN_bn2dec(bn_gw)); //to prove little 'w'
        results.push_back(BN_bn2dec(bn_gv)); //random factor in zkp
        results.push_back(BN_bn2dec(s)); //zkp
        results.push_back(BN_bn2dec(k)); //my secret
        results.push_back(BN_bn2dec(w)); //my little 'w' from zkp
        results.push_back(BN_bn2dec(partner_gk));
        results.push_back(BN_bn2dec(estimated_r));
    
        
        return results;
        
    }
    
    throw runtime_error("Your wallet does not have the private key.");
}

Value zkptest (const Array& params, bool fHelp) {
    vector<char *> alice_zkp;
    vector<char *> bob_zkp;
    vector<char *> alice_gets_secret;
    vector<char *> bob_gets_secret;
    
    /* 
     * These are hard-coded transaction ID's... 
     * You will NEED to change these to ID's which are also in
     * your wallet... Just demonstrates how to do the YAK protocol.
     */
    alice_zkp = getyakzkp("2dac21b624821f6a0c41ec030ed5b03a10e4bb9df2627d16f84dbe364b709647", "0", "348abac7317f5afb8af32c54d3504c53cc973948322cb5be301e8ca47bc8de85", "0", 1);
    bob_zkp = getyakzkp("348abac7317f5afb8af32c54d3504c53cc973948322cb5be301e8ca47bc8de85", "0", "2dac21b624821f6a0c41ec030ed5b03a10e4bb9df2627d16f84dbe364b709647", "0", 0);
    
    /* Expecting to be returned:
    * [0] = g^w
    * [1] = g^v
    * [2] = s
    * [3] = k
    * [4] = w
    * [5] = partners compressed key
    * [6] = x co-ordinate from sig
    *
    */
    return getyaksecret(bob_zkp[0], bob_zkp[1], alice_zkp[5], bob_zkp[2], alice_zkp[3], alice_zkp[4], "348abac7317f5afb8af32c54d3504c53cc973948322cb5be301e8ca47bc8de85", bob_zkp[6]);
}

Value getdiffiesecret(const Array& params, bool fHelp)
{
    
    Value res;

	if (fHelp || (params.size() != 2 && params.size() != 4))
		throw runtime_error(
							"getdiffiesecret \"txid txid\"\n"
							"\nGenerate a shared secret between your transaction and a partners.\n"
							"\nArguments:\n"
							"1. \"txid_1\"     (string) Transaction ID \n"
							"2. \"txid_2\"     (string) Transaction ID \n"
							"3. \"input_txid_1\" (optional) Input number for first transaction \n"
							"4. \"input_txid_2\" (optional) Input number for second transaction \n"
							"\nResult: (x,y) co-ordinate"
							);
    
	unsigned int first_input = 0;
	unsigned int second_input = 0;
    
	/*
	 * Two parameters = Diffie
	 * Four parameters = Diffie
	 *
	 */
	if(params.size() == 4) {
		first_input = atoi(params[2].get_str().c_str());
		second_input = atoi(params[3].get_str().c_str());
	}
    
    
	//Get first transaction
	uint256 hash = ParseHashV(params[0], "parameter 1");
    
	CTransaction tx;
	uint256 hashBlock = 0;
	if (!GetTransaction(hash, tx, hashBlock, true))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    
	//Returns r,s, optional: k
	vector<char *> first_tx = getsignaturevalues(tx, first_input, true);
    
	//Get second transaction
	hash = ParseHashV(params[1], "parameter 2");
    
	if (!GetTransaction(hash, tx, hashBlock, true))
		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");
    
	//Returns r,s, optional: k
	vector<char *> second_tx = getsignaturevalues(tx, second_input, false);
    
	if(first_tx.size() == 3) {
		res = calculateSharedKey(first_tx[2], second_tx[0], "0");
	} else if(second_tx.size() == 3) {
		res = calculateSharedKey(second_tx[2], first_tx[0], "0");
	}

    return res;
}

