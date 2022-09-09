// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018 The Verus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script_ext.h"

using namespace std;

bool CScriptExt::IsPayToScriptHash(CScriptID *scriptID) const
{
    if (((CScript *)this)->IsPayToScriptHash())
    {
        *scriptID = CScriptID(uint160(std::vector<unsigned char>(this->begin() + 2, this->end() - 1)));
        return true;
    }
    return false;
}

// P2PKH script, adds to whatever is already in the script (for example CLTV)
const CScriptExt &CScriptExt::AddPayToPubKeyHash(const CKeyID &key) const
{
    *((CScript *)this) << OP_DUP;
    *((CScript *)this) << OP_HASH160;
    *((CScript *)this) << ToByteVector(key);
    *((CScript *)this) << OP_EQUALVERIFY;
    *((CScript *)this) << OP_CHECKSIG;
    return *this;
}

// push data into an op_return script with an opret type indicator, fails if the op_return is too large
const CScriptExt &CScriptExt::OpReturnScript(const vector<unsigned char> &data, unsigned char opretType) const
{
    ((CScript *)this)->clear();
    if (data.size() < CScript::MAX_SCRIPT_ELEMENT_SIZE)
    {
        vector<unsigned char> scratch = vector<unsigned char>(data);
        scratch.insert(scratch.begin(), opretType);
        *((CScript *)this) << OP_RETURN;
        *((CScript *)this) << scratch;
    }
    return *this;
}

// push data into an op_return script with an opret type indicator, fails if the op_return is too large
const CScriptExt &CScriptExt::OpReturnScript(const CScript &src, unsigned char opretType) const
{
    vector<unsigned char> vch = vector<unsigned char>(src.begin(), src.end());
    return OpReturnScript(vch, opretType);
}

// P2SH script, adds to whatever is already in the script (for example CLTV)
const CScriptExt &CScriptExt::PayToScriptHash(const CScriptID &scriptID) const
{
    ((CScript *)this)->clear();
    *((CScript *)this) << OP_HASH160;
    *((CScript *)this) << ToByteVector(scriptID);
    *((CScript *)this) << OP_EQUAL;
    return *this;
}

// P2SH script, adds to whatever is already in the script (for example CLTV)
const CScriptExt &CScriptExt::AddCheckLockTimeVerify(int64_t unlocktime) const
{
    if (unlocktime > 0)
    {
        *((CScript *)this) << CScriptNum::serialize(unlocktime);
        *((CScript *)this) << OP_CHECKLOCKTIMEVERIFY;
        *((CScript *)this) << OP_DROP;
        return *this;
    }
    return *this;
}

// combined CLTV script and P2PKH
const CScriptExt &CScriptExt::TimeLockSpend(const CKeyID &key, int64_t unlocktime) const
{
    ((CScript *)this)->clear();
    this->AddCheckLockTimeVerify(unlocktime);
    this->AddPayToPubKeyHash(key);
    return *this;
}

/**
 * provide destination extraction for non-standard, timelocked coinbase transactions
 * as well as other transactions
 */
bool CScriptExt::ExtractVoutDestination(const CTransaction& tx, int32_t voutNum, CTxDestination& addressRet)
{
    if (tx.vout.size() <= voutNum)
        return false;

    CScriptID scriptHash;
    CScriptExt spk = tx.vout[voutNum].scriptPubKey;

    // if this is a timelocked transaction, get the destination behind the time lock
    if (tx.IsCoinBase() && voutNum == 0 &&
        spk.IsPayToScriptHash(&scriptHash) &&
        tx.vout.back().scriptPubKey.IsOpReturn())
    {
        opcodetype op;
        std::vector<uint8_t> opretData = std::vector<uint8_t>();
        CScript::const_iterator it = tx.vout.back().scriptPubKey.begin() + 1;
        if (tx.vout.back().scriptPubKey.GetOp2(it, op, &opretData))
        {
            if (opretData.size() > 0 && opretData[0] == OPRETTYPE_TIMELOCK)
            {
                int64_t unlocktime;
                CScriptExt se = CScriptExt(&opretData[1], &opretData[opretData.size()]);

                if (CScriptID(se) == scriptHash &&
                    se.IsCheckLockTimeVerify(&unlocktime))
                {
                    spk = se;
                }
            }
        }
    }
    return ExtractDestination(spk, addressRet);
}

