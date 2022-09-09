// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "wallet/wallet.h"

#include "asyncrpcqueue.h"
#include "checkpoints.h"
#include "coincontrol.h"
#include "core_io.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "consensus/consensus.h"
#include "init.h"
#include "key_io.h"
#include "main.h"
#include "mmr.h"
#include "net.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "script/script.h"
#include "script/sign.h"
#include "timedata.h"
#include "utilmoneystr.h"
#include "zcash/Note.hpp"
#include "crypter.h"
#include "coins.h"
#include "wallet/asyncrpcoperation_saplingconsolidation.h"
#include "wallet/asyncrpcoperation_sweeptoaddress.h"
#include <zcash/address/zip32.h>
#include "cc/StakeGuard.h"
#include "pbaas/identity.h"
#include "pbaas/pbaas.h"

#include <assert.h>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

using namespace std;
using namespace libzcash;

/**
 * Settings
 */
CFeeRate payTxFee(DEFAULT_TRANSACTION_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;
unsigned int nTxConfirmTarget = DEFAULT_TX_CONFIRM_TARGET;
bool bSpendZeroConfChange = true;
bool fSendFreeTransactions = false;
bool fPayAtLeastCustomFee = true;
#include "komodo_defs.h"

extern int32_t USE_EXTERNAL_PUBKEY;
extern std::string NOTARY_PUBKEY;
extern int32_t KOMODO_EXCHANGEWALLET;
extern char ASSETCHAINS_SYMBOL[KOMODO_ASSETCHAIN_MAXLEN];
extern uint160 ASSETCHAINS_CHAINID;
extern int32_t VERUS_MIN_STAKEAGE;
CBlockIndex *komodo_chainactive(int32_t height);
extern std::string DONATION_PUBKEY;
extern BlockMap mapBlockIndex;

/**
 * Fees smaller than this (in satoshi) are considered zero fee (for transaction creation)
 * Override with -mintxfee
 */
CFeeRate CWallet::minTxFee = CFeeRate(1000);

/** @defgroup mapWallet
 *
 * @{
 */

struct CompareValueOnly
{
    bool operator()(const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t1,
                    const pair<CAmount, pair<const CWalletTx*, unsigned int> >& t2) const
    {
        return t1.first < t2.first;
    }
};

class CompareValueMap
{
public:
    CCurrencyValueMap totalTargetValues;
    CompareValueMap() {}
    CompareValueMap(const CCurrencyValueMap &targetValues) : totalTargetValues(targetValues) {}
    bool CompareMaps(const CCurrencyValueMap &m1,
                     const CCurrencyValueMap &m2) const
    {
        // if we have a target to compare against,
        // check to see if one leaves less change after meeting the target
        CCurrencyValueMap m1LeftOver = totalTargetValues.SubtractToZero(m1).CanonicalMap();
        CCurrencyValueMap m2LeftOver = totalTargetValues.SubtractToZero(m2).CanonicalMap();
        if (m1LeftOver == CCurrencyValueMap())
        {
            if (m2LeftOver != CCurrencyValueMap())
            {
                return false;
            }
        }
        else if (m2LeftOver == CCurrencyValueMap())
        {
            return true;
        }
        if (totalTargetValues.valueMap.size())
        {
            CCurrencyValueMap leftover1 = m1.SubtractToZero(totalTargetValues);
            CCurrencyValueMap leftover2 = m2.SubtractToZero(totalTargetValues);

            if (leftover1 < leftover2 && leftover2 < leftover1)
            {
                if (leftover1.valueMap.size() < leftover2.valueMap.size())
                {
                    return true;
                }
                else if (leftover2.valueMap.size() < leftover1.valueMap.size())
                {
                    return false;
                }
            }
            return leftover1 < leftover2;
        }
        else if (m1 < m2 && m2 < m1)
        {
            // this is used for sorting
            // what we care about most in this case is that we always give the same answer,
            // so, run a repeatable check, regardless of the order of operands. we'd also want
            // to be as close to right as possible.
            CCurrencyValueMap checkMap1 = m1.IntersectingValues(m2);
            CCurrencyValueMap checkMap2;
            // where they intersect, they are empty, no way to know which is less for sorting
            if (!(checkMap2 < checkMap1))
            {
                return false;
            }
            checkMap2 = checkMap1 - m2.IntersectingValues(m1);
            if (!(checkMap2 < checkMap1))
            {
                return false;
            }
            else
            {
                return true;
            }
        }
        return m1 < m2;
    }
};

std::string JSOutPoint::ToString() const
{
    return strprintf("JSOutPoint(%s, %d, %d)", hash.ToString().substr(0,10), js, n);
}

std::string COutput::ToString() const
{
    return strprintf("COutput(%s, %d, %d) [%s]", tx->GetHash().ToString(), i, nDepth, FormatMoney(tx->vout[i].nValue));
}

const CWalletTx* CWallet::GetWalletTx(const uint256& hash) const
{
    LOCK(cs_wallet);
    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(hash);
    if (it == mapWallet.end())
        return NULL;
    return &(it->second);
}

// Generate a new spending key and return its public payment address
libzcash::SproutPaymentAddress CWallet::GenerateNewSproutZKey()
{
    AssertLockHeld(cs_wallet); // mapSproutZKeyMetadata

    auto k = SproutSpendingKey::random();
    auto addr = k.address();

    // Check for collision, even though it is unlikely to ever occur
    if (CCryptoKeyStore::HaveSproutSpendingKey(addr))
        throw std::runtime_error("CWallet::GenerateNewSproutZKey(): Collision detected");

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapSproutZKeyMetadata[addr] = CKeyMetadata(nCreationTime);

    if (!AddSproutZKey(k))
        throw std::runtime_error("CWallet::GenerateNewSproutZKey(): AddSproutZKey failed");
    return addr;
}

// Generate a new Sapling spending key and return its public payment address
SaplingPaymentAddress CWallet::GenerateNewSaplingZKey()
{
    AssertLockHeld(cs_wallet); // mapSaplingZKeyMetadata

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // Try to get the seed
    HDSeed seed;
    if (!GetHDSeed(seed))
        throw std::runtime_error("CWallet::GenerateNewSaplingZKey(): HD seed not found");

    auto m = libzcash::SaplingExtendedSpendingKey::Master(seed);
    uint32_t bip44CoinType = Params().BIP44CoinType();

    // We use a fixed keypath scheme of m/32'/coin_type'/account'
    // Derive m/32'
    auto m_32h = m.Derive(32 | ZIP32_HARDENED_KEY_LIMIT);
    // Derive m/32'/coin_type'
    auto m_32h_cth = m_32h.Derive(bip44CoinType | ZIP32_HARDENED_KEY_LIMIT);

    // Derive account key at next index, skip keys already known to the wallet
    libzcash::SaplingExtendedSpendingKey xsk;
    do
    {
        xsk = m_32h_cth.Derive(hdChain.saplingAccountCounter | ZIP32_HARDENED_KEY_LIMIT);
        metadata.hdKeypath = "m/32'/" + std::to_string(bip44CoinType) + "'/" + std::to_string(hdChain.saplingAccountCounter) + "'";
        metadata.seedFp = hdChain.seedFp;
        // Increment childkey index
        hdChain.saplingAccountCounter++;
    } while (HaveSaplingSpendingKey(xsk.ToXFVK()));

    // Update the chain model in the database
    if (fFileBacked && !CWalletDB(strWalletFile).WriteHDChain(hdChain))
        throw std::runtime_error("CWallet::GenerateNewSaplingZKey(): Writing HD chain model failed");

    auto ivk = xsk.expsk.full_viewing_key().in_viewing_key();
    mapSaplingZKeyMetadata[ivk] = metadata;

    auto addr = xsk.DefaultAddress();
    if (!AddSaplingZKey(xsk, addr)) {
        throw std::runtime_error("CWallet::GenerateNewSaplingZKey(): AddSaplingZKey failed");
    }
    // return default sapling payment address.
    return addr;
}

// Add spending key to keystore 
bool CWallet::AddSaplingZKey(
    const libzcash::SaplingExtendedSpendingKey &sk,
    const libzcash::SaplingPaymentAddress &defaultAddr)
{
    AssertLockHeld(cs_wallet); // mapSaplingZKeyMetadata

    if (!CCryptoKeyStore::AddSaplingSpendingKey(sk)) {
        return false;
    }
    
    if (!fFileBacked) {
        return true;
    }

    if (!IsCrypted()) {
        auto ivk = sk.expsk.full_viewing_key().in_viewing_key();
        return CWalletDB(strWalletFile).WriteSaplingZKey(ivk, sk, mapSaplingZKeyMetadata[ivk]);
    }
    
    return true;
}

// Add payment address -> incoming viewing key map entry
bool CWallet::AddSaplingIncomingViewingKey(
    const libzcash::SaplingIncomingViewingKey &ivk,
    const libzcash::SaplingPaymentAddress &addr)
{
    AssertLockHeld(cs_wallet); // mapSaplingZKeyMetadata

    if (!CCryptoKeyStore::AddSaplingIncomingViewingKey(ivk, addr)) {
        return false;
    }

    if (!fFileBacked) {
        return true;
    }

    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteSaplingPaymentAddress(addr, ivk);
    }

    return true;
}


// Add spending key to keystore and persist to disk
bool CWallet::AddSproutZKey(const libzcash::SproutSpendingKey &key)
{
    AssertLockHeld(cs_wallet); // mapSproutZKeyMetadata
    auto addr = key.address();

    if (!CCryptoKeyStore::AddSproutSpendingKey(key))
        return false;

    // check if we need to remove from viewing keys
    if (HaveSproutViewingKey(addr))
        RemoveSproutViewingKey(key.viewing_key());

    if (!fFileBacked)
        return true;

    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteZKey(addr,
                                                  key,
                                                  mapSproutZKeyMetadata[addr]);
    }
    return true;
}

CPubKey CWallet::GenerateNewKey()
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;
    secret.MakeNewKey(fCompressed);

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed)
        SetMinVersion(FEATURE_COMPRPUBKEY);

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    // Create new metadata
    int64_t nCreationTime = GetTime();
    mapKeyMetadata[pubkey.GetID()] = CKeyMetadata(nCreationTime);
    if (!nTimeFirstKey || nCreationTime < nTimeFirstKey)
        nTimeFirstKey = nCreationTime;

    if (!AddKeyPubKey(secret, pubkey))
        throw std::runtime_error("CWallet::GenerateNewKey(): AddKey failed");
    return pubkey;
}

bool CWallet::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (!CCryptoKeyStore::AddKeyPubKey(secret, pubkey))
        return false;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(pubkey.GetID());
    if (HaveWatchOnly(script))
        RemoveWatchOnly(script);

    if (!fFileBacked)
        return true;
    if (!IsCrypted()) {
        return CWalletDB(strWalletFile).WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    return true;
}

bool CWallet::AddCryptedKey(const CPubKey &vchPubKey,
                            const vector<unsigned char> &vchCryptedSecret)
{

    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return CWalletDB(strWalletFile).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
    return false;
}


bool CWallet::AddCryptedSproutSpendingKey(
    const libzcash::SproutPaymentAddress &address,
    const libzcash::ReceivingKey &rk,
    const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedSproutSpendingKey(address, rk, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption) {
            return pwalletdbEncryption->WriteCryptedZKey(address,
                                                         rk,
                                                         vchCryptedSecret,
                                                         mapSproutZKeyMetadata[address]);
        } else {
            return CWalletDB(strWalletFile).WriteCryptedZKey(address,
                                                             rk,
                                                             vchCryptedSecret,
                                                             mapSproutZKeyMetadata[address]);
        }
    }
    return false;
}

bool CWallet::AddCryptedSaplingSpendingKey(const libzcash::SaplingExtendedFullViewingKey &extfvk,
                                           const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedSaplingSpendingKey(extfvk, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        LOCK(cs_wallet);

        auto addr = EncodePaymentAddress(extfvk.DefaultAddress());
        uint256 sha256addr;
        CSHA256().Write((const unsigned char *)addr.c_str(), addr.length()).Finalize(sha256addr.begin());

        if (pwalletdbEncryption) {
            return pwalletdbEncryption->WriteCryptedSaplingZKey(extfvk,
                                                         sha256addr,
                                                         vchCryptedSecret,
                                                         mapSaplingZKeyMetadata[extfvk.fvk.in_viewing_key()]);
        } else {
            return CWalletDB(strWalletFile).WriteCryptedSaplingZKey(extfvk,
                                                         sha256addr,
                                                         vchCryptedSecret,
                                                         mapSaplingZKeyMetadata[extfvk.fvk.in_viewing_key()]);
        }
    }
    return false;
}

bool CWallet::LoadKeyMetadata(const CPubKey &pubkey, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    if (meta.nCreateTime && (!nTimeFirstKey || meta.nCreateTime < nTimeFirstKey))
        nTimeFirstKey = meta.nCreateTime;

    mapKeyMetadata[pubkey.GetID()] = meta;
    return true;
}

bool CWallet::LoadZKeyMetadata(const SproutPaymentAddress &addr, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapSproutZKeyMetadata
    mapSproutZKeyMetadata[addr] = meta;
    return true;
}

bool CWallet::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

bool CWallet::LoadCryptedZKey(const libzcash::SproutPaymentAddress &addr, const libzcash::ReceivingKey &rk, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedSproutSpendingKey(addr, rk, vchCryptedSecret);
}

bool CWallet::LoadCryptedSaplingZKey(
    const libzcash::SaplingExtendedFullViewingKey &extfvk,
    const std::vector<unsigned char> &vchCryptedSecret)
{
     return CCryptoKeyStore::AddCryptedSaplingSpendingKey(extfvk, vchCryptedSecret);
}

bool CWallet::LoadSaplingZKeyMetadata(const libzcash::SaplingIncomingViewingKey &ivk, const CKeyMetadata &meta)
{
    AssertLockHeld(cs_wallet); // mapSaplingZKeyMetadata
    mapSaplingZKeyMetadata[ivk] = meta;
    return true;
}

bool CWallet::LoadSaplingZKey(const libzcash::SaplingExtendedSpendingKey &key)
{
    return CCryptoKeyStore::AddSaplingSpendingKey(key);
}

bool CWallet::LoadSaplingPaymentAddress(
    const libzcash::SaplingPaymentAddress &addr,
    const libzcash::SaplingIncomingViewingKey &ivk)
{
    return CCryptoKeyStore::AddSaplingIncomingViewingKey(ivk, addr);
}

bool CWallet::LoadZKey(const libzcash::SproutSpendingKey &key)
{
    return CCryptoKeyStore::AddSproutSpendingKey(key);
}

bool CWallet::AddSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    if (!CCryptoKeyStore::AddSproutViewingKey(vk)) {
        return false;
    }
    nTimeFirstKey = 1; // No birthday information for viewing keys.
    if (!fFileBacked) {
        return true;
    }
    return CWalletDB(strWalletFile).WriteSproutViewingKey(vk);
}

bool CWallet::RemoveSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveSproutViewingKey(vk)) {
        return false;
    }
    if (fFileBacked) {
        if (!CWalletDB(strWalletFile).EraseSproutViewingKey(vk)) {
            return false;
        }
    }

    return true;
}

bool CWallet::LoadSproutViewingKey(const libzcash::SproutViewingKey &vk)
{
    return CCryptoKeyStore::AddSproutViewingKey(vk);
}

bool CWallet::AddCScript(const CScript& redeemScript)
{
    // if this is an identity, which we currently need to check, we
    // store the ID as a script in the wallet script storage, but instead of using the
    // hash of the script, we store it under the name ID
    if (!CCryptoKeyStore::AddCScript(redeemScript))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteCScript(ScriptOrIdentityID(redeemScript), redeemScript);
}

bool CWallet::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > CScript::MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptOrIdentityID(redeemScript));
        LogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n",
            __func__, redeemScript.size(), CScript::MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return CCryptoKeyStore::AddCScript(redeemScript);
}

bool CWallet::AddIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    // if this is an identity, which we currently need to check, we
    // store the ID as a script in the wallet script storage, but instead of using the
    // hash of the script, we store it under the name ID
    if (!CCryptoKeyStore::AddIdentity(mapKey, identity))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteIdentity(mapKey, identity);
}

bool CWallet::UpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    // if this is an identity, which we currently need to check, we
    // store the ID as a script in the wallet script storage, but instead of using the
    // hash of the script, we store it under the name ID
    if (!CCryptoKeyStore::UpdateIdentity(mapKey, identity))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteIdentity(mapKey, identity);
}

bool CWallet::AddUpdateIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    // if this is an identity, which we currently need to check, we
    // store the ID as a script in the wallet script storage, but instead of using the
    // hash of the script, we store it under the name ID
    if (!CCryptoKeyStore::AddUpdateIdentity(mapKey, identity))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteIdentity(mapKey, identity);
}

void CWallet::ClearIdentities(uint32_t fromHeight)
{
    if (fFileBacked)
    {
        for (auto &idPair : mapIdentities)
        {
            if (CIdentityMapKey(idPair.first).blockHeight >= fromHeight)
            {
                CWalletDB(strWalletFile).EraseIdentity(idPair.first);
            }
        }    
    }

    CCryptoKeyStore::ClearIdentities(fromHeight);
}

bool CWallet::RemoveIdentity(const CIdentityMapKey &mapKey, const uint256 &txid)
{
    CIdentityMapKey localKey = mapKey;
    std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> toErase;
    if (localKey.blockHeight == 0)
    {
        localKey.blockHeight = INT_MAX;
    }
    if (!GetIdentity(mapKey, localKey, toErase))
    {
        return false;
    }
    if (!txid.IsNull())
    {
        std::pair<CIdentityMapKey, CIdentityMapValue> idEntry;
        for (auto id : toErase)
        {
            if (id.second.txid == txid)
            {
                idEntry = id;
            }
        }
        toErase.clear();
        if (idEntry.first.IsValid() && idEntry.second.IsValid())
        {
            toErase.push_back(idEntry);
        }
    }
    if (!CCryptoKeyStore::RemoveIdentity(mapKey, txid))
        return false;
    if (!fFileBacked)
        return true;

    bool error = false;
    for (auto idPair : toErase)
    {
        error = CWalletDB(strWalletFile).EraseIdentity(idPair.first) ? error : true;
    }    
    return error;
}

bool CWallet::LoadIdentity(const CIdentityMapKey &mapKey, const CIdentityMapValue &identity)
{
    return CCryptoKeyStore::AddUpdateIdentity(mapKey, identity);
}

// returns all key IDs that are destinations for UTXOs in the wallet
std::set<CKeyID> CWallet::GetTransactionDestinationIDs()
{
    std::vector<COutput> vecOutputs;
    std::set<CKeyID> setKeyIDs;

    AvailableCoins(vecOutputs, false, NULL, true, true, true, true);

    for (int i = 0; i < vecOutputs.size(); i++)
    {
        auto &txout = vecOutputs[i];
        txnouttype outType;
        std::vector<CTxDestination> dests;
        int nRequiredSigs;

        if (ExtractDestinations(txout.tx->vout[txout.i].scriptPubKey, outType, dests, nRequiredSigs))
        {
            CScript scriptPubKey;
            if (outType != TX_SCRIPTHASH ||
                (dests.size() &&
                 GetCScript(GetDestinationID(dests[0]), scriptPubKey) &&
                 ExtractDestinations(scriptPubKey, outType, dests, nRequiredSigs)))
            {
                for (auto &dest : dests)
                {
                    if (dest.which() == COptCCParams::ADDRTYPE_PK || dest.which() == COptCCParams::ADDRTYPE_PKH)
                    {
                        setKeyIDs.insert(GetDestinationID(dest));
                    }
                }
            }
        }
    }
    return setKeyIDs;
}

bool CWallet::AddWatchOnly(const CScript &dest)
{
    if (!CCryptoKeyStore::AddWatchOnly(dest))
        return false;
    nTimeFirstKey = 1; // No birthday information for watch-only keys.
    NotifyWatchonlyChanged(true);
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteWatchOnly(dest);
}

bool CWallet::RemoveWatchOnly(const CScript &dest)
{
    AssertLockHeld(cs_wallet);
    if (!CCryptoKeyStore::RemoveWatchOnly(dest))
        return false;
    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (fFileBacked)
        if (!CWalletDB(strWalletFile).EraseWatchOnly(dest))
            return false;

    return true;
}

bool CWallet::LoadWatchOnly(const CScript &dest)
{
    return CCryptoKeyStore::AddWatchOnly(dest);
}

bool CWallet::Unlock(const SecureString& strWalletPassphrase)
{
    CCrypter crypter;
    CKeyingMaterial vMasterKey;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(const MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                continue; // try another master key
            if (CCryptoKeyStore::Unlock(vMasterKey)) {
                // Now that the wallet is decrypted, ensure we have an HD seed.
                // https://github.com/zcash/zcash/issues/3607
                if (!this->HaveHDSeed()) {
                    this->GenerateNewSeed();
                }
                return true;
            }
        }
    }
    return false;
}

bool CWallet::ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase)
{
    bool fWasLocked = IsLocked();

    {
        LOCK(cs_wallet);
        Lock();

        CCrypter crypter;
        CKeyingMaterial vMasterKey;
        BOOST_FOREACH(MasterKeyMap::value_type& pMasterKey, mapMasterKeys)
        {
            if(!crypter.SetKeyFromPassphrase(strOldWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                return false;
            if (!crypter.Decrypt(pMasterKey.second.vchCryptedKey, vMasterKey))
                return false;
            if (CCryptoKeyStore::Unlock(vMasterKey))
            {
                int64_t nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = pMasterKey.second.nDeriveIterations * (100 / ((double)(GetTimeMillis() - nStartTime)));

                nStartTime = GetTimeMillis();
                crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod);
                pMasterKey.second.nDeriveIterations = (pMasterKey.second.nDeriveIterations + pMasterKey.second.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

                if (pMasterKey.second.nDeriveIterations < 25000)
                    pMasterKey.second.nDeriveIterations = 25000;

                LogPrintf("Wallet passphrase changed to an nDeriveIterations of %i\n", pMasterKey.second.nDeriveIterations);

                if (!crypter.SetKeyFromPassphrase(strNewWalletPassphrase, pMasterKey.second.vchSalt, pMasterKey.second.nDeriveIterations, pMasterKey.second.nDerivationMethod))
                    return false;
                if (!crypter.Encrypt(vMasterKey, pMasterKey.second.vchCryptedKey))
                    return false;
                CWalletDB(strWalletFile).WriteMasterKey(pMasterKey.first, pMasterKey.second);
                if (fWasLocked)
                    Lock();
                return true;
            }
        }
    }

    return false;
}

void CWallet::ChainTipAdded(const CBlockIndex *pindex,
                            const CBlock *pblock,
                            SproutMerkleTree sproutTree,
                            SaplingMerkleTree saplingTree)
{
    IncrementNoteWitnesses(pindex, pblock, sproutTree, saplingTree);
    UpdateSaplingNullifierNoteMapForBlock(pblock);
}

void CWallet::ChainTip(const CBlockIndex *pindex, 
                       const CBlock *pblock,
                       SproutMerkleTree sproutTree,
                       SaplingMerkleTree saplingTree, 
                       bool added)
{
    if (added) {
        ChainTipAdded(pindex, pblock, sproutTree, saplingTree);
    } else {
        DecrementNoteWitnesses(pindex);
        UpdateSaplingNullifierNoteMapForBlock(pblock);
    }
}

void CWallet::AddPendingSaplingMigrationTx(const CTransaction& tx) {
    LOCK(cs_wallet);
    pendingSaplingMigrationTxs.push_back(tx);
}

void CWallet::CommitAutomatedTx(const CTransaction& tx) {
  CWalletTx wtx(this, tx);
  CReserveKey reservekey(pwalletMain);
  CommitTransaction(wtx, reservekey);
}

void CWallet::SetBestChain(const CBlockLocator& loc)
{
    CWalletDB walletdb(strWalletFile);
    SetBestChainINTERNAL(walletdb, loc);
}

std::set<std::pair<libzcash::PaymentAddress, uint256>> CWallet::GetNullifiersForAddresses(
        const std::set<libzcash::PaymentAddress> & addresses)
{
    std::set<std::pair<libzcash::PaymentAddress, uint256>> nullifierSet;
    // Sapling ivk -> list of addrs map
    // (There may be more than one diversified address for a given ivk.)
    std::map<libzcash::SaplingIncomingViewingKey, std::vector<libzcash::SaplingPaymentAddress>> ivkMap;
    for (const auto & addr : addresses) {
        auto saplingAddr = boost::get<libzcash::SaplingPaymentAddress>(&addr);
        if (saplingAddr != nullptr) {
            libzcash::SaplingIncomingViewingKey ivk;
            this->GetSaplingIncomingViewingKey(*saplingAddr, ivk);
            ivkMap[ivk].push_back(*saplingAddr);
        }
    }
    for (const auto & txPair : mapWallet) {
        // Sprout
        for (const auto & noteDataPair : txPair.second.mapSproutNoteData) {
            auto & noteData = noteDataPair.second;
            auto & nullifier = noteData.nullifier;
            auto & address = noteData.address;
            if (nullifier && addresses.count(address)) {
                nullifierSet.insert(std::make_pair(address, nullifier.get()));
            }
        }
        // Sapling
        for (const auto & noteDataPair : txPair.second.mapSaplingNoteData) {
            auto & noteData = noteDataPair.second;
            auto & nullifier = noteData.nullifier;
            auto & ivk = noteData.ivk;
            if (nullifier && ivkMap.count(ivk)) {
                for (const auto & addr : ivkMap[ivk]) {
                    nullifierSet.insert(std::make_pair(addr, nullifier.get()));
                }
            }
        }
    }
    return nullifierSet;
}

bool CWallet::IsNoteSproutChange(
        const std::set<std::pair<libzcash::PaymentAddress, uint256>> & nullifierSet,
        const PaymentAddress & address,
        const JSOutPoint & jsop)
{
    // A Note is marked as "change" if the address that received it
    // also spent Notes in the same transaction. This will catch,
    // for instance:
    // - Change created by spending fractions of Notes (because
    //   z_sendmany sends change to the originating z-address).
    // - "Chaining Notes" used to connect JoinSplits together.
    // - Notes created by consolidation transactions (e.g. using
    //   z_mergetoaddress).
    // - Notes sent from one address to itself.
    for (const JSDescription & jsd : mapWallet[jsop.hash].vJoinSplit) {
        for (const uint256 & nullifier : jsd.nullifiers) {
            if (nullifierSet.count(std::make_pair(address, nullifier))) {
                return true;
            }
        }
    }
    return false;
}

bool CWallet::IsNoteSaplingChange(const std::set<std::pair<libzcash::PaymentAddress, uint256>> & nullifierSet,
        const libzcash::PaymentAddress & address,
        const SaplingOutPoint & op)
{
    // A Note is marked as "change" if the address that received it
    // also spent Notes in the same transaction. This will catch,
    // for instance:
    // - Change created by spending fractions of Notes (because
    //   z_sendmany sends change to the originating z-address).
    // - Notes created by consolidation transactions (e.g. using
    //   z_mergetoaddress).
    // - Notes sent from one address to itself.
    for (const SpendDescription &spend : mapWallet[op.hash].vShieldedSpend) {
        if (nullifierSet.count(std::make_pair(address, spend.nullifier))) {
            return true;
        }
    }
    return false;
}
bool CWallet::SetWalletCrypted(CWalletDB* pwalletdb) {
    LOCK(cs_wallet);

    if (fFileBacked)
    {
            return pwalletdb->WriteIsCrypted(true);
    }

    return false;
}

bool CWallet::SetMinVersion(enum WalletFeature nVersion, CWalletDB* pwalletdbIn, bool fExplicit)
{
    LOCK(cs_wallet); // nWalletVersion
    if (nWalletVersion >= nVersion)
        return true;

    // when doing an explicit upgrade, if we pass the max version permitted, upgrade all the way
    if (fExplicit && nVersion > nWalletMaxVersion)
            nVersion = FEATURE_LATEST;

    nWalletVersion = nVersion;

    if (nVersion > nWalletMaxVersion)
        nWalletMaxVersion = nVersion;

    if (fFileBacked)
    {
        CWalletDB* pwalletdb = pwalletdbIn ? pwalletdbIn : new CWalletDB(strWalletFile);
        if (nWalletVersion > 40000)
            pwalletdb->WriteMinVersion(nWalletVersion);
        if (!pwalletdbIn)
            delete pwalletdb;
    }

    return true;
}

bool CWallet::SetMaxVersion(int nVersion)
{
    LOCK(cs_wallet); // nWalletVersion, nWalletMaxVersion
    // cannot downgrade below current version
    if (nWalletVersion > nVersion)
        return false;

    nWalletMaxVersion = nVersion;

    return true;
}

set<uint256> CWallet::GetConflicts(const uint256& txid) const
{
    set<uint256> result;
    AssertLockHeld(cs_wallet);

    std::map<uint256, CWalletTx>::const_iterator it = mapWallet.find(txid);
    if (it == mapWallet.end())
        return result;
    const CWalletTx& wtx = it->second;

    std::pair<TxSpends::const_iterator, TxSpends::const_iterator> range;

    BOOST_FOREACH(const CTxIn& txin, wtx.vin)
    {
        if (mapTxSpends.count(txin.prevout) <= 1)
            continue;  // No conflict if zero or one spends
        range = mapTxSpends.equal_range(txin.prevout);
        for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
            result.insert(it->second);
    }

    std::pair<TxNullifiers::const_iterator, TxNullifiers::const_iterator> range_n;

    for (const JSDescription& jsdesc : wtx.vJoinSplit) {
        for (const uint256& nullifier : jsdesc.nullifiers) {
            if (mapTxSproutNullifiers.count(nullifier) <= 1) {
                continue;  // No conflict if zero or one spends
            }
            range_n = mapTxSproutNullifiers.equal_range(nullifier);
            for (TxNullifiers::const_iterator it = range_n.first; it != range_n.second; ++it) {
                result.insert(it->second);
            }
        }
    }

    std::pair<TxNullifiers::const_iterator, TxNullifiers::const_iterator> range_o;

    for (const SpendDescription &spend : wtx.vShieldedSpend) {
        uint256 nullifier = spend.nullifier;
        if (mapTxSaplingNullifiers.count(nullifier) <= 1) {
            continue;  // No conflict if zero or one spends
        }
        range_o = mapTxSaplingNullifiers.equal_range(nullifier);
        for (TxNullifiers::const_iterator it = range_o.first; it != range_o.second; ++it) {
            result.insert(it->second);
        }
    }
    return result;
}

void CWallet::Flush(bool shutdown)
{
    bitdb.Flush(shutdown);
}

bool CWallet::Verify(const string& walletFile, string& warningString, string& errorString)
{
    if (!bitdb.Open(GetDataDir()))
    {
        // try moving the database env out of the way
        boost::filesystem::path pathDatabase = GetDataDir() / "database";
        boost::filesystem::path pathDatabaseBak = GetDataDir() / strprintf("database.%d.bak", GetTime());
        try {
            boost::filesystem::rename(pathDatabase, pathDatabaseBak);
            LogPrintf("Moved old %s to %s. Retrying.\n", pathDatabase.string(), pathDatabaseBak.string());
        } catch (const boost::filesystem::filesystem_error&) {
            // failure is ok (well, not really, but it's not worse than what we started with)
        }

        // try again
        if (!bitdb.Open(GetDataDir())) {
            // if it still fails, it probably means we can't even create the database env
            string msg = strprintf(_("Error initializing wallet database environment %s!"), GetDataDir());
            errorString += msg;
            return true;
        }
    }

    if (GetBoolArg("-salvagewallet", false))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, walletFile, true))
            return false;
    }

    if (boost::filesystem::exists(GetDataDir() / walletFile))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(walletFile, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            warningString += strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."), GetDataDir());
        }
        if (r == CDBEnv::RECOVER_FAIL)
            errorString += _("wallet.dat corrupt, salvage failed");
    }

    return true;
}

template <class T>
void CWallet::SyncMetaData(pair<typename TxSpendMap<T>::iterator, typename TxSpendMap<T>::iterator> range)
{
    // We want all the wallet transactions in range to have the same metadata as
    // the oldest (smallest nOrderPos).
    // So: find smallest nOrderPos:

    int nMinOrderPos = std::numeric_limits<int>::max();
    const CWalletTx* copyFrom = NULL;
    for (typename TxSpendMap<T>::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        int n = mapWallet[hash].nOrderPos;
        if (n < nMinOrderPos)
        {
            nMinOrderPos = n;
            copyFrom = &mapWallet[hash];
        }
    }
    // Now copy data from copyFrom to rest:
    for (typename TxSpendMap<T>::iterator it = range.first; it != range.second; ++it)
    {
        const uint256& hash = it->second;
        CWalletTx* copyTo = &mapWallet[hash];
        if (copyFrom == copyTo) continue;
        copyTo->mapValue = copyFrom->mapValue;
        // mapSproutNoteData and mapSaplingNoteData not copied on purpose
        // (it is always set correctly for each CWalletTx)
        copyTo->vOrderForm = copyFrom->vOrderForm;
        // fTimeReceivedIsTxTime not copied on purpose
        // nTimeReceived not copied on purpose
        copyTo->nTimeSmart = copyFrom->nTimeSmart;
        copyTo->fFromMe = copyFrom->fFromMe;
        copyTo->strFromAccount = copyFrom->strFromAccount;
        // nOrderPos not copied on purpose
        // cached members not copied on purpose
    }
}

/**
 * Outpoint is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSpent(const uint256& hash, unsigned int n) const
{
    const COutPoint outpoint(hash, n);
    pair<TxSpends::const_iterator, TxSpends::const_iterator> range;
    range = mapTxSpends.equal_range(outpoint);

    for (TxSpends::const_iterator it = range.first; it != range.second; ++it)
    {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end() && mit->second.GetDepthInMainChain() >= 0)
            return true; // Spent
    }
    return false;
}

/**
 * Note is spent if any non-conflicted transaction
 * spends it:
 */
bool CWallet::IsSproutSpent(const uint256& nullifier) const {
    pair<TxNullifiers::const_iterator, TxNullifiers::const_iterator> range;
    range = mapTxSproutNullifiers.equal_range(nullifier);

    for (TxNullifiers::const_iterator it = range.first; it != range.second; ++it) {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end() && mit->second.GetDepthInMainChain() >= 0) {
            return true; // Spent
        }
    }
    return false;
}

bool CWallet::IsSaplingSpent(const uint256& nullifier) const {
    pair<TxNullifiers::const_iterator, TxNullifiers::const_iterator> range;
    range = mapTxSaplingNullifiers.equal_range(nullifier);

    for (TxNullifiers::const_iterator it = range.first; it != range.second; ++it) {
        const uint256& wtxid = it->second;
        std::map<uint256, CWalletTx>::const_iterator mit = mapWallet.find(wtxid);
        if (mit != mapWallet.end() && mit->second.GetDepthInMainChain() >= 0) {
            return true; // Spent
        }
    }
    return false;
}

void CWallet::AddToTransparentSpends(const COutPoint& outpoint, const uint256& wtxid)
{
    mapTxSpends.insert(make_pair(outpoint, wtxid));

    pair<TxSpends::iterator, TxSpends::iterator> range;
    range = mapTxSpends.equal_range(outpoint);
    SyncMetaData<COutPoint>(range);
}

void CWallet::AddToSproutSpends(const uint256& nullifier, const uint256& wtxid)
{
    mapTxSproutNullifiers.insert(make_pair(nullifier, wtxid));

    pair<TxNullifiers::iterator, TxNullifiers::iterator> range;
    range = mapTxSproutNullifiers.equal_range(nullifier);
    SyncMetaData<uint256>(range);
}

void CWallet::AddToSaplingSpends(const uint256& nullifier, const uint256& wtxid)
{
    mapTxSaplingNullifiers.insert(make_pair(nullifier, wtxid));

    pair<TxNullifiers::iterator, TxNullifiers::iterator> range;
    range = mapTxSaplingNullifiers.equal_range(nullifier);
    SyncMetaData<uint256>(range);
}

void CWallet::AddToSpends(const uint256& wtxid)
{
    assert(mapWallet.count(wtxid));
    CWalletTx& thisTx = mapWallet[wtxid];
    if (thisTx.IsCoinBase()) // Coinbases don't spend anything!
        return;

    for (const CTxIn& txin : thisTx.vin) {
        AddToTransparentSpends(txin.prevout, wtxid);
    }
    for (const JSDescription& jsdesc : thisTx.vJoinSplit) {
        for (const uint256& nullifier : jsdesc.nullifiers) {
            AddToSproutSpends(nullifier, wtxid);
        }
    }
    for (const SpendDescription &spend : thisTx.vShieldedSpend) {
        AddToSaplingSpends(spend.nullifier, wtxid);
    }
}

void CWallet::ClearNoteWitnessCache()
{
    LOCK(cs_wallet);
    for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
        for (mapSproutNoteData_t::value_type& item : wtxItem.second.mapSproutNoteData) {
            item.second.witnesses.clear();
            item.second.witnessHeight = -1;
        }
        for (mapSaplingNoteData_t::value_type& item : wtxItem.second.mapSaplingNoteData) {
            item.second.witnesses.clear();
            item.second.witnessHeight = -1;
        }
    }
    nWitnessCacheSize = 0;
    //fprintf(stderr,"Clear witness cache\n");
}

template<typename NoteDataMap>
void CopyPreviousWitnesses(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize)
{
    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        // Only increment witnesses that are behind the current height
        if (nd->witnessHeight < indexHeight) {
            // Check the validity of the cache
            // The only time a note witnessed above the current height
            // would be invalid here is during a reindex when blocks
            // have been decremented, and we are incrementing the blocks
            // immediately after.
            assert(nWitnessCacheSize >= nd->witnesses.size());
            // Witnesses being incremented should always be either -1
            // (never incremented or decremented) or one below indexHeight
            assert((nd->witnessHeight == -1) || (nd->witnessHeight == indexHeight - 1));
            // Copy the witness for the previous block if we have one
            if (nd->witnesses.size() > 0) {
                nd->witnesses.push_front(nd->witnesses.front());
            }
            if (nd->witnesses.size() > WITNESS_CACHE_SIZE) {
                nd->witnesses.pop_back();
            }
        }
    }
}

template<typename NoteDataMap>
void AppendNoteCommitment(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize, const uint256& note_commitment)
{
    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        if (nd->witnessHeight < indexHeight && nd->witnesses.size() > 0) {
            // Check the validity of the cache
            // See comment in CopyPreviousWitnesses about validity.
            assert(nWitnessCacheSize >= nd->witnesses.size());
            nd->witnesses.front().append(note_commitment);
        }
    }
}

template<typename OutPoint, typename NoteData, typename Witness>
void WitnessNoteIfMine(std::map<OutPoint, NoteData>& noteDataMap, int indexHeight, int64_t nWitnessCacheSize, const OutPoint& key, const Witness& witness)
{
    if (noteDataMap.count(key) && noteDataMap[key].witnessHeight < indexHeight) {
        auto* nd = &(noteDataMap[key]);
        if (nd->witnesses.size() > 0) {
            // We think this can happen because we write out the
            // witness cache state after every block increment or
            // decrement, but the block index itself is written in
            // batches. So if the node crashes in between these two
            // operations, it is possible for IncrementNoteWitnesses
            // to be called again on previously-cached blocks. This
            // doesn't affect existing cached notes because of the
            // NoteData::witnessHeight checks. See #1378 for details.
            LogPrintf("Inconsistent witness cache state found for %s\n- Cache size: %d\n- Top (height %d): %s\n- New (height %d): %s\n",
                        key.ToString(), nd->witnesses.size(),
                        nd->witnessHeight,
                        nd->witnesses.front().root().GetHex(),
                        indexHeight,
                        witness.root().GetHex());
            nd->witnesses.clear();
        }
        nd->witnesses.push_front(witness);
        // Set height to one less than pindex so it gets incremented
        nd->witnessHeight = indexHeight - 1;
        // Check the validity of the cache
        assert(nWitnessCacheSize >= nd->witnesses.size());
    }
}


template<typename NoteDataMap>
void UpdateWitnessHeights(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize)
{
    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        if (nd->witnessHeight < indexHeight) {
            nd->witnessHeight = indexHeight;
            // Check the validity of the cache
            // See comment in CopyPreviousWitnesses about validity.
            assert(nWitnessCacheSize >= nd->witnesses.size());
        }
    }
}

void CWallet::IncrementNoteWitnesses(const CBlockIndex* pindex,
                                     const CBlock* pblockIn,
                                     SproutMerkleTree& sproutTree,
                                     SaplingMerkleTree& saplingTree)
{
    LOCK(cs_wallet);
    for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
       ::CopyPreviousWitnesses(wtxItem.second.mapSproutNoteData, pindex->GetHeight(), nWitnessCacheSize);
       ::CopyPreviousWitnesses(wtxItem.second.mapSaplingNoteData, pindex->GetHeight(), nWitnessCacheSize);
    }

    if (nWitnessCacheSize < WITNESS_CACHE_SIZE) {
        nWitnessCacheSize += 1;
    }

    const CBlock* pblock {pblockIn};
    CBlock block;
    if (!pblock) {
        ReadBlockFromDisk(block, pindex, Params().GetConsensus());
        pblock = &block;
    }

    for (const CTransaction& tx : pblock->vtx) {
        auto hash = tx.GetHash();
        bool txIsOurs = mapWallet.count(hash);
        // Sprout
        for (size_t i = 0; i < tx.vJoinSplit.size(); i++) {
            const JSDescription& jsdesc = tx.vJoinSplit[i];
            for (uint8_t j = 0; j < jsdesc.commitments.size(); j++) {
                const uint256& note_commitment = jsdesc.commitments[j];
                sproutTree.append(note_commitment);

                // Increment existing witnesses
                for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
                    ::AppendNoteCommitment(wtxItem.second.mapSproutNoteData, pindex->GetHeight(), nWitnessCacheSize, note_commitment);
                }

                // If this is our note, witness it
                if (txIsOurs) {
                    JSOutPoint jsoutpt {hash, i, j};
                    ::WitnessNoteIfMine(mapWallet[hash].mapSproutNoteData, pindex->GetHeight(), nWitnessCacheSize, jsoutpt, sproutTree.witness());
                }
            }
        }
        // Sapling
        for (uint32_t i = 0; i < tx.vShieldedOutput.size(); i++) {
            const uint256& note_commitment = tx.vShieldedOutput[i].cm;
            saplingTree.append(note_commitment);

            // Increment existing witnesses
            for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
                ::AppendNoteCommitment(wtxItem.second.mapSaplingNoteData, pindex->GetHeight(), nWitnessCacheSize, note_commitment);
            }

            // If this is our note, witness it
            if (txIsOurs) {
                SaplingOutPoint outPoint {hash, i};
                ::WitnessNoteIfMine(mapWallet[hash].mapSaplingNoteData, pindex->GetHeight(), nWitnessCacheSize, outPoint, saplingTree.witness());
            }
        }
    }

    // Update witness heights
    for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
        ::UpdateWitnessHeights(wtxItem.second.mapSproutNoteData, pindex->GetHeight(), nWitnessCacheSize);
        ::UpdateWitnessHeights(wtxItem.second.mapSaplingNoteData, pindex->GetHeight(), nWitnessCacheSize);
    }

    // For performance reasons, we write out the witness cache in
    // CWallet::SetBestChain() (which also ensures that overall consistency
    // of the wallet.dat is maintained).
}

template<typename NoteDataMap>
bool DecrementNoteWitnesses(NoteDataMap& noteDataMap, int indexHeight, int64_t nWitnessCacheSize)
{
    extern int32_t KOMODO_REWIND;

    for (auto& item : noteDataMap) {
        auto* nd = &(item.second);
        // Only decrement witnesses that are not above the current height
        if (nd->witnessHeight <= indexHeight) {
            // Check the validity of the cache
            // See comment below (this would be invalid if there were a
            // prior decrement).
            assert(nWitnessCacheSize >= nd->witnesses.size());
            // Witnesses being decremented should always be either -1
            // (never incremented or decremented) or equal to the height
            // of the block being removed (indexHeight)
            if (!((nd->witnessHeight == -1) || (nd->witnessHeight == indexHeight)))
            {
                printf("at height %d\n", indexHeight);
                return false;
            }
            if (nd->witnesses.size() > 0) {
                nd->witnesses.pop_front();
            }
            // indexHeight is the height of the block being removed, so 
            // the new witness cache height is one below it.
            nd->witnessHeight = indexHeight - 1;
        }
        // Check the validity of the cache
        // Technically if there are notes witnessed above the current
        // height, their cache will now be invalid (relative to the new
        // value of nWitnessCacheSize). However, this would only occur
        // during a reindex, and by the time the reindex reaches the tip
        // of the chain again, the existing witness caches will be valid
        // again.
        // We don't set nWitnessCacheSize to zero at the start of the
        // reindex because the on-disk blocks had already resulted in a
        // chain that didn't trigger the assertion below.
        if (nd->witnessHeight < indexHeight) {
            // Subtract 1 to compare to what nWitnessCacheSize will be after
            // decrementing.
            assert((nWitnessCacheSize - 1) >= nd->witnesses.size());
        }
    }
    assert(KOMODO_REWIND != 0 || nWitnessCacheSize > 0);
    return true;
}

void CWallet::DecrementNoteWitnesses(const CBlockIndex* pindex)
{
    LOCK(cs_wallet);
    for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
        if (!::DecrementNoteWitnesses(wtxItem.second.mapSproutNoteData, pindex->GetHeight(), nWitnessCacheSize))
            needsRescan = true;
        if (!::DecrementNoteWitnesses(wtxItem.second.mapSaplingNoteData, pindex->GetHeight(), nWitnessCacheSize))
            needsRescan = true;
    }
    if (nWitnessCacheSize != 0)
    {
        nWitnessCacheSize -= 1;
        // TODO: If nWitnessCache is zero, we need to regenerate the caches (#1302)
        if (nWitnessCacheSize == 0)
        {
            ClearNoteWitnessCache();
        }
        //assert(nWitnessCacheSize > 0);
    }

    // For performance reasons, we write out the witness cache in
    // CWallet::SetBestChain() (which also ensures that overall consistency
    // of the wallet.dat is maintained).
}

bool CWallet::EncryptWallet(const SecureString& strWalletPassphrase)
{
    if (IsCrypted())
        return false;

    CKeyingMaterial vMasterKey;

    vMasterKey.resize(WALLET_CRYPTO_KEY_SIZE);
    GetRandBytes(&vMasterKey[0], WALLET_CRYPTO_KEY_SIZE);

    CMasterKey kMasterKey;

    kMasterKey.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
    GetRandBytes(&kMasterKey.vchSalt[0], WALLET_CRYPTO_SALT_SIZE);

    CCrypter crypter;
    int64_t nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, 25000, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = 2500000 / ((double)(GetTimeMillis() - nStartTime));

    nStartTime = GetTimeMillis();
    crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod);
    kMasterKey.nDeriveIterations = (kMasterKey.nDeriveIterations + kMasterKey.nDeriveIterations * 100 / ((double)(GetTimeMillis() - nStartTime))) / 2;

    if (kMasterKey.nDeriveIterations < 25000)
        kMasterKey.nDeriveIterations = 25000;

    LogPrintf("Encrypting Wallet with an nDeriveIterations of %i\n", kMasterKey.nDeriveIterations);

    if (!crypter.SetKeyFromPassphrase(strWalletPassphrase, kMasterKey.vchSalt, kMasterKey.nDeriveIterations, kMasterKey.nDerivationMethod))
        return false;
    if (!crypter.Encrypt(vMasterKey, kMasterKey.vchCryptedKey))
        return false;

    {
        LOCK(cs_wallet);
        mapMasterKeys[++nMasterKeyMaxID] = kMasterKey;
        if (fFileBacked)
        {
            if (!pwalletdbEncryption) {
                delete pwalletdbEncryption;
                pwalletdbEncryption = NULL;
            }
            pwalletdbEncryption = new CWalletDB(strWalletFile);
            pwalletdbEncryption->WriteMasterKey(nMasterKeyMaxID, kMasterKey);
        }

        if (!EncryptKeys(vMasterKey)) {
            LogPrintf("Encrypt Keys failed!!!");
            return false;
        }

        //Write Crypted statuses
        SetWalletCrypted(pwalletdbEncryption);
        SetDBCrypted();

        // Encryption was introduced in version 0.4.0
        SetMinVersion(FEATURE_WALLETCRYPT, pwalletdbEncryption, true);

        delete pwalletdbEncryption;
        pwalletdbEncryption = NULL;


        Lock();
        Unlock(strWalletPassphrase);
        NewKeyPool();
        Lock();

        // Need to completely rewrite the wallet file; if we don't, bdb might keep
        // bits of the unencrypted private key in slack space in the database file.
        CDB::Rewrite(strWalletFile);

    }
    NotifyStatusChanged(this);

    return true;
}

int64_t CWallet::IncOrderPosNext(CWalletDB *pwalletdb)
{
    AssertLockHeld(cs_wallet); // nOrderPosNext
    int64_t nRet = nOrderPosNext++;
    if (pwalletdb) {
        pwalletdb->WriteOrderPosNext(nOrderPosNext);
    } else {
        CWalletDB(strWalletFile).WriteOrderPosNext(nOrderPosNext);
    }
    return nRet;
}

CWallet::TxItems CWallet::OrderedTxItems(std::list<CAccountingEntry>& acentries, std::string strAccount)
{
    AssertLockHeld(cs_wallet); // mapWallet
    CWalletDB walletdb(strWalletFile);

    // First: get all CWalletTx and CAccountingEntry into a sorted-by-order multimap.
    TxItems txOrdered;

    // Note: maintaining indices in the database of (account,time) --> txid and (account, time) --> acentry
    // would make this much faster for applications that do this a lot.
    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* wtx = &((*it).second);
        txOrdered.insert(make_pair(wtx->nOrderPos, TxPair(wtx, (CAccountingEntry*)0)));
    }
    acentries.clear();
    walletdb.ListAccountCreditDebit(strAccount, acentries);
    BOOST_FOREACH(CAccountingEntry& entry, acentries)
    {
        txOrdered.insert(make_pair(entry.nOrderPos, TxPair((CWalletTx*)0, &entry)));
    }

    return txOrdered;
}

bool CWallet::IsMineLock(const CTxDestination &destination) const
{
    LOCK(pwalletMain->cs_wallet);
    return ::IsMine(*this, destination);
}

// looks through all wallet UTXOs and checks to see if any qualify to stake the block at the current height. it always returns the qualified
// UTXO with the smallest coin age if there is more than one, as larger coin age will win more often and is worth saving
// each attempt consists of taking a VerusHash of the following values:
//  ASSETCHAINS_MAGIC, nHeight, txid, voutNum
bool CWallet::VerusSelectStakeOutput(CBlock *pBlock, arith_uint256 &hashResult, CTransaction &stakeSource, int32_t &voutNum, int32_t nHeight, uint32_t &bnTarget) const
{
    arith_uint256 target;
    arith_uint256 curHash;
    COutput *pwinner = NULL;
    CWalletTx winnerWtx;

    txnouttype whichType;
    std:vector<std::vector<unsigned char>> vSolutions;

    pBlock->nNonce.SetPOSTarget(bnTarget, pBlock->nVersion);
    target.SetCompact(bnTarget);

    auto consensusParams = Params().GetConsensus();
    CValidationState state;

    std::vector<COutput> vecOutputs;
    std::vector<CWalletTx> vwtx;
    CAmount totalStakingAmount = 0;

    uint32_t solutionVersion = CConstVerusSolutionVector::GetVersionByHeight(nHeight);
    bool extendedStake = solutionVersion >= CActivationHeight::ACTIVATE_EXTENDEDSTAKE;

    {
        LOCK2(cs_main, cs_wallet);
        pwalletMain->AvailableCoins(vecOutputs, true, NULL, false, true, false);

        int newSize = 0;

        for (int i = 0; i < vecOutputs.size(); i++)
        {
            auto &txout = vecOutputs[i];
            COptCCParams p;

            if (txout.tx &&
                txout.i < txout.tx->vout.size() &&
                txout.tx->vout[txout.i].nValue > 0 &&
                txout.fSpendable &&
                (txout.nDepth >= VERUS_MIN_STAKEAGE) &&
                ((txout.tx->vout[txout.i].scriptPubKey.IsPayToCryptoCondition(p) &&
                  extendedStake && 
                  p.IsValid() && 
                  txout.tx->vout[txout.i].scriptPubKey.IsSpendableOutputType(p)) ||
                (!p.IsValid() && 
                 Solver(txout.tx->vout[txout.i].scriptPubKey, whichType, vSolutions) &&
                 (whichType == TX_PUBKEY || whichType == TX_PUBKEYHASH))))
            {
                totalStakingAmount += txout.tx->vout[txout.i].nValue;
                // if all are valid, no change, else compress
                if (newSize != i)
                {
                    vecOutputs[newSize] = txout;
                }
                newSize++;
            }
        }

        if (newSize)
        {
            // no reallocations to move objects. do all at once, so we can release the wallet lock
            vecOutputs.resize(newSize);
            vwtx.resize(newSize);
            for (int i = 0; i < vecOutputs.size(); i++)
            {
                vwtx[i] = *vecOutputs[i].tx;
                vecOutputs[i].tx = &vwtx[i];
            }
        }
    }

    if (totalStakingAmount)
    {
        LogPrintf("Staking with %s VRSC\n", ValueFromAmount(totalStakingAmount).write().c_str());
    }
    else
    {
        LogPrintf("No VRSC staking\n");
        return false;
    }

    // we get these sources of entropy to prove all sources in the header
    int posHeight = -1, powHeight = -1, altHeight = -1;
    uint256 pastHash;
    {
        LOCK(cs_main);
        pastHash = chainActive.GetVerusEntropyHash(nHeight, &posHeight, &powHeight, &altHeight);
        if (extendedStake && (altHeight == -1 && (powHeight == -1 || posHeight == -1)))
        {
            printf("Error retrieving entropy hash at height %d, posHeight: %d, powHeight: %d, altHeight: %d\n", nHeight, posHeight, powHeight, altHeight);
            LogPrintf("Error retrieving entropy hash at height %d, posHeight: %d, powHeight: %d, altHeight: %d\n", nHeight, posHeight, powHeight, altHeight);
            return false;
        }
    }

    // secondBlockHeight is either less than first or -1 if there isn't one
    int secondBlockHeight = altHeight != -1 ? 
                                altHeight : 
                                posHeight == -1 ? 
                                    posHeight :
                                    powHeight == -1 ?
                                        powHeight :
                                        (posHeight > powHeight ? 
                                            powHeight : 
                                            posHeight);

    int proveBlockHeight = posHeight > secondBlockHeight ? posHeight : ((powHeight == -1) ? posHeight : powHeight);

    if (proveBlockHeight == -1)
    {
        printf("No block suitable for proof for height %d, posHeight: %d, powHeight: %d, altHeight: %d\n", nHeight, posHeight, powHeight, altHeight);
        LogPrintf("No block suitable for proof for height %d, posHeight: %d, powHeight: %d, altHeight: %d\n", nHeight, posHeight, powHeight, altHeight);
    }
    else
    {
        CPOSNonce curNonce;
        uint32_t srcIndex;

        CCoinsViewCache view(pcoinsTip);
        CMutableTransaction checkStakeTx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);
        std::vector<CTxDestination> addressRet;
        int nRequiredRet;

        BOOST_FOREACH(COutput &txout, vecOutputs)
        {
            COptCCParams p;
            std::vector<CTxDestination> destinations;
            int nRequired = 0;
            bool canSign = false, canSpend = false;

            if (UintToArith256(txout.tx->GetVerusPOSHash(&(pBlock->nNonce), txout.i, nHeight, pastHash)) <= target)
            {
                LOCK2(cs_main, cs_wallet);

                if (ExtractDestinations(txout.tx->vout[txout.i].scriptPubKey, whichType, destinations, nRequired, this, &canSign, &canSpend) &&
                    ((txout.tx->vout[txout.i].scriptPubKey.IsPayToCryptoCondition(p) && 
                    extendedStake && 
                    canSpend) ||
                    (!p.IsValid() && (whichType == TX_PUBKEY || whichType == TX_PUBKEYHASH) && ::IsMine(*this, destinations[0]))))
                {
                    uint256 txHash = txout.tx->GetHash();
                    checkStakeTx.vin.push_back(CTxIn(COutPoint(txHash, txout.i)));

                    if ((!pwinner || UintToArith256(curNonce) < UintToArith256(pBlock->nNonce)) &&
                        !cheatList.IsUTXOInList(COutPoint(txHash, txout.i), nHeight <= 100 ? 1 : nHeight-100))
                    {
                        if (view.HaveCoins(txHash) && Consensus::CheckTxInputs(checkStakeTx, state, view, nHeight, consensusParams))
                        {
                            //printf("Found PoS block\nnNonce:    %s\n", pBlock->nNonce.GetHex().c_str());
                            pwinner = &txout;
                            curNonce = pBlock->nNonce;
                            srcIndex = nHeight - txout.nDepth;
                        }
                        else
                        {
                            LogPrintf("Transaction %s failed to stake due to %s\n", txout.tx->GetHash().GetHex().c_str(), 
                                                                                    view.HaveCoins(txHash) ? "bad inputs" : "unavailable coins");
                        }
                    }

                    checkStakeTx.vin.pop_back();
                }
            }
        }

        if (pwinner)
        {
            stakeSource = static_cast<CTransaction>(*pwinner->tx);

            // arith_uint256 post;
            // post.SetCompact(pBlock->GetVerusPOSTarget());
            // printf("Found stake transaction\n");
            // printf("POS hash: %s  \ntarget:   %s\n\n", 
            //         stakeSource.GetVerusPOSHash(&(pBlock->nNonce), pwinner->i, nHeight, pastHash).GetHex().c_str(), 
            //         ArithToUint256(post).GetHex().c_str());

            voutNum = pwinner->i;
            pBlock->nNonce = curNonce;

            if (solutionVersion >= CActivationHeight::ACTIVATE_STAKEHEADER)
            {
                LOCK(cs_main);
                CDataStream headerStream = CDataStream(SER_NETWORK, PROTOCOL_VERSION);

                // store:
                // 1. PBaaS header for this block
                // 2. source transaction
                // 3. block index of base MMR being used
                // 4. source tx block index for proof
                // 5. full merkle proof of source tx up to prior MMR root
                // 6. block hash of block of entropyhash
                // 7. proof of block hash (not full header) in the MMR for the block height of the entropy hash block
                // all that data includes enough information to verify
                // prior MMR, blockhash, transaction, entropy hash, and block indexes match
                // also checks root match & block power
                auto mmrView = chainActive.GetMMV();
                pBlock->SetPrevMMRRoot(mmrView.GetRoot());
                pBlock->AddUpdatePBaaSHeader();

                // get map and MMR for stake source transaction
                CTransactionMap txMap(stakeSource);
                TransactionMMView txView(txMap.transactionMMR);
                uint256 txRoot = txView.GetRoot();

                std::vector<CTransactionComponentProof> txProofVec;
                txProofVec.push_back(CTransactionComponentProof(txView, txMap, stakeSource, CTransactionHeader::TX_HEADER, 0));
                txProofVec.push_back(CTransactionComponentProof(txView, txMap, stakeSource, CTransactionHeader::TX_OUTPUT, pwinner->i));

                // now, both the header and stake output are dependent on the transaction MMR root being provable up
                // through the block MMR, and since we don't cache the new MMR proof for transactions yet, we need the block to create the proof.
                // when we switch to the new MMR in place of a merkle tree, we can keep that in the wallet as well
                CBlock block;
                if (!ReadBlockFromDisk(block, chainActive[srcIndex], Params().GetConsensus(), false))
                {
                    LogPrintf("%s: ERROR: could not read block number  %u from disk\n", __func__, srcIndex);
                    return false;
                }

                BlockMMRange blockMMR(block.GetBlockMMRTree());
                BlockMMView blockView(blockMMR);

                int txIndexPos;
                for (txIndexPos = 0; txIndexPos < blockMMR.size(); txIndexPos++)
                {
                    uint256 txRootHashFromMMR = blockMMR[txIndexPos].hash;
                    if (txRootHashFromMMR == txRoot)
                    {
                        //printf("tx with root %s found in block\n", txRootHashFromMMR.GetHex().c_str());
                        break;
                    }
                }

                if (txIndexPos == blockMMR.size())
                {
                    LogPrintf("%s: ERROR: could not find source transaction root in block %u\n", __func__, srcIndex);
                    return false;
                }

                // prove the tx up to the MMR root, which also contains the block hash
                CMMRProof txRootProof;
                if (!blockView.GetProof(txRootProof, txIndexPos))
                {
                    LogPrintf("%s: ERROR: could not create proof of source transaction in block %u\n", __func__, srcIndex);
                    return false;
                }

                mmrView.resize(proveBlockHeight + 1);
                chainActive.GetMerkleProof(mmrView, txRootProof, srcIndex);

                headerStream << CPartialTransactionProof(txRootProof, txProofVec);

                CMMRProof blockHeaderProof1;
                if (!chainActive.GetBlockProof(mmrView, blockHeaderProof1, proveBlockHeight))
                {
                    LogPrintf("%s: ERROR: could not create block proof for block %u\n", __func__, srcIndex);
                    return false;
                }
                headerStream << CBlockHeaderProof(blockHeaderProof1, chainActive[proveBlockHeight]->GetBlockHeader());

                CMMRProof blockHeaderProof2;
                if (!chainActive.GetBlockProof(mmrView, blockHeaderProof2, secondBlockHeight))
                {
                    LogPrintf("%s: ERROR: could not create block proof for second entropy source block %u\n", __func__, srcIndex);
                    chainActive.GetBlockProof(mmrView, blockHeaderProof2, secondBlockHeight); // repeat for debugging
                    return false;
                }
                headerStream << CBlockHeaderProof(blockHeaderProof2, chainActive[secondBlockHeight]->GetBlockHeader());

                std::vector<unsigned char> stx(headerStream.begin(), headerStream.end());

                // printf("\nFound Stake transaction... all proof serialized size == %lu\n", stx.size());

                CVerusSolutionVector(pBlock->nSolution).ResizeExtraData(stx.size());

                pBlock->SetExtraData(stx.data(), stx.size());

                //CBlockHeader blkHeader(*pBlock);
                //CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
                //printf("Staking block header size %ld\n", GetSerializeSize(s, blkHeader));
            }
            return true;
        }
    }
    return false;
}

int32_t CWallet::VerusStakeTransaction(CBlock *pBlock, CMutableTransaction &txNew, uint32_t &bnTarget, arith_uint256 &hashResult, std::vector<unsigned char> &utxosig, CTxDestination &rewardDest) const
{
    CTransaction stakeSource;
    int32_t voutNum, siglen = 0;
    int64_t nValue;
    txnouttype whichType;
    std::vector<std::vector<unsigned char>> vSolutions;

    CBlockIndex *tipindex = chainActive.LastTip();
    uint32_t stakeHeight = tipindex->GetHeight() + 1;
    bool extendedStake = CConstVerusSolutionVector::GetVersionByHeight(stakeHeight) >= CActivationHeight::ACTIVATE_EXTENDEDSTAKE;

    bnTarget = lwmaGetNextPOSRequired(tipindex, Params().GetConsensus());

    if (!VerusSelectStakeOutput(pBlock, hashResult, stakeSource, voutNum, stakeHeight, bnTarget))
    {
        //LogPrintf("Searched for eligible staking transactions, no winners found\n");
        return 0;
    }

    bool signSuccess; 
    SignatureData sigdata; 
    uint64_t txfee;
    auto consensusBranchId = CurrentEpochBranchId(stakeHeight, Params().GetConsensus());

    const CKeyStore& keystore = *pwalletMain;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txfee = 0;
    txNew.vin[0].prevout.hash = stakeSource.GetHash();
    txNew.vin[0].prevout.n = voutNum;

    COptCCParams p;
    if (stakeSource.vout[voutNum].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
    {
        if (!p.vKeys.size())
        {
            LogPrintf("%s: Please report - no destination on stake source\n");
            return 0;
        }

        // send output to same destination as source, convert stakeguard into normal output, since
        // that is a spendable output that only works in coinbases. preserve all recipients and
        // min sigs
        if (p.evalCode == EVAL_STAKEGUARD)
        {
            // "CIdentity" is a dummy object type since an obj is not passed, and it does not make this an identity output
            txNew.vout[0].scriptPubKey = MakeMofNCCScript(CConditionObj<CIdentity>(0, p.vKeys, p.m));
        }
        else
        {
            txNew.vout[0].scriptPubKey = stakeSource.vout[voutNum].scriptPubKey;
        }
        rewardDest = p.vKeys[0];
    }
    else if (Solver(stakeSource.vout[voutNum].scriptPubKey, whichType, vSolutions))
    {
        if (whichType == TX_PUBKEY)
        {
            txNew.vout[0].scriptPubKey << ToByteVector(vSolutions[0]) << OP_CHECKSIG;
            rewardDest = CPubKey(vSolutions[0]);
        }
        else if (whichType == TX_PUBKEYHASH)
        {
            txNew.vout[0].scriptPubKey << OP_DUP << OP_HASH160 << ToByteVector(vSolutions[0]) << OP_EQUALVERIFY << OP_CHECKSIG;
            rewardDest = CKeyID(uint160(vSolutions[0]));
        }
        else
        {
            LogPrintf("%s: Please report - found stake source that is not valid\n");
            return 0;
        }
    }
    else
    {
        return 0;
    }

    // set expiry to time out after 100 blocks, so we can remove the transaction if it orphans
    txNew.nExpiryHeight = stakeHeight + 100;

    uint256 srcBlock = uint256();
    CBlockIndex *pSrcIndex;

    txNew.vout.push_back(CTxOut());
    CTxOut &txOut1 = txNew.vout[1];
    txOut1.nValue = 0;
    if (!GetTransaction(stakeSource.GetHash(), stakeSource, srcBlock))
        return 0;
    
    BlockMap::const_iterator it = mapBlockIndex.find(srcBlock);
    if (it == mapBlockIndex.end() || (pSrcIndex = it->second) == 0)
        return 0;

    // !! DISABLE THIS FOR RELEASE: THIS MAKES A CHEAT TRANSACTION FOR EVERY STAKE FOR TESTING
    //CMutableTransaction cheat;
    //cheat = CMutableTransaction(txNew);
    //printf("TESTING ONLY: THIS SHOULD NOT BE ENABLED FOR RELEASE - MAKING CHEAT TRANSACTION FOR TESTING\n");
    //cheat.vout[1].scriptPubKey << OP_RETURN 
    //    << CStakeParams(pSrcIndex->GetHeight(), tipindex->GetHeight() + 1, pSrcIndex->GetBlockHash(), pk).AsVector();
    // !! DOWN TO HERE

    if (USE_EXTERNAL_PUBKEY)
    {
        rewardDest = CPubKey(ParseHex(NOTARY_PUBKEY));
    }
    else if (!VERUS_DEFAULTID.IsNull())
    {
        rewardDest = VERUS_DEFAULTID;
    }

    if (rewardDest.which() == COptCCParams::ADDRTYPE_INVALID)
    {
        printf("%s: Invalid reward destinaton for stake\n", __func__);
        return 0;
    }

    txOut1.scriptPubKey << OP_RETURN 
        << CStakeParams(pSrcIndex->GetHeight(), tipindex->GetHeight() + 1, tipindex->GetBlockHash(), rewardDest).AsVector();

    // !! DISABLE THIS FOR RELEASE: REMOVE THIS TOO
    //nValue = cheat.vout[0].nValue = stakeSource.vout[voutNum].nValue - txfee;
    //cheat.nLockTime = 0;
    //CTransaction cheatConst(cheat);
    //SignatureData cheatSig;
    //if (!ProduceSignature(TransactionSignatureCreator(&keystore, &cheatConst, 0, nValue, SIGHASH_ALL), stakeSource.vout[voutNum].scriptPubKey, cheatSig, consensusBranchId))
    //    fprintf(stderr,"failed to create cheat test signature\n");
    //else
    //{
    //    uint8_t *ptr;
    //    UpdateTransaction(cheat,0,cheatSig);
    //    cheatList.Add(CTxHolder(CTransaction(cheat), tipindex->GetHeight() + 1));
    //}
    // !! DOWN TO HERE

    nValue = txNew.vout[0].nValue = stakeSource.vout[voutNum].nValue - txfee;

    txNew.nLockTime = 0;
    CTransaction txNewConst(txNew);
    signSuccess = ProduceSignature(TransactionSignatureCreator(&keystore, &txNewConst, 0, nValue, stakeSource.vout[voutNum].scriptPubKey), stakeSource.vout[voutNum].scriptPubKey, sigdata, consensusBranchId);
    if (!signSuccess)
    {
        fprintf(stderr,"failed to create signature\n");
        utxosig.clear();
    }
    else
    {
        uint8_t *ptr;
        UpdateTransaction(txNew, 0, sigdata);
        utxosig.resize(sigdata.scriptSig.size());
        memcpy(&(utxosig[0]), &(sigdata.scriptSig[0]), utxosig.size());
    }
    return(utxosig.size());
}

void CWallet::MarkDirty()
{
    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
            item.second.MarkDirty();
    }
}

/**
 * Ensure that every note in the wallet (for which we possess a spending key)
 * has a cached nullifier.
 */
bool CWallet::UpdateNullifierNoteMap()
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        ZCNoteDecryption dec;
        for (std::pair<const uint256, CWalletTx>& wtxItem : mapWallet) {
            for (mapSproutNoteData_t::value_type& item : wtxItem.second.mapSproutNoteData) {
                if (!item.second.nullifier) {
                    if (GetNoteDecryptor(item.second.address, dec)) {
                        auto i = item.first.js;
                        auto hSig = wtxItem.second.vJoinSplit[i].h_sig(
                            *pzcashParams, wtxItem.second.joinSplitPubKey);
                        item.second.nullifier = GetSproutNoteNullifier(
                            wtxItem.second.vJoinSplit[i],
                            item.second.address,
                            dec,
                            hSig,
                            item.first.n);
                    }
                }
            }

            // TODO: Sapling.  This method is only called from RPC walletpassphrase, which is currently unsupported
            // as RPC encryptwallet is hidden behind two flags: -developerencryptwallet -experimentalfeatures

            UpdateNullifierNoteMapWithTx(wtxItem.second);
        }
    }
    return true;
}

/**
 * Update mapSproutNullifiersToNotes and mapSaplingNullifiersToNotes
 * with the cached nullifiers in this tx.
 */
void CWallet::UpdateNullifierNoteMapWithTx(const CWalletTx& wtx)
{
    {
        LOCK(cs_wallet);
        for (const mapSproutNoteData_t::value_type& item : wtx.mapSproutNoteData) {
            if (item.second.nullifier) {
                mapSproutNullifiersToNotes[*item.second.nullifier] = item.first;
            }
        }

        for (const mapSaplingNoteData_t::value_type& item : wtx.mapSaplingNoteData) {
            if (item.second.nullifier) {
                mapSaplingNullifiersToNotes[*item.second.nullifier] = item.first;
            }
        }
    }
}

/**
 * Update mapSaplingNullifiersToNotes, computing the nullifier from a cached witness if necessary.
 */
void CWallet::UpdateSaplingNullifierNoteMapWithTx(CWalletTx& wtx) {
    LOCK(cs_wallet);

    for (mapSaplingNoteData_t::value_type &item : wtx.mapSaplingNoteData) {
        SaplingOutPoint op = item.first;
        SaplingNoteData nd = item.second;

        if (nd.witnesses.empty()) {
            // If there are no witnesses, erase the nullifier and associated mapping.
            if (item.second.nullifier) {
                mapSaplingNullifiersToNotes.erase(item.second.nullifier.get());
            }
            item.second.nullifier = boost::none;
        }
        else {
            uint64_t position = nd.witnesses.front().position();
            SaplingExtendedFullViewingKey extfvk = mapSaplingFullViewingKeys.at(nd.ivk);
            OutputDescription output = wtx.vShieldedOutput[op.n];
            auto optPlaintext = SaplingNotePlaintext::decrypt(output.encCiphertext, nd.ivk, output.ephemeralKey, output.cm);
            if (!optPlaintext) {
                // An item in mapSaplingNoteData must have already been successfully decrypted,
                // otherwise the item would not exist in the first place.
                assert(false);
            }
            auto optNote = optPlaintext.get().note(nd.ivk);
            if (!optNote) {
                assert(false);
            }
            auto optNullifier = optNote.get().nullifier(extfvk.fvk, position);
            if (!optNullifier) {
                // This should not happen.  If it does, maybe the position has been corrupted or miscalculated?
                assert(false);
            }
            uint256 nullifier = optNullifier.get();
            mapSaplingNullifiersToNotes[nullifier] = op;
            item.second.nullifier = nullifier;
        }
    }
}

/**
 * Iterate over transactions in a block and update the cached Sapling nullifiers
 * for transactions which belong to the wallet.
 */
void CWallet::UpdateSaplingNullifierNoteMapForBlock(const CBlock *pblock) {
    LOCK(cs_wallet);

    for (const CTransaction& tx : pblock->vtx) {
        auto hash = tx.GetHash();
        bool txIsOurs = mapWallet.count(hash);
        if (txIsOurs) {
            UpdateSaplingNullifierNoteMapWithTx(mapWallet[hash]);
        }
    }
}

bool CWallet::AddToWallet(const CWalletTx& wtxIn, bool fFromLoadWallet, CWalletDB* pwalletdb)
{
    uint256 hash = wtxIn.GetHash();

    if (fFromLoadWallet)
    {
        mapWallet[hash] = wtxIn;
        mapWallet[hash].BindWallet(this);
        UpdateNullifierNoteMapWithTx(mapWallet[hash]);
        AddToSpends(hash);
    }
    else
    {
        LOCK(cs_wallet);
        // Inserts only if not already there, returns tx inserted or tx found
        pair<map<uint256, CWalletTx>::iterator, bool> ret = mapWallet.insert(make_pair(hash, wtxIn));
        CWalletTx& wtx = (*ret.first).second;
        wtx.BindWallet(this);
        UpdateNullifierNoteMapWithTx(wtx);
        bool fInsertedNew = ret.second;
        if (fInsertedNew)
        {
            wtx.nTimeReceived = GetAdjustedTime();
            wtx.nOrderPos = IncOrderPosNext(pwalletdb);

            wtx.nTimeSmart = wtx.nTimeReceived;
            if (!wtxIn.hashBlock.IsNull())
            {
                if (mapBlockIndex.count(wtxIn.hashBlock))
                {
                    int64_t latestNow = wtx.nTimeReceived;
                    int64_t latestEntry = 0;
                    {
                        // Tolerate times up to the last timestamp in the wallet not more than 5 minutes into the future
                        int64_t latestTolerated = latestNow + 300;
                        std::list<CAccountingEntry> acentries;
                        TxItems txOrdered = OrderedTxItems(acentries);
                        for (TxItems::reverse_iterator it = txOrdered.rbegin(); it != txOrdered.rend(); ++it)
                        {
                            CWalletTx *const pwtx = (*it).second.first;
                            if (pwtx == &wtx)
                                continue;
                            CAccountingEntry *const pacentry = (*it).second.second;
                            int64_t nSmartTime;
                            if (pwtx)
                            {
                                nSmartTime = pwtx->nTimeSmart;
                                if (!nSmartTime)
                                    nSmartTime = pwtx->nTimeReceived;
                            }
                            else
                                nSmartTime = pacentry->nTime;
                            if (nSmartTime <= latestTolerated)
                            {
                                latestEntry = nSmartTime;
                                if (nSmartTime > latestNow)
                                    latestNow = nSmartTime;
                                break;
                            }
                        }
                    }

                    int64_t blocktime = mapBlockIndex[wtxIn.hashBlock]->GetBlockTime();
                    wtx.nTimeSmart = std::max(latestEntry, std::min(blocktime, latestNow));
                }
                else
                    LogPrintf("AddToWallet(): found %s in block %s not in index\n",
                             wtxIn.GetHash().ToString(),
                             wtxIn.hashBlock.ToString());
            }
            AddToSpends(hash);
        }

        bool fUpdated = false;
        if (!fInsertedNew)
        {
            // Merge
            if (!wtxIn.hashBlock.IsNull() && wtxIn.hashBlock != wtx.hashBlock)
            {
                wtx.hashBlock = wtxIn.hashBlock;
                fUpdated = true;
            }
            if (wtxIn.nIndex != -1 && (wtxIn.vMerkleBranch != wtx.vMerkleBranch || wtxIn.nIndex != wtx.nIndex))
            {
                wtx.vMerkleBranch = wtxIn.vMerkleBranch;
                wtx.nIndex = wtxIn.nIndex;
                fUpdated = true;
            }
            if (UpdatedNoteData(wtxIn, wtx)) {
                fUpdated = true;
            }
            if (wtxIn.fFromMe && wtxIn.fFromMe != wtx.fFromMe)
            {
                wtx.fFromMe = wtxIn.fFromMe;
                fUpdated = true;
            }
        }

        //// debug log out
        if (fDebug)
        {
            LogPrintf("AddToWallet %s  %s%s\n", wtxIn.GetHash().ToString(), (fInsertedNew ? "new" : ""), (fUpdated ? "update" : ""));
        }

        // Write to disk
        if (fInsertedNew || fUpdated)
            if (!wtx.WriteToDisk(pwalletdb))
                return false;

        // Break debit/credit balance caches:
        wtx.MarkDirty();

        // Notify UI of new or updated transaction
        NotifyTransactionChanged(this, hash, fInsertedNew ? CT_NEW : CT_UPDATED);

        // notify an external script when a wallet transaction comes in or is updated
        std::string strCmd = GetArg("-walletnotify", "");

        if ( !strCmd.empty())
        {
            boost::replace_all(strCmd, "%s", wtxIn.GetHash().GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }

    }
    return true;
}

bool CWallet::UpdatedNoteData(const CWalletTx& wtxIn, CWalletTx& wtx)
{
    bool unchangedSproutFlag = (wtxIn.mapSproutNoteData.empty() || wtxIn.mapSproutNoteData == wtx.mapSproutNoteData);
    if (!unchangedSproutFlag) {
        auto tmp = wtxIn.mapSproutNoteData;
        // Ensure we keep any cached witnesses we may already have
        for (const std::pair <JSOutPoint, SproutNoteData> nd : wtx.mapSproutNoteData) {
            if (tmp.count(nd.first) && nd.second.witnesses.size() > 0) {
                tmp.at(nd.first).witnesses.assign(
                        nd.second.witnesses.cbegin(), nd.second.witnesses.cend());
            }
            tmp.at(nd.first).witnessHeight = nd.second.witnessHeight;
        }
        // Now copy over the updated note data
        wtx.mapSproutNoteData = tmp;
    }

    bool unchangedSaplingFlag = (wtxIn.mapSaplingNoteData.empty() || wtxIn.mapSaplingNoteData == wtx.mapSaplingNoteData);
    if (!unchangedSaplingFlag) {
        auto tmp = wtxIn.mapSaplingNoteData;
        // Ensure we keep any cached witnesses we may already have

        for (const std::pair <SaplingOutPoint, SaplingNoteData> nd : wtx.mapSaplingNoteData) {
            if (tmp.count(nd.first) && nd.second.witnesses.size() > 0) {
                tmp.at(nd.first).witnesses.assign(
                        nd.second.witnesses.cbegin(), nd.second.witnesses.cend());
            }
            tmp.at(nd.first).witnessHeight = nd.second.witnessHeight;
        }

        // Now copy over the updated note data
        wtx.mapSaplingNoteData = tmp;
    }

    return !unchangedSproutFlag || !unchangedSaplingFlag;
}

std::pair<bool, bool> CWallet::CheckAuthority(const CIdentity &identity)
{
    std::pair<bool, bool> canSignCanSpend({false, false});
    if (!identity.IsValidUnrevoked())
    {
        return canSignCanSpend;
    }
    std::set<CIdentityID> keySet;

    // determine our status of cansign or canspend for this new ID
    for (auto key : identity.primaryAddresses)
    {
        CKeyID keyID = CKeyID(GetDestinationID(key));
        if (HaveKey(keyID))
        {
            keySet.insert(keyID);
        }
    }

    // if we have enough keys to fully authorize, it is ours
    if (keySet.size() >= identity.minSigs)
    {
        canSignCanSpend.first = true;
        canSignCanSpend.second = true;
    }
    else if (keySet.size())
    {
        canSignCanSpend.first = true;
    }
    return canSignCanSpend;
}

bool CWallet::MarkIdentityDirty(const CIdentityID &idID)
{
    bool found = false;
    // if we already had signing authority, but not spending, enumerate wallet transactions sent to this ID and mark them dirty
    // for proper balance calculation
    for (auto &txidAndWtx : mapWallet)
    {
        bool dirty = false;
        txnouttype txType;
        std::vector<CTxDestination> addresses;
        int minSigs;
        for (auto txout : txidAndWtx.second.vout)
        {
            if (txout.scriptPubKey.IsPayToCryptoCondition() && ExtractDestinations(txout.scriptPubKey, txType, addresses, minSigs))
            {
                for (auto dest : addresses)
                {
                    if (GetDestinationID(dest) == idID)
                    {
                        dirty = true;
                        found = true;
                        break;
                    }
                }
            }
        }
        if (dirty)
        {
            txidAndWtx.second.MarkDirty();
        }
    }
    return found;
}

/**
 * Add a transaction to the wallet, or update it.
 * pblock is optional, but should be provided if the transaction is known to be in a block.
 * If fUpdate is true, existing transactions will be updated.
 *
 * If pblock is null, this transaction has either recently entered the mempool from the
 * network, is re-entering the mempool after a block was disconnected, or is exiting the
 * mempool because it conflicts with another transaction. In all these cases, if there is
 * an existing wallet transaction, the wallet transaction's Merkle branch data is _not_
 * updated; instead, the transaction being in the mempool or conflicted is determined on
 * the fly in CMerkleTx::GetDepthInMainChain().
 */
bool CWallet::AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool isRescan)
{
    {
        AssertLockHeld(cs_wallet);
        AssertLockHeld(cs_main);
        uint256 txHash = tx.GetHash();

        bool fExisted = mapWallet.count(txHash) != 0;
        bool isNewID = false;
        if (fExisted && !fUpdate) return false;
        auto sproutNoteData = FindMySproutNotes(tx);
        auto saplingNoteDataAndAddressesToAdd = FindMySaplingNotes(tx);
        auto saplingNoteData = saplingNoteDataAndAddressesToAdd.first;
        auto addressesToAdd = saplingNoteDataAndAddressesToAdd.second;
        for (const auto &addressToAdd : addressesToAdd) {
            if (!AddSaplingIncomingViewingKey(addressToAdd.second, addressToAdd.first)) {
                return false;
            }
        }

        uint32_t nHeight = 0;
        if (pblock)
        {
            auto blkIndexIt = mapBlockIndex.find(pblock->GetHash());
            if (blkIndexIt != mapBlockIndex.end())
            {
                nHeight = blkIndexIt->second->GetHeight();
            }
            else
            {
                // this should never happen
                UniValue txUniv(UniValue::VOBJ);
                TxToUniv(tx, pblock->GetHash(), txUniv);
                LogPrintf("%s: UNEXPECTED ERROR: block (%s) for transaction %s:\n%s\nnot found\n", __func__, pblock->GetHash().GetHex().c_str(), txHash.GetHex().c_str(), txUniv.write(1,2).c_str());
                printf("%s: UNEXPECTED ERROR: block (%s) for transaction %s:\n%s\nnot found\n", __func__, pblock->GetHash().GetHex().c_str(), txHash.GetHex().c_str(), txUniv.write(1,2).c_str());
                return false;
            }
        }

        for (auto output : tx.vout)
        {
            bool canSpend = false;
            COptCCParams p;

            if (output.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.version >= p.VERSION_V3)
            {
                CIdentityMapValue identity;

                if (p.evalCode == EVAL_IDENTITY_PRIMARY && p.vData.size() && (*(CIdentity *)&identity = CIdentity(p.vData[0])).IsValid())
                {
                    identity.txid = txHash;
                    CIdentityMapKey idMapKey = CIdentityMapKey(identity.GetID(), 
                                                               nHeight, 
                                                               1, 
                                                               CIdentityMapKey::VALID);

                    std::set<CKeyID> keySet;
                    CIdentityID idID(identity.GetID());
                    int blockOrder = 1;
                    bool doneWithID = false;

                    std::pair<CIdentityMapKey, CIdentityMapValue> idHistory;

                    // if adding, current is what it will be, idHistory is what it was
                    // if we are deleting, current identity is what it was, idHistory is what it will be
                    std::pair<bool, bool> wasCanSignCanSpend({false, false});
                    std::pair<bool, bool> canSignCanSpend(CheckAuthority(identity));

                    // does identity already exist in this wallet?
                    if (GetIdentity(idID, idHistory, nHeight ? nHeight : INT_MAX))
                    {
                        wasCanSignCanSpend = CheckAuthority(idHistory.second);

                        // if this is an add of the initial registration, delete all other instances of the ID
                        if (CNameReservation(tx).IsValid())
                        {
                            while (GetIdentity(idID, idHistory))
                            {
                                // any definition of this identity in this wallet must be
                                // invalid now
                                RemoveIdentity(idHistory.first, idHistory.second.txid);
                                if (idHistory.second.txid != txHash)
                                {
                                    // any definition of this ID in this wallet that is not this definition
                                    // must also be on an invalid transaction
                                    EraseFromWallet(idHistory.second.txid);
                                }
                                // set wasCanSignCanSpend to true, true to delete any dependent transactions
                                wasCanSignCanSpend = {true, true};
                            }
                            idHistory = std::pair<CIdentityMapKey, CIdentityMapValue>();
                            wasCanSignCanSpend = std::pair<bool, bool>({false, false});
                        }
                        else if (nHeight && idHistory.first.blockHeight == nHeight && idHistory.second.txid != identity.txid)
                        {
                            // this is one of more than one identity records in the same block
                            std::vector<std::pair<CIdentityMapKey, CIdentityMapValue>> thisHeightIdentities;
                            CIdentityMapKey heightKey(idID, nHeight);
                            GetIdentity(heightKey, heightKey, thisHeightIdentities);

                            std::map<uint256, std::pair<CIdentityMapKey, CIdentityMapValue>> firstIDMap;
                            for (auto &foundID : thisHeightIdentities)
                            {
                                firstIDMap[foundID.second.txid] = foundID;
                            }

                            if (firstIDMap.count(identity.txid))
                            {
                                doneWithID = true;
                            }
                            else
                            {
                                blockOrder = thisHeightIdentities.size() + 1;
                                firstIDMap.insert(make_pair(identity.txid, 
                                                            make_pair(CIdentityMapKey(idID, 
                                                                                        nHeight,
                                                                                        blockOrder, 
                                                                                        (canSignCanSpend.first ? CIdentityMapKey::CAN_SIGN : 0) + canSignCanSpend.second ? CIdentityMapKey::CAN_SPEND : 0), 
                                                                      identity)));

                                // now we have all the entries of the specified height, including those from before and the new one in the firstIDMap
                                // the #1 in the block is one that has none of its input txes in the map. the last is not present in any input tx
                                // to sort, we make a new map, indexed by the one that it spends, then follow the chain
                                std::map<uint256, std::pair<CIdentityMapKey, CIdentityMapValue>> indexedByPrior;
                                std::pair<CIdentityMapKey, CIdentityMapValue> firstInBlock;

                                for (auto &idEntry : firstIDMap)
                                {
                                    uint256 spendsTxId;
                                    CTransaction entryTx;
                                    uint256 blkHash;
                                    if (!myGetTransaction(idEntry.first, entryTx, blkHash))
                                    {
                                        LogPrint("%s - error: cannot retrieve transaction %s during sort of identity transactions in block, blockchain state may be corrupt and need resynchronization\n", __func__, idEntry.first.GetHex().c_str());
                                    }
                                    else
                                    {
                                        bool isFirst = true;
                                        for (auto &input : entryTx.vin)
                                        {
                                            auto idMapIt = firstIDMap.find(input.prevout.hash);
                                            if (idMapIt != firstIDMap.end())
                                            {
                                                indexedByPrior[input.prevout.hash] = idEntry.second;
                                                isFirst = false;
                                            }
                                        }
                                        if (isFirst)
                                        {
                                            // this should first be added solo, so #1 should always be set
                                            if (idEntry.second.first.blockOrder != 1)
                                            {
                                                LogPrint("%s - error: unexpected block order in %s\n", __func__, idEntry.first.GetHex().c_str());
                                            }
                                            firstInBlock = idEntry.second;
                                        }
                                    }
                                }

                                if (!firstInBlock.first.IsValid())
                                {
                                    LogPrint("%s - error: missing first in block\n", __func__);
                                }
                                else
                                {
                                    // now validate that from 1st to last, we have order correct
                                    std::pair<CIdentityMapKey, CIdentityMapValue> *pCurID;
                                    int i = 1;
                                    for (pCurID = &firstInBlock; pCurID; i++)
                                    {
                                        if (pCurID->first.blockOrder != i)
                                        {
                                            LogPrint("%s - error: incorrect block order in entry %s\n", __func__, pCurID->second.txid.GetHex().c_str());
                                            printf("%s - error: incorrect block order in entry %s\n", __func__, pCurID->second.txid.GetHex().c_str());
                                        }
                                    }
                                }
                            }
                        }
                        else if (nHeight && idHistory.first.blockHeight == nHeight)
                        {
                            // nHeight means this is an add, it has the same txid as an ID already present in the wallet, so we can ignore
                            doneWithID = true;
                        }
                        else
                        {
                            if (idHistory.first.flags & idHistory.first.CAN_SPEND)
                            {
                                wasCanSignCanSpend.first = true;
                                wasCanSignCanSpend.second = true;
                            }
                            else if ((idHistory.first.flags & idHistory.first.CAN_SIGN))
                            {
                                wasCanSignCanSpend.first = true;
                            }
                            // if we are supposed to remove the last entry, do so
                            if (!pblock && txHash == idHistory.second.txid)
                            {
                                RemoveIdentity(idHistory.first, idHistory.second.txid);
                            }
                        }
                    }
                    else if (!pblock)
                    {
                        // not present, nothing to delete
                        doneWithID = true;
                    }

                    if (!doneWithID)
                    {
                        if (pblock)
                        {
                            // if we used to be able to sign with this identity, can now, or we put it on a manual hold, and it's not invalid or blacklisted, store it
                            if ((wasCanSignCanSpend.first || canSignCanSpend.first || (idHistory.first.flags & idHistory.first.MANUAL_HOLD)) && !(idHistory.first.flags & idHistory.first.BLACKLIST))
                            {
                                idMapKey = CIdentityMapKey(identity.GetID(), 
                                                            nHeight, 
                                                            blockOrder, 
                                                            idHistory.first.VALID | 
                                                                ((idHistory.second.IsValid() ? idHistory.first.flags : 0) & idHistory.first.MANUAL_HOLD) | 
                                                                (canSignCanSpend.first ? idHistory.first.CAN_SIGN : 0) | 
                                                                (canSignCanSpend.second ? idHistory.first.CAN_SPEND : 0));
                                AddUpdateIdentity(idMapKey, identity);
                                if (canSignCanSpend.first)
                                {
                                    isNewID = true;
                                }
                            }
                        }
                        else
                        {
                            std::pair<bool, bool> swapBools = canSignCanSpend;
                            canSignCanSpend = wasCanSignCanSpend;
                            wasCanSignCanSpend = swapBools;
                        }

                        // store transitions as needed in the wallet
                        if (canSignCanSpend.first != wasCanSignCanSpend.first || canSignCanSpend.second != wasCanSignCanSpend.second)
                        {
                            // mark all transactions dirty to recalculate numbers
                            for (auto &txidAndWtx : mapWallet)
                            {
                                // mark the whole wallet dirty. if this is an issue, we can optimize.
                                txidAndWtx.second.MarkDirty();
                            }

                            if (canSignCanSpend.first != wasCanSignCanSpend.first)
                            {
                                if (canSignCanSpend.first)
                                {
                                    // add all UTXOs sent to this ID to this wallet
                                    // and also check any other outputs that are sent to this ID to see if they have
                                    // been spent, and if so, add them as spends as well
                                    std::set<std::pair<uint256, uint32_t>> unspentOutputSet;
                                    auto consensus = Params().GetConsensus();

                                    // Do not flush the wallet here for performance reasons
                                    // this is safe, as in case of a crash, we rescan the necessary blocks on startup through our SetBestChain-mechanism
                                    CWalletDB walletdb(strWalletFile, "r+", false);

                                    {
                                        std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue>> unspentOutputs;
                                        GetAddressUnspent(idID, CScript::P2ID, unspentOutputs);

                                        // to prevent forced rescans, don't rescan anything that has too many UTXOs
                                        // unless this is a real rescan, and above a very small threshold, only dynamically scan
                                        // if this wallet holds revoke and recover as well
                                        if (!isRescan &&
                                            unspentOutputs.size() > MAX_UTXOS_ID_RESCAN)
                                        {
                                            if (unspentOutputs.size() > MAX_OUR_UTXOS_ID_RESCAN)
                                            {
                                                unspentOutputs.clear();
                                            }
                                            // the exception would currently be if all of the following are true:
                                            // 1) We have spending, not just signing power over the ID,
                                            // 2) the ID has no separate revoke and recover, so it cannot be pulled back, and
                                            // 3) the ID does not have an average of < 0.00001 in native outputs of a random sample
                                            //    of its UTXOs
                                            if (unspentOutputs.size() &&
                                                canSignCanSpend.second &&
                                                identity.revocationAuthority == identity.recoveryAuthority &&
                                                identity.revocationAuthority == idID)
                                            {
                                                seed_insecure_rand();
                                                std::set<int> counted;
                                                int loopMax = std::min((int)MAX_OUR_UTXOS_ID_RESCAN, (int)unspentOutputs.size());

                                                CAmount total = 0;
                                                for (int loop = 0; loop < loopMax; loop++)
                                                {
                                                    int index = insecure_rand() % unspentOutputs.size();
                                                    int retry = 0;
                                                    for (; counted.count(index) && retry < 2; retry++)
                                                    {
                                                        index = insecure_rand() % unspentOutputs.size();
                                                    }
                                                    if (retry == 2)
                                                    {
                                                        continue;
                                                    }
                                                    counted.insert(index);
                                                    total += unspentOutputs[index].second.satoshis;
                                                }
                                                if (!counted.size() ||
                                                    (total / (CAmount)counted.size() < 10000))
                                                {
                                                    unspentOutputs.clear();
                                                }
                                            }
                                            else if (unspentOutputs.size())
                                            {
                                                unspentOutputs.clear();
                                            }
                                        }

                                        // first, put all the txids of the UTXOs in a set to check intersection with wallet txes
                                        // that may already include outputs to the newly controlled ID. we also need to check wallet
                                        // txes that are not UTXOs to record spends, rather than considering them UTXOs
                                        for (auto &newOut : unspentOutputs)
                                        {
                                            unspentOutputSet.insert(std::make_pair(newOut.first.txhash, newOut.first.index));

                                            txnouttype newTypeRet;
                                            std::vector<CTxDestination> newAddressRet;
                                            int newNRequired;
                                            bool newCanSign, newCanSpend;
                                            const CWalletTx *pWtx = GetWalletTx(newOut.first.txhash);

                                            // check if already present and if its a CC output, so we know it can be sent to an identity
                                            if (pWtx == nullptr)
                                            {
                                                CWalletTx wtx;
                                                if (!(ExtractDestinations(newOut.second.script, newTypeRet, newAddressRet, newNRequired, this, &newCanSign, &newCanSpend, nHeight == 0 ? INT_MAX : nHeight + 1) && newCanSign))
                                                {
                                                    continue;
                                                }
                                                uint256 blkHash;
                                                CTransaction newTx;
                                                if (myGetTransaction(newOut.first.txhash, newTx, blkHash))
                                                {
                                                    wtx = CWalletTx(this, newTx);

                                                    // Get merkle branch if transaction was found in a block
                                                    CBlock block;
                                                    auto blkIndexIt = mapBlockIndex.find(blkHash);
                                                    if (!blkHash.IsNull() && blkIndexIt != mapBlockIndex.end() && chainActive.Contains(blkIndexIt->second))
                                                    {
                                                        // if it's supposed to be in a block, but can't be loaded, don't add without merkle
                                                        if (!ReadBlockFromDisk(block, blkIndexIt->second, consensus))
                                                        {
                                                            continue;
                                                        }
                                                        wtx.SetMerkleBranch(block);
                                                        AddToWallet(wtx, false, &walletdb);
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    std::vector<std::pair<const CWalletTx *, uint32_t>> checkIfSpent;

                                    // now, look through existing wallet txes for outputs to the ID, which we did not, but now will
                                    // consider as ours and add them to the outputs that need to be checked
                                    for (auto &wtx : mapWallet)
                                    {
                                        for (int k = 0; k < wtx.second.vout.size(); k++)
                                        {
                                            // if it's not in the chain, or already in the unspent set, we don't need to check it further
                                            if (!wtx.second.IsInMainChain() ||
                                                unspentOutputSet.count(std::make_pair(wtx.first, k)))
                                            {
                                                continue;
                                            }

                                            const CTxOut &oneOut = wtx.second.vout[k];
                                            txnouttype newTypeRet;
                                            std::vector<CTxDestination> newAddressRet;
                                            int newNRequired;
                                            bool newCanSign, newCanSpend;

                                            // if we think this output isn't spent and we couldn't sign for it, but the ID enables us to,
                                            // then we need to check it further to see if we need to add other spending txes now
                                            if (IsSpent(wtx.first, k) ||
                                                (ExtractDestinations(oneOut.scriptPubKey, newTypeRet, newAddressRet, newNRequired, this, &newCanSign, &newCanSpend, nHeight == 0 ? INT_MAX : nHeight) && newCanSign))
                                            {
                                                continue;
                                            }

                                            for (auto &oneDest : newAddressRet)
                                            {
                                                if (oneDest.which() == COptCCParams::ADDRTYPE_ID && GetDestinationID(oneDest) == idID)
                                                {
                                                    checkIfSpent.push_back(std::make_pair(&wtx.second, k));
                                                    break;
                                                }
                                            }
                                        }
                                    }

                                    // now we have a list of outputs that were in our wallet, are sent to the new ID, are not known
                                    // by the wallet to be spent, but are almost certainly spent, since they are also not in the unspent
                                    // results for the ID.
                                    // that means we need to trace their spent state and add the forward chain of their spending to the
                                    // wallet.

                                    txnouttype newTypeRet;
                                    std::vector<CTxDestination> newAddressRet;
                                    int newNRequired;
                                    bool newCanSign, newCanSpend;

                                    // while we know there is an unspent index to this ID on the new transaction output, we don't know
                                    // if there are other outputs to this ID on the transaction, which are already spent.
                                    // if so, we need to record the spends in the wallet as well, or it will add them but
                                    // not consider them spent.
                                    uint256 spendBlkHash;
                                    CTransaction spendTx;

                                    for (int i = 0; i < checkIfSpent.size(); i++)
                                    {
                                        const CWalletTx *txToCheck = checkIfSpent[i].first;

                                        CSpentIndexValue spentInfo;
                                        CSpentIndexKey spentKey(txToCheck->GetHash(), checkIfSpent[i].second);

                                        // if it's spent, we need to put spender in the wallet
                                        // if the spender has outputs that we can now spend due to the ID,
                                        // we need to check for those being spent as well
                                        if (GetSpentIndex(spentKey, spentInfo) &&
                                            !spentInfo.IsNull())
                                        {
                                            const CWalletTx *pSpendingTx = GetWalletTx(spentInfo.txid);
                                            if (pSpendingTx == nullptr &&
                                                spentInfo.blockHeight <= nHeight &&
                                                myGetTransaction(spentInfo.txid, spendTx, spendBlkHash) &&
                                                !spendBlkHash.IsNull())
                                            {
                                                CWalletTx spendWtx(this, spendTx);

                                                // Get merkle branch if transaction was found in a block
                                                CBlock spendBlock;
                                                auto spendBlkIndexIt = mapBlockIndex.find(spendBlkHash);
                                                if (spendBlkIndexIt != mapBlockIndex.end() &&
                                                    chainActive.Contains(spendBlkIndexIt->second) &&
                                                    ReadBlockFromDisk(spendBlock, spendBlkIndexIt->second, consensus))
                                                {
                                                    spendWtx.SetMerkleBranch(spendBlock);
                                                    AddToWallet(spendWtx, false, &walletdb);
                                                    const CWalletTx *pNewWTx = GetWalletTx(spendWtx.GetHash());
                                                    if (!pNewWTx)
                                                    {
                                                        LogPrintf("%s: ERROR: Failure to add transaction %s to wallet\n", __func__, spendWtx.GetHash().GetHex().c_str());
                                                        continue;
                                                    }

                                                    // add these outputs to the outputs we need to check if spent
                                                    // as long as we are adding spending transactions that are earlier
                                                    // or up to this height, we follow the spends
                                                    for (int counter = 0; counter < pNewWTx->vout.size(); counter++)
                                                    {
                                                        if (IsSpent(pNewWTx->GetHash(), counter) ||
                                                            (ExtractDestinations(pNewWTx->vout[counter].scriptPubKey, newTypeRet, newAddressRet, newNRequired, this, &newCanSign, &newCanSpend, nHeight == 0 ? INT_MAX : nHeight) && newCanSign))
                                                        {
                                                            continue;
                                                        }

                                                        for (auto &oneDest : newAddressRet)
                                                        {
                                                            if (oneDest.which() == COptCCParams::ADDRTYPE_ID && GetDestinationID(oneDest) == idID)
                                                            {
                                                                checkIfSpent.push_back(std::make_pair(pNewWTx, counter));
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    // we have gone from canSign to no control over this ID, either by deletion of tx or removal from signers. this will take effect retroactively on deletion and next block on addition
                                    // 1. remove all transactions that have UTXOs sent to this ID and are no longer can sign or can spend for us from the wallet
                                    // 2. if deletion, remove all transactions since the last idHistory that are in the wallet due to this ID
                                    // 3. remove all IDs from the wallet that are found in those removed transactions, are neither canSpend nor canSign, and are neither on manual hold nor present on any remaining transactions
                                    // 4. remove any transactions that are only in the wallet because they spend an output that was sent to this ID

                                    std::set<CIdentityID> idsToCheck = std::set<CIdentityID>();

                                    if (!pblock)
                                    {
                                        idsToCheck.insert(idID);
                                    }

                                    // first and last blocks to consider when deleting spent transactions from the wallet
                                    uint32_t deleteSpentFrom;
                                    
                                    if (!pblock)
                                    {
                                        deleteSpentFrom = idHistory.first.blockHeight + 1;
                                    }
                                    else
                                    {
                                        deleteSpentFrom = idMapKey.blockHeight + 1;
                                    }

                                    std::map<const uint256 *, CWalletTx *> txesToErase;

                                    for (auto &txidAndWtx : mapWallet)
                                    {
                                        const CBlockIndex *pIndex;
                                        if (txidAndWtx.second.GetDepthInMainChain(pIndex) > 0 && pIndex->GetHeight() <= deleteSpentFrom)
                                        {
                                            continue;
                                        }

                                        txnouttype txType;
                                        std::vector<CTxDestination> addresses;
                                        int minSigs;
                                        bool eraseTx = true;
                                        int i = 0;
                                        uint256 hashTx = txidAndWtx.second.GetHash();

                                        // if we still have z-address notes on the transaction, don't delete
                                        auto sprNoteData = FindMySproutNotes(txidAndWtx.second);
                                        auto sapNoteDataAndAddressesToAdd = FindMySaplingNotes(txidAndWtx.second);
                                        if (sprNoteData.size() || sapNoteDataAndAddressesToAdd.first.size())
                                        {
                                            // don't erase the tx, but check to erase IDs
                                            eraseTx = false;
                                        }

                                        // if the tx is spending from another in this wallet, we will not erase it
                                        // but check destinations before deciding not to erase IDs
                                        if (IsFromMe(txidAndWtx.second, deleteSpentFrom - 1))
                                        {
                                            eraseTx = false;
                                        }

                                        // look for a reason not to delete this tx or IDs it is sent to
                                        for (auto txout : txidAndWtx.second.vout)
                                        {
                                            // we only want to remove UTXOs that are sent to this ID, used to be ours, and are no longer cansign
                                            if (!txout.scriptPubKey.IsPayToCryptoCondition() || IsSpent(hashTx, i))
                                            {
                                                // if this is ours, we will not erase the tx
                                                // we already checked IsFromMe
                                                if (IsMine(txout))
                                                {
                                                    eraseTx = false;
                                                    continue;
                                                }
                                            }
                                            bool canSignOut = false;
                                            bool canSpendOut = false;

                                            if (ExtractDestinations(txout.scriptPubKey, txType, addresses, minSigs, this, &canSignOut, &canSpendOut, nHeight == 0 ? INT_MAX : nHeight + 1))
                                            {
                                                if (canSignOut || canSpendOut)
                                                {
                                                    // we should keep this transaction anyhow, check next
                                                    eraseTx = false;
                                                    continue;
                                                }

                                                for (auto &dest : addresses)
                                                {
                                                    if (dest.which() == COptCCParams::ADDRTYPE_ID)
                                                    {
                                                        idsToCheck.insert(GetDestinationID(dest));
                                                    }
                                                }
                                            }

                                            i++;
                                        }
                                        if (eraseTx)
                                        {
                                            txesToErase.insert(make_pair(&txidAndWtx.first, &txidAndWtx.second));
                                        }
                                    }

                                    for (auto &oneTx : txesToErase)
                                    {
                                        EraseFromWallet(*oneTx.first);
                                    }

                                    if (pblock && idsToCheck.count(idID))
                                    {
                                        // do not remove the current identity that was just added to take away our authority
                                        // that is an important record to keep
                                        idsToCheck.erase(idID);
                                    }

                                    // now, we've deleted all transactions that were only in the wallet due to our ability to sign with the ID we just lost
                                    // loop through all transactions and remove all IDs found in the remaining transactions from our idsToCheck set after we 
                                    // have gone through all wallet transactions, we can delete all IDs remaining in the idsToCheck set
                                    // that are not on manual hold
                                    for (auto &txidAndWtx : mapWallet)
                                    {
                                        for (auto txout : txidAndWtx.second.vout)
                                        {
                                            if (!txout.scriptPubKey.IsPayToCryptoCondition())
                                            {
                                                continue;
                                            }
                                            bool canSignOut = false;
                                            bool canSpendOut = false;
                                            txnouttype txType;
                                            std::vector<CTxDestination> addresses;
                                            int minSigs;
                                            if (ExtractDestinations(txout.scriptPubKey, txType, addresses, minSigs, this, &canSignOut, &canSpendOut, nHeight == 0 ? INT_MAX : nHeight + 1))
                                            {
                                                if (canSignOut || canSpendOut)
                                                {
                                                    for (auto &dest : addresses)
                                                    {
                                                        if (dest.which() == COptCCParams::ADDRTYPE_ID)
                                                        {
                                                            idsToCheck.erase(GetDestinationID(dest));
                                                            if (!idsToCheck.size())
                                                            {
                                                                break;
                                                            }
                                                        }
                                                    }
                                                }                                                
                                            }
                                            if (!idsToCheck.size())
                                            {
                                                break;
                                            }
                                        }
                                        if (!idsToCheck.size())
                                        {
                                            break;
                                        }
                                    }

                                    // delete all remaining IDs that are not held for manual hold
                                    for (auto &idToRemove : idsToCheck)
                                    {
                                        std::pair<CIdentityMapKey, CIdentityMapValue> identityToRemove;

                                        // if not cansign or canspend, no transactions we care about relating to it and no manual hold, delete the ID from the wallet
                                        // also keep the first transition after one we will keep
                                        if (GetIdentity(idToRemove, identityToRemove) && 
                                            !((identityToRemove.first.flags & (identityToRemove.first.CAN_SIGN + identityToRemove.first.CAN_SPEND)) || identityToRemove.first.flags & identityToRemove.first.MANUAL_HOLD))
                                        {
                                            std::pair<CIdentityMapKey, CIdentityMapValue> priorIdentity;

                                            if (!GetPriorIdentity(identityToRemove.first, priorIdentity) ||
                                                !((priorIdentity.first.flags & (priorIdentity.first.CAN_SIGN + priorIdentity.first.CAN_SPEND)) || identityToRemove.first.flags & identityToRemove.first.MANUAL_HOLD))
                                            {
                                                // if we don't have recovery on a revoked ID in our wallet, then remove it
                                                std::pair<CIdentityMapKey, CIdentityMapValue> recoveryIdentity;
                                                if (!identityToRemove.second.IsRevoked() || !GetIdentity(identityToRemove.second.recoveryAuthority, recoveryIdentity) || !(recoveryIdentity.first.flags & recoveryIdentity.first.CAN_SIGN))
                                                {
                                                    RemoveIdentity(CIdentityMapKey(idToRemove));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // for IsMine, the default height is max, not 0
        nHeight = nHeight == 0 ? INT_MAX : nHeight;
        if (fExisted || isNewID || IsMine(tx, nHeight) || IsFromMe(tx, nHeight) || sproutNoteData.size() > 0 || saplingNoteData.size() > 0)
        {
            CWalletTx wtx(this, tx);

            if (sproutNoteData.size() > 0) {
                wtx.SetSproutNoteData(sproutNoteData);
            }

            if (saplingNoteData.size() > 0) {
                wtx.SetSaplingNoteData(saplingNoteData);
            }

            // Get merkle branch if transaction was found in a block
            if (pblock)
                wtx.SetMerkleBranch(*pblock);

            // Do not flush the wallet here for performance reasons
            // this is safe, as in case of a crash, we rescan the necessary blocks on startup through our SetBestChain-mechanism
            CWalletDB walletdb(strWalletFile, "r+", false);

            return AddToWallet(wtx, false, &walletdb);
        }
    }
    return false;
}

void CWallet::SyncTransaction(const CTransaction& tx, const CBlock* pblock)
{
    LOCK2(cs_main, cs_wallet);
    if (!AddToWalletIfInvolvingMe(tx, pblock, true, false))
        return; // Not one of ours

    MarkAffectedTransactionsDirty(tx);
}

void CWallet::MarkAffectedTransactionsDirty(const CTransaction& tx)
{
    // If a transaction changes 'conflicted' state, that changes the balance
    // available of the outputs it spends. So force those to be
    // recomputed, also:
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (mapWallet.count(txin.prevout.hash))
            mapWallet[txin.prevout.hash].MarkDirty();
    }
    for (const JSDescription& jsdesc : tx.vJoinSplit) {
        for (const uint256& nullifier : jsdesc.nullifiers) {
            if (mapSproutNullifiersToNotes.count(nullifier) &&
                mapWallet.count(mapSproutNullifiersToNotes[nullifier].hash)) {
                mapWallet[mapSproutNullifiersToNotes[nullifier].hash].MarkDirty();
            }
        }
    }

    for (const SpendDescription &spend : tx.vShieldedSpend) {
        uint256 nullifier = spend.nullifier;
        if (mapSaplingNullifiersToNotes.count(nullifier) &&
            mapWallet.count(mapSaplingNullifiersToNotes[nullifier].hash)) {
            mapWallet[mapSaplingNullifiersToNotes[nullifier].hash].MarkDirty();
        }
    }
}

void CWallet::EraseFromWallet(const uint256 &hash)
{
    if (!fFileBacked)
        return;
    {
        LOCK(cs_wallet);
        if (mapWallet.erase(hash))
            CWalletDB(strWalletFile).EraseTx(hash);
    }
    return;
}

void CWallet::RescanWallet()
{
    if (needsRescan)
    {
        CBlockIndex *start = chainActive.Height() > 0 ? chainActive[1] : NULL;
        if (start)
            ScanForWalletTransactions(start, true);
        needsRescan = false;
    }
}


/**
 * Returns a nullifier if the SpendingKey is available
 * Throws std::runtime_error if the decryptor doesn't match this note
 */
boost::optional<uint256> CWallet::GetSproutNoteNullifier(const JSDescription &jsdesc,
                                                         const libzcash::SproutPaymentAddress &address,
                                                         const ZCNoteDecryption &dec,
                                                         const uint256 &hSig,
                                                         uint8_t n) const
{
    boost::optional<uint256> ret;
    auto note_pt = libzcash::SproutNotePlaintext::decrypt(
        dec,
        jsdesc.ciphertexts[n],
        jsdesc.ephemeralKey,
        hSig,
        (unsigned char) n);
    auto note = note_pt.note(address);

    // Check note plaintext against note commitment
    if (note.cm() != jsdesc.commitments[n]) {
        throw libzcash::note_decryption_failed();
    }

    // SpendingKeys are only available if:
    // - We have them (this isn't a viewing key)
    // - The wallet is unlocked
    libzcash::SproutSpendingKey key;
    if (GetSproutSpendingKey(address, key)) {
        ret = note.nullifier(key);
    }
    return ret;
}

/**
 * Finds all output notes in the given transaction that have been sent to
 * PaymentAddresses in this wallet.
 *
 * It should never be necessary to call this method with a CWalletTx, because
 * the result of FindMySproutNotes (for the addresses available at the time) will
 * already have been cached in CWalletTx.mapSproutNoteData.
 */
mapSproutNoteData_t CWallet::FindMySproutNotes(const CTransaction &tx) const
{
    LOCK(cs_SpendingKeyStore);
    uint256 hash = tx.GetHash();

    mapSproutNoteData_t noteData;
    for (size_t i = 0; i < tx.vJoinSplit.size(); i++) {
        auto hSig = tx.vJoinSplit[i].h_sig(*pzcashParams, tx.joinSplitPubKey);
        for (uint8_t j = 0; j < tx.vJoinSplit[i].ciphertexts.size(); j++) {
            for (const NoteDecryptorMap::value_type& item : mapNoteDecryptors) {
                try {
                    auto address = item.first;
                    JSOutPoint jsoutpt {hash, i, j};
                    auto nullifier = GetSproutNoteNullifier(
                        tx.vJoinSplit[i],
                        address,
                        item.second,
                        hSig, j);
                    if (nullifier) {
                        SproutNoteData nd {address, *nullifier};
                        noteData.insert(std::make_pair(jsoutpt, nd));
                    } else {
                        SproutNoteData nd {address};
                        noteData.insert(std::make_pair(jsoutpt, nd));
                    }
                    break;
                } catch (const note_decryption_failed &err) {
                    // Couldn't decrypt with this decryptor
                } catch (const std::exception &exc) {
                    // Unexpected failure
                    LogPrintf("FindMySproutNotes(): Unexpected error while testing decrypt:\n");
                    LogPrintf("%s\n", exc.what());
                }
            }
        }
    }
    return noteData;
}


/**
 * Finds all output notes in the given transaction that have been sent to
 * SaplingPaymentAddresses in this wallet.
 *
 * It should never be necessary to call this method with a CWalletTx, because
 * the result of FindMySaplingNotes (for the addresses available at the time) will
 * already have been cached in CWalletTx.mapSaplingNoteData.
 */
std::pair<mapSaplingNoteData_t, SaplingIncomingViewingKeyMap> CWallet::FindMySaplingNotes(const CTransaction &tx) const
{
    LOCK(cs_SpendingKeyStore);
    uint256 hash = tx.GetHash();

    mapSaplingNoteData_t noteData;
    SaplingIncomingViewingKeyMap viewingKeysToAdd;

    // Protocol Spec: 4.19 Block Chain Scanning (Sapling)
    for (uint32_t i = 0; i < tx.vShieldedOutput.size(); ++i) {
        const OutputDescription output = tx.vShieldedOutput[i];
        for (auto it = mapSaplingFullViewingKeys.begin(); it != mapSaplingFullViewingKeys.end(); ++it) {
            SaplingIncomingViewingKey ivk = it->first;
            auto result = SaplingNotePlaintext::decrypt(output.encCiphertext, ivk, output.ephemeralKey, output.cm);
            if (!result) {
                continue;
            }
            auto address = ivk.address(result.get().d);
            if (address && mapSaplingIncomingViewingKeys.count(address.get()) == 0) {
                viewingKeysToAdd[address.get()] = ivk;
            }
            // We don't cache the nullifier here as computing it requires knowledge of the note position
            // in the commitment tree, which can only be determined when the transaction has been mined.
            SaplingOutPoint op {hash, i};
            SaplingNoteData nd;
            nd.ivk = ivk;
            noteData.insert(std::make_pair(op, nd));
            break;
        }
    }

    return std::make_pair(noteData, viewingKeysToAdd);
}

bool CWallet::IsSproutNullifierFromMe(const uint256& nullifier) const
{
    {
        LOCK(cs_wallet);
        if (mapSproutNullifiersToNotes.count(nullifier) &&
                mapWallet.count(mapSproutNullifiersToNotes.at(nullifier).hash)) {
            return true;
        }
    }
    return false;
}

bool CWallet::IsSaplingNullifierFromMe(const uint256& nullifier) const
{
    {
        LOCK(cs_wallet);
        if (mapSaplingNullifiersToNotes.count(nullifier) &&
                mapWallet.count(mapSaplingNullifiersToNotes.at(nullifier).hash)) {
            return true;
        }
    }
    return false;
}

void CWallet::GetSproutNoteWitnesses(std::vector<JSOutPoint> notes,
                                     std::vector<boost::optional<SproutWitness>>& witnesses,
                                     uint256 &final_anchor)
{
    LOCK(cs_wallet);
    witnesses.resize(notes.size());
    boost::optional<uint256> rt;
    int i = 0;
    for (JSOutPoint note : notes) {
        if (mapWallet.count(note.hash) &&
                mapWallet[note.hash].mapSproutNoteData.count(note) &&
                mapWallet[note.hash].mapSproutNoteData[note].witnesses.size() > 0) {
            witnesses[i] = mapWallet[note.hash].mapSproutNoteData[note].witnesses.front();
            if (!rt) {
                rt = witnesses[i]->root();
            } else {
                assert(*rt == witnesses[i]->root());
            }
        }
        i++;
    }
    // All returned witnesses have the same anchor
    if (rt) {
        final_anchor = *rt;
    }
}

void CWallet::GetSaplingNoteWitnesses(std::vector<SaplingOutPoint> notes,
                                      std::vector<boost::optional<SaplingWitness>>& witnesses,
                                      uint256 &final_anchor)
{
    LOCK(cs_wallet);
    witnesses.resize(notes.size());
    boost::optional<uint256> rt;
    int i = 0;
    for (SaplingOutPoint note : notes) {
        if (mapWallet.count(note.hash) &&
                mapWallet[note.hash].mapSaplingNoteData.count(note) &&
                mapWallet[note.hash].mapSaplingNoteData[note].witnesses.size() > 0) {
            witnesses[i] = mapWallet[note.hash].mapSaplingNoteData[note].witnesses.front();
            if (!rt) {
                rt = witnesses[i]->root();
            } else {
                assert(*rt == witnesses[i]->root());
            }
        }
        i++;
    }
    // All returned witnesses have the same anchor
    if (rt) {
        final_anchor = *rt;
    }
}

isminetype CWallet::IsMine(const CTxIn &txin, uint32_t nHeight) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                return (::IsMine(*this, prev.vout[txin.prevout.n].scriptPubKey, nHeight));
        }
    }
    return ISMINE_NO;
}

CAmount CWallet::GetDebit(const CTxIn &txin, const isminefilter& filter, uint32_t nHeight) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (::IsMine(*this, prev.vout[txin.prevout.n].scriptPubKey, nHeight) & filter)
                    return prev.vout[txin.prevout.n].nValue; // komodo_interest?
        }
    }
    return 0;
}

CCurrencyValueMap CWallet::GetReserveDebit(const CTxIn &txin, const isminefilter& filter, uint32_t nHeight) const
{
    {
        LOCK(cs_wallet);
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
        if (mi != mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
                if (::IsMine(*this, prev.vout[txin.prevout.n].scriptPubKey, nHeight) & filter)
                    return prev.vout[txin.prevout.n].ReserveOutValue();
        }
    }
    return CCurrencyValueMap();
}

isminetype CWallet::IsMine(const CTxOut& txout, uint32_t nHeight) const
{
    return ::IsMine(*this, txout.scriptPubKey, nHeight);
}

CAmount CWallet::GetCredit(const CTxOut& txout, const isminefilter& filter, uint32_t nHeight) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CWallet::GetCredit(): value out of range");
    return ((IsMine(txout, nHeight) & filter) ? txout.nValue : 0);
}

bool CWallet::IsChange(const CTxOut& txout) const
{
    // TODO: fix handling of 'change' outputs. The assumption is that any
    // payment to a script that is ours, but is not in the address book
    // is change. That assumption is likely to break when we implement multisignature
    // wallets that return change back into a multi-signature-protected address;
    // a better way of identifying which outputs are 'the send' and which are
    // 'the change' will need to be implemented (maybe extend CWalletTx to remember
    // which output, if any, was change).
    if (::IsMine(*this, txout.scriptPubKey))
    {
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
            return true;

        LOCK(cs_wallet);
        if (!mapAddressBook.count(address))
            return true;
    }
    return false;
}

CAmount CWallet::GetChange(const CTxOut& txout) const
{
    if (!MoneyRange(txout.nValue))
        throw std::runtime_error("CWallet::GetChange(): value out of range");
    return (IsChange(txout) ? txout.nValue : 0);
}

typedef vector<unsigned char> valtype;
unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore);

bool CWallet::IsMine(const CTransaction& tx, uint32_t nHeight)
{
    for (int i = 0; i < tx.vout.size(); i++)
    {
        isminetype mine;
        IsMine(tx, i, mine, nHeight);
        if (mine)
            return true;
    }
    return false;
}

// special case handling for non-standard/Verus OP_RETURN script outputs, which need the transaction
// to determine ownership
void CWallet::IsMine(const CTransaction& tx, uint32_t voutNum, isminetype &mine, uint32_t nHeight)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    CScript scriptPubKey = tx.vout[voutNum].scriptPubKey;

    if (scriptPubKey.IsCheckLockTimeVerify())
    {
        uint8_t pushOp = scriptPubKey[0];
        uint32_t scriptStart = pushOp + 3;

        // continue with post CLTV script
        scriptPubKey = CScript(scriptPubKey.size() > scriptStart ? scriptPubKey.begin() + scriptStart : scriptPubKey.end(), scriptPubKey.end());
    }

    COptCCParams p;
    if (scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
    {
        std::vector<CTxDestination> dests;
        int minSigs;
        bool canSign = false;
        bool canSpend = false;

        if (ExtractDestinations(scriptPubKey, whichType, dests, minSigs, this, &canSign, &canSpend, nHeight))
        {
            if (canSpend)
            {
                mine = ISMINE_SPENDABLE;
                return;
            }
            else if (canSign)
            {
                mine = ISMINE_WATCH_ONLY;
                return;
            }
            else
            {
                mine = ISMINE_NO;
                return;
            }
        }
        else
        {
            mine = ISMINE_NO;
            return;
        }
    }
    else if (!Solver(scriptPubKey, whichType, vSolutions))
    {
        if (this->HaveWatchOnly(scriptPubKey))
        {
            mine = ISMINE_WATCH_ONLY;
            return;
        }
        mine = ISMINE_NO;
        return;
    }

    CKeyID keyID;
    CScriptID scriptID;
    CScriptExt subscript;
    int voutNext = voutNum + 1;

    switch (whichType)
    {
        case TX_NONSTANDARD:
        case TX_NULL_DATA:
            break;

        case TX_CRYPTOCONDITION:
            // for now, default is that the first value returned will be the target address, subsequent values will be
            // pubkeys. if we have the first in our wallet, we consider it spendable for now
            if (vSolutions[0].size() == 33)
            {
                keyID = CPubKey(vSolutions[0]).GetID();
            }
            else if (vSolutions[0].size() == 20)
            {
                keyID = CKeyID(uint160(vSolutions[0]));
            }
            if (!keyID.IsNull() && HaveKey(keyID))
            {
                mine = ISMINE_SPENDABLE;
                return;
            }
            break;

        case TX_PUBKEY:
            keyID = CPubKey(vSolutions[0]).GetID();
            if (this->HaveKey(keyID))
            {
                mine = ISMINE_SPENDABLE;
                return;
            }
            break;

        case TX_PUBKEYHASH:
            keyID = CKeyID(uint160(vSolutions[0]));
            if (this->HaveKey(keyID))
            {
                mine = ISMINE_SPENDABLE;
                return;
            }
            break;

        case TX_SCRIPTHASH:
            scriptID = CScriptID(uint160(vSolutions[0]));
            if (this->GetCScript(scriptID, subscript)) 
            {
                // if this is a CLTV, handle it differently
                if (subscript.IsCheckLockTimeVerify())
                {
                    mine = (::IsMine(*this, subscript));
                    return;
                }
                else
                {
                    isminetype ret = ::IsMine(*this, subscript);
                    if (ret == ISMINE_SPENDABLE)
                    {
                        mine = ret;
                        return;
                    }
                }
            }
            else if (tx.vout.size() > (voutNum + 1) &&
                tx.vout.back().scriptPubKey.size() > 7 &&
                tx.vout.back().scriptPubKey[0] == OP_RETURN)
            {
                // get the opret script from next vout, verify that the front is CLTV and hash matches
                // if so, remove it and use the solver
                opcodetype op;
                std::vector<uint8_t> opretData;
                CScript::const_iterator it = tx.vout.back().scriptPubKey.begin() + 1;
                if (tx.vout.back().scriptPubKey.GetOp2(it, op, &opretData))
                {
                    if (opretData.size() > 0 && opretData[0] == OPRETTYPE_TIMELOCK)
                    {
                        CScript opretScript = CScript(opretData.begin() + 1, opretData.end());

                        if (CScriptID(opretScript) == scriptID &&
                            opretScript.IsCheckLockTimeVerify())
                        {
                            // if we find that this is ours, we need to add this script to the wallet,
                            // and we can then recognize this transaction
                            isminetype t = ::IsMine(*this, opretScript);
                            if (t != ISMINE_NO)
                            {
                                this->AddCScript(opretScript);
                            }
                            mine = t;
                            return;
                        }
                    }
                }
            }
            break;

        case TX_MULTISIG:
            // Only consider transactions "mine" if we own ALL the
            // keys involved. Multi-signature transactions that are
            // partially owned (somebody else has a key that can spend
            // them) enable spend-out-from-under-you attacks, especially
            // in shared-wallet situations.
            vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
            if (HaveKeys(keys, *this) == keys.size())
            {
                mine = ISMINE_SPENDABLE;
                return;
            }
            break;
    }

    if (this->HaveWatchOnly(scriptPubKey))
    {
        mine = ISMINE_WATCH_ONLY;
        return;
    }

    mine = ISMINE_NO;
}

bool CWallet::IsFromMe(const CTransaction& tx, uint32_t height) const
{
    {
        LOCK(cs_wallet);
        for (auto &txin : tx.vin)
        {
            map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(txin.prevout.hash);
            if (mi != mapWallet.end())
            {
                const CWalletTx& prev = (*mi).second;
                if (txin.prevout.n < prev.vout.size())
                {
                    if (::IsMine(*this, prev.vout[txin.prevout.n].scriptPubKey, height) & ISMINE_ALL)
                        return true;
                }
            }
        }
    }
    for (const JSDescription& jsdesc : tx.vJoinSplit) {
        for (const uint256& nullifier : jsdesc.nullifiers) {
            if (IsSproutNullifierFromMe(nullifier)) {
                return true;
            }
        }
    }
    for (const SpendDescription &spend : tx.vShieldedSpend) {
        if (IsSaplingNullifierFromMe(spend.nullifier)) {
            return true;
        }
    }
    return false;
}

CAmount CWallet::GetDebit(const CTransaction& tx, const isminefilter& filter, uint32_t nHeight) const
{
    CAmount nDebit = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        nDebit += GetDebit(txin, filter, nHeight);
        if (!MoneyRange(nDebit))
            throw std::runtime_error("CWallet::GetDebit(): value out of range");
    }
    return nDebit;
}

CCurrencyValueMap CWallet::GetReserveDebit(const CTransaction& tx, const isminefilter& filter, uint32_t nHeight) const
{
    CCurrencyValueMap retVal;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        retVal += GetReserveDebit(txin, filter, nHeight);
    }
    return retVal;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const int32_t &voutNum, const isminefilter& filter, uint32_t nHeight) const
{
    if (voutNum >= tx.vout.size() || !MoneyRange(tx.vout[voutNum].nValue))
        throw std::runtime_error("CWallet::GetCredit(): value out of range");
    return ((IsMine(tx.vout[voutNum], nHeight) & filter) ? tx.vout[voutNum].nValue : 0);
}

CCurrencyValueMap CWallet::GetReserveCredit(const CTransaction& tx, int32_t voutNum, const isminefilter& filter) const
{
    return ((IsMine(tx.vout[voutNum]) & filter) ? tx.vout[voutNum].ReserveOutValue() : CCurrencyValueMap());
}

CCurrencyValueMap CWallet::GetReserveCredit(const CTransaction& tx, const isminefilter& filter) const
{
    CCurrencyValueMap nCredit;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        nCredit += GetReserveCredit(tx, i, filter);
    }
    return nCredit;
}

CAmount CWallet::GetCredit(const CTransaction& tx, const isminefilter& filter, uint32_t nHeight) const
{
    CAmount nCredit = 0;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        nCredit += GetCredit(tx, i, filter, nHeight);
    }
    return nCredit;
}

CAmount CWallet::GetChange(const CTransaction& tx) const
{
    CAmount nChange = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        nChange += GetChange(txout);
        if (!MoneyRange(nChange))
            throw std::runtime_error("CWallet::GetChange(): value out of range");
    }
    return nChange;
}

bool CWallet::IsHDFullyEnabled() const
{
    // Only Sapling addresses are HD for now
    return false;
}

void CWallet::GenerateNewSeed()
{
    LOCK(cs_wallet);

    auto seed = HDSeed::Random(HD_WALLET_SEED_LENGTH);

    int64_t nCreationTime = GetTime();

    // If the wallet is encrypted and locked, this will fail.
    if (!SetHDSeed(seed))
        throw std::runtime_error(std::string(__func__) + ": SetHDSeed failed");

    // store the key creation time together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.nVersion = CHDChain::VERSION_HD_BASE;
    newHdChain.seedFp = seed.Fingerprint();
    newHdChain.nCreateTime = nCreationTime;
    SetHDChain(newHdChain, false);
}

bool CWallet::SetHDSeed(const HDSeed& seed)
{
    if (!CCryptoKeyStore::SetHDSeed(seed)) {
        return false;
    }

    if (!fFileBacked) {
        return true;
    }

    {
        LOCK(cs_wallet);
        if (!IsCrypted()) {
            return CWalletDB(strWalletFile).WriteHDSeed(seed);
        }
    }
    return true;
}

bool CWallet::SetCryptedHDSeed(const uint256& seedFp, const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::SetCryptedHDSeed(seedFp, vchCryptedSecret)) {
        return false;
    }

    if (!fFileBacked) {
        return true;
    }

    {
        LOCK(cs_wallet);
        if (pwalletdbEncryption)
            return pwalletdbEncryption->WriteCryptedHDSeed(seedFp, vchCryptedSecret);
        else
            return CWalletDB(strWalletFile).WriteCryptedHDSeed(seedFp, vchCryptedSecret);
    }
    return false;
}

HDSeed CWallet::GetHDSeedForRPC() const {
    HDSeed seed;
    if (!pwalletMain->GetHDSeed(seed)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "HD seed not found");
    }
    return seed;
}

void CWallet::SetHDChain(const CHDChain& chain, bool memonly)
{
    LOCK(cs_wallet);
    if (!memonly && fFileBacked && !CWalletDB(strWalletFile).WriteHDChain(chain))
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");

    hdChain = chain;
}

bool CWallet::LoadHDSeed(const HDSeed& seed)
{
    return CBasicKeyStore::SetHDSeed(seed);
}

bool CWallet::LoadCryptedHDSeed(const uint256& seedFp, const std::vector<unsigned char>& seed)
{
    return CCryptoKeyStore::SetCryptedHDSeed(seedFp, seed);
}

void CWalletTx::SetSproutNoteData(mapSproutNoteData_t &noteData)
{
    mapSproutNoteData.clear();
    for (const std::pair<JSOutPoint, SproutNoteData> nd : noteData) {
        if (nd.first.js < vJoinSplit.size() &&
                nd.first.n < vJoinSplit[nd.first.js].ciphertexts.size()) {
            // Store the address and nullifier for the Note
            mapSproutNoteData[nd.first] = nd.second;
        } else {
            // If FindMySproutNotes() was used to obtain noteData,
            // this should never happen
            throw std::logic_error("CWalletTx::SetSproutNoteData(): Invalid note");
        }
    }
}

void CWalletTx::SetSaplingNoteData(mapSaplingNoteData_t &noteData)
{
    mapSaplingNoteData.clear();
    for (const std::pair<SaplingOutPoint, SaplingNoteData> nd : noteData) {
        if (nd.first.n < vShieldedOutput.size()) {
            mapSaplingNoteData[nd.first] = nd.second;
        } else {
            throw std::logic_error("CWalletTx::SetSaplingNoteData(): Invalid note");
        }
    }
}

std::pair<SproutNotePlaintext, SproutPaymentAddress> CWalletTx::DecryptSproutNote(
    JSOutPoint jsop) const
{
    LOCK(pwallet->cs_wallet);

    auto nd = this->mapSproutNoteData.at(jsop);
    SproutPaymentAddress pa = nd.address;

    // Get cached decryptor
    ZCNoteDecryption decryptor;
    if (!pwallet->GetNoteDecryptor(pa, decryptor)) {
        // Note decryptors are created when the wallet is loaded, so it should always exist
        throw std::runtime_error(strprintf(
            "Could not find note decryptor for payment address %s",
            EncodePaymentAddress(pa)));
    }

    auto hSig = this->vJoinSplit[jsop.js].h_sig(*pzcashParams, this->joinSplitPubKey);
    try {
        SproutNotePlaintext plaintext = SproutNotePlaintext::decrypt(
                decryptor,
                this->vJoinSplit[jsop.js].ciphertexts[jsop.n],
                this->vJoinSplit[jsop.js].ephemeralKey,
                hSig,
                (unsigned char) jsop.n);

        return std::make_pair(plaintext, pa);
    } catch (const note_decryption_failed &err) {
        // Couldn't decrypt with this spending key
        throw std::runtime_error(strprintf(
            "Could not decrypt note for payment address %s",
            EncodePaymentAddress(pa)));
    } catch (const std::exception &exc) {
        // Unexpected failure
        throw std::runtime_error(strprintf(
            "Error while decrypting note for payment address %s: %s",
            EncodePaymentAddress(pa), exc.what()));
    }
}

boost::optional<std::pair<
    SaplingNotePlaintext,
    SaplingPaymentAddress>> CWalletTx::DecryptSaplingNote(SaplingOutPoint op) const
{
    // Check whether we can decrypt this SaplingOutPoint
    if (this->mapSaplingNoteData.count(op) == 0) {
        return boost::none;
    }

    auto output = this->vShieldedOutput[op.n];
    auto nd = this->mapSaplingNoteData.at(op);

    auto maybe_pt = SaplingNotePlaintext::decrypt(
        output.encCiphertext,
        nd.ivk,
        output.ephemeralKey,
        output.cm);
    assert(static_cast<bool>(maybe_pt));
    auto notePt = maybe_pt.get();

    auto maybe_pa = nd.ivk.address(notePt.d);
    assert(static_cast<bool>(maybe_pa));
    auto pa = maybe_pa.get();

    return std::make_pair(notePt, pa);
}

boost::optional<std::pair<
    SaplingNotePlaintext,
    SaplingPaymentAddress>> CWalletTx::RecoverSaplingNote(
        SaplingOutPoint op, std::set<uint256>& ovks) const
{
    auto output = this->vShieldedOutput[op.n];

    for (auto ovk : ovks) {
        auto outPt = SaplingOutgoingPlaintext::decrypt(
            output.outCiphertext,
            ovk,
            output.cv,
            output.cm,
            output.ephemeralKey);
        if (!outPt) {
            continue;
        }

        auto maybe_pt = SaplingNotePlaintext::decrypt(
            output.encCiphertext,
            output.ephemeralKey,
            outPt->esk,
            outPt->pk_d,
            output.cm);
        assert(static_cast<bool>(maybe_pt));
        auto notePt = maybe_pt.get();

        return std::make_pair(notePt, SaplingPaymentAddress(notePt.d, outPt->pk_d));
    }

    // Couldn't recover with any of the provided OutgoingViewingKeys
    return boost::none;
}

int64_t CWalletTx::GetTxTime() const
{
    int64_t n = nTimeSmart;
    return n ? n : nTimeReceived;
}

int CWalletTx::GetRequestCount() const
{
    // Returns -1 if it wasn't being tracked
    int nRequests = -1;
    {
        LOCK(pwallet->cs_wallet);
        if (IsCoinBase())
        {
            // Generated block
            if (!hashBlock.IsNull())
            {
                map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                if (mi != pwallet->mapRequestCount.end())
                    nRequests = (*mi).second;
            }
        }
        else
        {
            // Did anyone request this transaction?
            map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(GetHash());
            if (mi != pwallet->mapRequestCount.end())
            {
                nRequests = (*mi).second;

                // How about the block it's in?
                if (nRequests == 0 && !hashBlock.IsNull())
                {
                    map<uint256, int>::const_iterator mi = pwallet->mapRequestCount.find(hashBlock);
                    if (mi != pwallet->mapRequestCount.end())
                        nRequests = (*mi).second;
                    else
                        nRequests = 1; // If it's in someone else's block it must have got out
                }
            }
        }
    }
    return nRequests;
}

// GetAmounts will determine the transparent debits and credits for a given wallet tx.
void CWalletTx::GetAmounts(list<COutputEntry>& listReceived,
                           list<COutputEntry>& listSent, CAmount& nFee, string& strSentAccount, const isminefilter& filter) const
{
    nFee = 0;
    listReceived.clear();
    listSent.clear();
    strSentAccount = strFromAccount;

    // Is this tx sent/signed by me?
    CAmount nDebit = GetDebit(filter);

    bool isFromMyTaddr = false;

    for (auto &txin : vin)
    {
        map<uint256, CWalletTx>::const_iterator mi = pwallet->mapWallet.find(txin.prevout.hash);
        if (mi != pwallet->mapWallet.end())
        {
            const CWalletTx& prev = (*mi).second;
            if (txin.prevout.n < prev.vout.size())
            {
                if (::IsMine(*pwallet, prev.vout[txin.prevout.n].scriptPubKey) & filter)
                {
                    isFromMyTaddr = true;
                    break;
                }
            }
        }
    }

    //bool isFromMyTaddr = pwallet->IsFromMe(*this); // IsFromMe(filter); // debit>0 means we signed/sent this transaction

    // Compute fee if we sent this transaction.
    if (isFromMyTaddr) {
        CAmount nValueOut = GetValueOut();  // transparent outputs plus all Sprout vpub_old and negative Sapling valueBalance
        CAmount nValueIn = GetShieldedValueIn();
        nFee = nDebit - nValueOut + nValueIn;
    }

    // Create output entry for vpub_old/new, if we sent utxos from this transaction
    if (isFromMyTaddr) {
        CAmount myVpubOld = 0;
        CAmount myVpubNew = 0;
        for (const JSDescription& js : vJoinSplit) {
            bool fMyJSDesc = false;

            // Check input side
            for (const uint256& nullifier : js.nullifiers) {
                if (pwallet->IsSproutNullifierFromMe(nullifier)) {
                    fMyJSDesc = true;
                    break;
                }
            }

            // Check output side
            if (!fMyJSDesc) {
                for (const std::pair<JSOutPoint, SproutNoteData> nd : this->mapSproutNoteData) {
                    if (nd.first.js < vJoinSplit.size() && nd.first.n < vJoinSplit[nd.first.js].ciphertexts.size()) {
                        fMyJSDesc = true;
                        break;
                    }
                }
            }

            if (fMyJSDesc) {
                myVpubOld += js.vpub_old;
                myVpubNew += js.vpub_new;
            }

            if (!MoneyRange(js.vpub_old) || !MoneyRange(js.vpub_new) || !MoneyRange(myVpubOld) || !MoneyRange(myVpubNew)) {
                 throw std::runtime_error("CWalletTx::GetAmounts: value out of range");
            }
        }

        // Create an output for the value taken from or added to the transparent value pool by JoinSplits
        if (myVpubOld > myVpubNew) {
            COutputEntry output = {CNoDestination(), myVpubOld - myVpubNew, (int)vout.size()};
            listSent.push_back(output);
        } else if (myVpubNew > myVpubOld) {
            COutputEntry output = {CNoDestination(), myVpubNew - myVpubOld, (int)vout.size()};
            listReceived.push_back(output);
        }
    }

    // If we sent utxos from this transaction, create output for value taken from (negative valueBalance)
    // or added (positive valueBalance) to the transparent value pool by Sapling shielding and unshielding.
    if (isFromMyTaddr) {
        if (valueBalance < 0) {
            COutputEntry output = {CNoDestination(), -valueBalance, (int) vout.size()};
            listSent.push_back(output);
        } else if (valueBalance > 0) {
            COutputEntry output = {CNoDestination(), valueBalance, (int) vout.size()};
            listReceived.push_back(output);
        }
    }

    // Sent/received.
    for (unsigned int i = 0; i < vout.size(); ++i)
    {
        const CTxOut& txout = vout[i];
        isminetype fIsMine = pwallet->IsMine(txout);
        // Only need to handle txouts if AT LEAST one of these is true:
        //   1) they debit from us (sent)
        //   2) the output is to us (received)
        if (nDebit > 0)
        {
            // Don't report 'change' txouts
            if (!(filter & ISMINE_CHANGE) && pwallet->IsChange(txout))
                continue;
        }
        else if (!(fIsMine & filter))
            continue;

        // In either case, we need to get the destination address
        CTxDestination address;
        if (!ExtractDestination(txout.scriptPubKey, address))
        {
            //LogPrintf("CWalletTx::GetAmounts: Unknown transaction type found, txid %s\n",this->GetHash().ToString()); complains on the opreturns
            address = CNoDestination();
        }

        COutputEntry output = {address, txout.nValue, (int)i};

        // If we are debited by the transaction, add the output as a "sent" entry
        if (nDebit > 0)
            listSent.push_back(output);

        // If we are receiving the output, add it as a "received" entry
        if (fIsMine & filter)
            listReceived.push_back(output);
    }
}

void CWalletTx::GetAccountAmounts(const string& strAccount, CAmount& nReceived,
                                  CAmount& nSent, CAmount& nFee, const isminefilter& filter) const
{
    nReceived = nSent = nFee = 0;

    CAmount allFee;
    string strSentAccount;
    list<COutputEntry> listReceived;
    list<COutputEntry> listSent;
    GetAmounts(listReceived, listSent, allFee, strSentAccount, filter);

    if (strAccount == strSentAccount)
    {
        BOOST_FOREACH(const COutputEntry& s, listSent)
            nSent += s.amount;
        nFee = allFee;
    }
    {
        LOCK(pwallet->cs_wallet);
        BOOST_FOREACH(const COutputEntry& r, listReceived)
        {
            if (pwallet->mapAddressBook.count(r.destination))
            {
                map<CTxDestination, CAddressBookData>::const_iterator mi = pwallet->mapAddressBook.find(r.destination);
                if (mi != pwallet->mapAddressBook.end() && (*mi).second.name == strAccount)
                    nReceived += r.amount;
            }
            else if (strAccount.empty())
            {
                nReceived += r.amount;
            }
        }
    }
}


bool CWalletTx::WriteToDisk(CWalletDB *pwalletdb)
{
    return pwalletdb->WriteTx(GetHash(), *this);
}

void CWallet::WitnessNoteCommitment(std::vector<uint256> commitments,
                                    std::vector<boost::optional<SproutWitness>>& witnesses,
                                    uint256 &final_anchor)
{
    witnesses.resize(commitments.size());
    CBlockIndex* pindex = chainActive.Genesis();
    SproutMerkleTree tree;

    while (pindex) {
        CBlock block;
        ReadBlockFromDisk(block, pindex, Params().GetConsensus(), 1);

        BOOST_FOREACH(const CTransaction& tx, block.vtx)
        {
            BOOST_FOREACH(const JSDescription& jsdesc, tx.vJoinSplit)
            {
                BOOST_FOREACH(const uint256 &note_commitment, jsdesc.commitments)
                {
                    tree.append(note_commitment);

                    BOOST_FOREACH(boost::optional<SproutWitness>& wit, witnesses) {
                        if (wit) {
                            wit->append(note_commitment);
                        }
                    }

                    size_t i = 0;
                    BOOST_FOREACH(uint256& commitment, commitments) {
                        if (note_commitment == commitment) {
                            witnesses.at(i) = tree.witness();
                        }
                        i++;
                    }
                }
            }
        }

        uint256 current_anchor = tree.root();

        // Consistency check: we should be able to find the current tree
        // in our CCoins view.
        SproutMerkleTree dummy_tree;
        assert(pcoinsTip->GetSproutAnchorAt(current_anchor, dummy_tree));

        pindex = chainActive.Next(pindex);
    }

    // TODO: #93; Select a root via some heuristic.
    final_anchor = tree.root();

    BOOST_FOREACH(boost::optional<SproutWitness>& wit, witnesses) {
        if (wit) {
            assert(final_anchor == wit->root());
        }
    }
}

/**
 * Reorder the transactions based on block hieght and block index.
 * Transactions can get out of order when they are deleted and subsequently
 * re-added during intial load rescan.
 */

void CWallet::ReorderWalletTransactions(std::map<std::pair<int,int>, CWalletTx*> &mapSorted, int64_t &maxOrderPos) {
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    int maxSortNumber = chainActive.Tip()->GetHeight() + 1;

    for (map<uint256, CWalletTx>::iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
    {
        CWalletTx* pwtx = &(it->second);
        maxOrderPos = max(maxOrderPos, pwtx->nOrderPos);

        if (mapBlockIndex.count(pwtx->hashBlock) > 0) {
            int wtxHeight = mapBlockIndex[pwtx->hashBlock]->GetHeight();
            auto key = std::make_pair(wtxHeight, pwtx->nIndex);
            mapSorted.insert(make_pair(key, pwtx));
        }
        else {
            auto key = std::make_pair(maxSortNumber, 0);
            mapSorted.insert(std::make_pair(key, pwtx));
            maxSortNumber++;
        }
    }
}

/**
 * Scan the block chain (starting in pindexStart) for transactions
 * from or to us. If fUpdate is true, found transactions that already
 * exist in the wallet will be updated.
 */
int CWallet::ScanForWalletTransactions(CBlockIndex* pindexStart, bool fUpdate)
{
    LOCK2(cs_main, cs_wallet);
    int ret = 0;
    int64_t nNow = GetTime();
    const CChainParams& chainParams = Params();

    CBlockIndex* pindex = pindexStart;

    pwalletMain->ClearIdentities(pindexStart->GetHeight());

    std::vector<uint256> myTxHashes;

    {
        //Lock cs_keystore to prevent wallet from locking during rescan
        LOCK(cs_KeyStore);

        // no need to read and scan block, if block was created before
        // our wallet birthday (as adjusted for block time variability)
        while (pindex && nTimeFirstKey && (pindex->GetBlockTime() < (nTimeFirstKey - 7200)))
            pindex = chainActive.Next(pindex);

        ShowProgress(_("Rescanning..."), 0); // show rescan progress in GUI as dialog or on splashscreen, if -rescan on startup
        double dProgressStart = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex, false);
        double dProgressTip = Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), chainActive.LastTip(), false);
        while (pindex)
        {
            //exit loop if trying to shutdown
            if (ShutdownRequested()) {
                break;
            }

            if (pindex->GetHeight() % 100 == 0 && dProgressTip - dProgressStart > 0.0)
                ShowProgress(_("Rescanning..."), std::max(1, std::min(99, (int)((Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex, false) - dProgressStart) / (dProgressTip - dProgressStart) * 100))));

            CBlock block;
            ReadBlockFromDisk(block, pindex, Params().GetConsensus());
            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (AddToWalletIfInvolvingMe(tx, &block, fUpdate, true)) {
                    myTxHashes.push_back(tx.GetHash());
                    ret++;
                }
            }

            SproutMerkleTree sproutTree;
            SaplingMerkleTree saplingTree;
            // This should never fail: we should always be able to get the tree
            // state on the path to the tip of our chain
            assert(pcoinsTip->GetSproutAnchorAt(pindex->hashSproutAnchor, sproutTree));
            if (pindex->pprev) {
                if (Params().GetConsensus().NetworkUpgradeActive(pindex->pprev->GetHeight(),  Consensus::UPGRADE_SAPLING)) {
                    assert(pcoinsTip->GetSaplingAnchorAt(pindex->pprev->hashFinalSaplingRoot, saplingTree));
                }
            }
            // Increment note witness caches
            ChainTipAdded(pindex, &block, sproutTree, saplingTree);

            pindex = chainActive.Next(pindex);
            if (GetTime() >= nNow + 60) {
                nNow = GetTime();
                LogPrintf("Still rescanning. At block %d. Progress=%f\n", pindex ? pindex->GetHeight() : -1, Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pindex));
            }
        }

        // After rescanning, persist Sapling note data that might have changed, e.g. nullifiers.
        // Do not flush the wallet here for performance reasons.
        CWalletDB walletdb(strWalletFile, "r+", false);
        for (auto hash : myTxHashes) {
            CWalletTx wtx = mapWallet[hash];
            if (!wtx.mapSaplingNoteData.empty()) {
                if (!wtx.WriteToDisk(&walletdb)) {
                    LogPrintf("Rescanning... WriteToDisk failed to update Sapling note data for: %s\n", hash.ToString());
                }
            }
        }

        ShowProgress(_("Rescanning..."), 100); // hide progress dialog in GUI
    }
    return ret;
}

void CWallet::ReacceptWalletTransactions()
{
    // If transactions aren't being broadcasted, don't let them into local mempool either
    if (!fBroadcastTransactions)
        return;
    LOCK2(cs_main, cs_wallet);
    std::map<int64_t, CWalletTx*> mapSorted;

    // Sort pending wallet transactions based on their initial wallet insertion order
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
        const uint256& wtxid = item.first;
        CWalletTx& wtx = item.second;
        assert(wtx.GetHash() == wtxid);

        int nDepth = wtx.GetDepthInMainChain();

        if (!wtx.IsCoinBase() && nDepth < 0) {
            mapSorted.insert(std::make_pair(wtx.nOrderPos, &wtx));
        }
    }

    std::vector<uint256> vwtxh;

    // Try to add wallet transactions to memory pool
    BOOST_FOREACH(PAIRTYPE(const int64_t, CWalletTx*)& item, mapSorted)
    {
        CWalletTx& wtx = *(item.second);

        CValidationState state;
        // attempt to add them, but don't set any DOS level
        if (!::AcceptToMemoryPool(mempool, state, wtx, false, NULL, true, 0))
        {
            int nDoS;
            bool invalid = state.IsInvalid(nDoS);

            // log rejection and deletion
            // printf("ERROR reaccepting wallet transaction %s to mempool, reason: %s, DoS: %d\n", wtx.GetHash().ToString().c_str(), state.GetRejectReason().c_str(), nDoS);

            if (!wtx.IsCoinBase() && invalid && nDoS > 0)
            {
                LogPrintf("erasing transaction %s\n", wtx.GetHash().GetHex().c_str());
                vwtxh.push_back(wtx.GetHash());
            }
        }
    }
    for (auto hash : vwtxh)
    {
        EraseFromWallet(hash);
    }
}

bool CWalletTx::RelayWalletTransaction()
{
    if ( pwallet == 0 )
    {
        fprintf(stderr,"unexpected null pwallet in RelayWalletTransaction\n");
        return(false);
    }
    assert(pwallet->GetBroadcastTransactions());
    if (!IsCoinBase())
    {
        if (GetDepthInMainChain() == 0)
        {
            // if tx is expired, dont relay
            LogPrintf("Relaying wtx %s\n", GetHash().ToString());
            RelayTransaction((CTransaction)*this);
            return true;
        }
    }
    return false;
}

set<uint256> CWalletTx::GetConflicts() const
{
    set<uint256> result;
    if (pwallet != NULL)
    {
        uint256 myHash = GetHash();
        result = pwallet->GetConflicts(myHash);
        result.erase(myHash);
    }
    return result;
}

CAmount CWalletTx::GetDebit(const isminefilter& filter) const
{
    if (vin.empty())
        return 0;

    CAmount debit = 0;
    if(filter & ISMINE_SPENDABLE)
    {
        if (fDebitCached)
            debit += nDebitCached;
        else
        {
            int depth = this->GetDepthInMainChain();
            uint32_t height = chainActive.Height() - --depth;
            nDebitCached = pwallet->GetDebit(*this, ISMINE_SPENDABLE, height);
            fDebitCached = true;
            debit += nDebitCached;
        }
    }
    if(filter & ISMINE_WATCH_ONLY)
    {
        if(fWatchDebitCached)
            debit += nWatchDebitCached;
        else
        {
            int depth = this->GetDepthInMainChain();
            uint32_t height = chainActive.Height() - --depth;
            nWatchDebitCached = pwallet->GetDebit(*this, ISMINE_WATCH_ONLY, height);
            fWatchDebitCached = true;
            debit += nWatchDebitCached;
        }
    }
    return debit;
}

CCurrencyValueMap CWalletTx::GetReserveDebit(const isminefilter& filter) const
{
    if (vin.empty())
        return CCurrencyValueMap();

    int depth = this->GetDepthInMainChain();
    uint32_t height = chainActive.Height() - --depth;

    return pwallet->GetReserveDebit(*this, filter, height);
}

CAmount CWalletTx::GetCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    int64_t credit = 0;
    if (filter & ISMINE_SPENDABLE)
    {
        // GetBalance can assume transactions in mapWallet won't change
        if (fCreditCached)
            credit += nCreditCached;
        else
        {
            int depth = this->GetDepthInMainChain();
            uint32_t height = chainActive.Height() - --depth;

            nCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE, height);
            fCreditCached = true;
            credit += nCreditCached;
        }
    }
    if (filter & ISMINE_WATCH_ONLY)
    {
        if (fWatchCreditCached)
            credit += nWatchCreditCached;
        else
        {
            int depth = this->GetDepthInMainChain();
            uint32_t height = chainActive.Height() - --depth;

            nWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY, height);
            fWatchCreditCached = true;
            credit += nWatchCreditCached;
        }
    }
    return credit;
}

bool CWalletTx::HasMatureCoins() const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (!(IsCoinBase() && GetBlocksToMaturity() > 0))
    {
        return true;
    }
    else
    {
        for (auto oneout : vout)
        {
            if (oneout.scriptPubKey.IsInstantSpend())
            {
                return true;
            }
        }
        return false;
    }
}

CCurrencyValueMap CWalletTx::GetReserveCredit(const isminefilter& filter) const
{
    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return CCurrencyValueMap();

    return pwallet->GetReserveCredit(*this, filter);
}

CAmount CWalletTx::GetImmatureCredit(bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureCreditCached)
            return nImmatureCreditCached;
        nImmatureCreditCached = pwallet->GetCredit(*this, ISMINE_SPENDABLE);
        fImmatureCreditCached = true;
        return nImmatureCreditCached;
    }

    return 0;
}

CCurrencyValueMap CWalletTx::GetImmatureReserveCredit(bool fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        return pwallet->GetReserveCredit(*this, ISMINE_SPENDABLE);
    }
    return CCurrencyValueMap();
}

CAmount CWalletTx::GetAvailableCredit(bool fUseCache, bool includeIDLocked) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (includeIDLocked && fUseCache && fAvailableCreditCached)
        return nAvailableCreditCached;

    CAmount nCredit = 0;
    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(hashTx, i) && vout[i].scriptPubKey.IsSpendableOutputType())
        {
            CAmount newCredit = pwallet->GetCredit(*this, i, ISMINE_SPENDABLE);;
            if (newCredit)
            {
                if (!includeIDLocked)
                {
                    // if this is sent to an ID in this wallet, ensure that the ID is unlocked or skip it
                    CTxDestination checkDest;
                    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
                    if (ExtractDestination(vout[i].scriptPubKey, checkDest) &&
                        checkDest.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        if (pwalletMain->GetIdentity(GetDestinationID(checkDest), keyAndIdentity))
                        {
                            if (keyAndIdentity.second.IsLocked(chainActive.Height()))
                            {
                                continue;
                            }
                        }
                        else
                        {
                            //LogPrintf("%s: unable to locate ID %s that should be present in wallet\n", __func__, EncodeDestination(checkDest).c_str());
                            continue;
                        }
                    }
                }
                nCredit += newCredit;
            }
        }
    }

    if (includeIDLocked && fUseCache)
    {
        nAvailableCreditCached = nCredit;
        fAvailableCreditCached = true;
    }
    return nCredit;
}

CCurrencyValueMap CWalletTx::GetAvailableReserveCredit(bool fUseCache, bool includeIDLocked) const
{
    CCurrencyValueMap retVal;
    if (pwallet == 0)
        return retVal;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return retVal;

    uint256 hashTx = GetHash();
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(hashTx, i) && vout[i].scriptPubKey.IsSpendableOutputType())
        {
            CCurrencyValueMap newValue = pwallet->GetReserveCredit(*this, i, ISMINE_SPENDABLE);;
            if (newValue.valueMap.size())
            {
                if (!includeIDLocked)
                {
                    // if this is sent to an ID in this wallet, ensure that the ID is unlocked or skip it
                    CTxDestination checkDest;
                    std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
                    if (ExtractDestination(vout[i].scriptPubKey, checkDest) &&
                        checkDest.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        if (pwalletMain->GetIdentity(GetDestinationID(checkDest), keyAndIdentity))
                        {
                            if (keyAndIdentity.second.IsLocked(chainActive.Height()))
                            {
                                continue;
                            }
                        }
                        else
                        {
                            //LogPrintf("%s: unable to locate ID %s that should be present in wallet\n", __func__, EncodeDestination(checkDest).c_str());
                            continue;
                        }
                    }
                }
                retVal += newValue;
            }
        }
    }
    return retVal;
}

CAmount CWalletTx::GetImmatureWatchOnlyCredit(const bool& fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
        if (fUseCache && fImmatureWatchCreditCached)
            return nImmatureWatchCreditCached;
        nImmatureWatchCreditCached = pwallet->GetCredit(*this, ISMINE_WATCH_ONLY);
        fImmatureWatchCreditCached = true;
        return nImmatureWatchCreditCached;
    }

    return 0;
}

CCurrencyValueMap CWalletTx::GetImmatureWatchOnlyReserveCredit(const bool& fUseCache) const
{
    if (IsCoinBase() && GetBlocksToMaturity() > 0 && IsInMainChain())
    {
       return pwallet->GetReserveCredit(*this, ISMINE_WATCH_ONLY);
    }

    return CCurrencyValueMap();
}

CAmount CWalletTx::GetAvailableWatchOnlyCredit(const bool& fUseCache) const
{
    if (pwallet == 0)
        return 0;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return 0;

    if (fUseCache && fAvailableWatchCreditCached)
        return nAvailableWatchCreditCached;

    CAmount nCredit = 0;
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(GetHash(), i))
        {
            nCredit += pwallet->GetCredit(*this, i, ISMINE_WATCH_ONLY);
            if (!MoneyRange(nCredit))
                throw std::runtime_error("CWalletTx::GetAvailableCredit() : value out of range");
        }
    }

    nAvailableWatchCreditCached = nCredit;
    fAvailableWatchCreditCached = true;
    return nCredit;
}

CCurrencyValueMap CWalletTx::GetAvailableWatchOnlyReserveCredit(const bool& fUseCache) const
{
    CCurrencyValueMap retVal;
    if (pwallet == 0)
        return retVal;

    // Must wait until coinbase is safely deep enough in the chain before valuing it
    if (IsCoinBase() && GetBlocksToMaturity() > 0)
        return retVal;

    for (unsigned int i = 0; i < vout.size(); i++)
    {
        if (!pwallet->IsSpent(GetHash(), i))
        {
            retVal += pwallet->GetReserveCredit(*this, i, ISMINE_WATCH_ONLY);
        }
    }

    return retVal;
}

CAmount CWalletTx::GetChange() const
{
    if (fChangeCached)
        return nChangeCached;
    nChangeCached = pwallet->GetChange(*this);
    fChangeCached = true;
    return nChangeCached;
}

bool CWalletTx::IsTrusted() const
{
    // Quick answer in most cases
    if (!CheckFinalTx(*this))
        return false;
    int nDepth = GetDepthInMainChain();
    if (nDepth >= 1)
        return true;
    if (nDepth < 0)
        return false;
    if (!bSpendZeroConfChange || !IsFromMe(ISMINE_ALL)) // using wtx's cached debit
        return false;

    // Trusted if all inputs are from us and are in the mempool:
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Transactions not sent by us: not trusted
        const CWalletTx* parent = pwallet->GetWalletTx(txin.prevout.hash);
        if (parent == NULL)
            return false;
        if (!parent->vout.size())
        {
            LogPrintf("%s: No spendable output in wallet for input to %s, num %d\n", __func__, txin.prevout.hash.GetHex().c_str(), txin.prevout.n);
            return false;
        }
        const CTxOut& parentOut = parent->vout[txin.prevout.n];
        if (pwallet->IsMine(parentOut) != ISMINE_SPENDABLE)
            return false;
    }
    return true;
}

std::vector<uint256> CWallet::ResendWalletTransactionsBefore(int64_t nTime)
{
    std::vector<uint256> result;

    LOCK(cs_wallet);
    // Sort them in chronological order
    multimap<unsigned int, CWalletTx*> mapSorted;
    uint32_t now = (uint32_t)time(NULL);
    std::vector<uint256> vwtxh;
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, mapWallet)
    {
        CWalletTx& wtx = item.second;
        // Don't rebroadcast if newer than nTime:
        if (wtx.nTimeReceived > nTime)
            continue;
        if ( (wtx.nLockTime >= LOCKTIME_THRESHOLD && wtx.nLockTime < now-KOMODO_MAXMEMPOOLTIME) || wtx.hashBlock.IsNull() )
        {
            //LogPrintf("skip Relaying wtx %s nLockTime %u vs now.%u\n", wtx.GetHash().ToString(),(uint32_t)wtx.nLockTime,now);
            //vwtxh.push_back(wtx.GetHash());
            continue;
        }
        mapSorted.insert(make_pair(wtx.nTimeReceived, &wtx));
    }
    BOOST_FOREACH(PAIRTYPE(const unsigned int, CWalletTx*)& item, mapSorted)
    {
        if ( item.second != 0 )
        {
            CWalletTx &wtx = *item.second;
            if (wtx.RelayWalletTransaction())
                result.push_back(wtx.GetHash());
        }
    }
    for (auto hash : vwtxh)
    {
        EraseFromWallets(hash);
    }
    return result;
}

void CWallet::ResendWalletTransactions(int64_t nBestBlockTime)
{
    // Do this infrequently and randomly to avoid giving away
    // that these are our transactions.
    if (GetTime() < nNextResend || !fBroadcastTransactions)
        return;
    bool fFirst = (nNextResend == 0);
    nNextResend = GetTime() + GetRand(30 * 60);
    if (fFirst)
        return;

    // Only do it if there's been a new block since last time
    if (nBestBlockTime < nLastResend)
        return;
    nLastResend = GetTime();

    // Rebroadcast unconfirmed txes older than 5 minutes before the last
    // block was found:
    std::vector<uint256> relayed = ResendWalletTransactionsBefore(nBestBlockTime-5*60);
    if (!relayed.empty())
        LogPrintf("%s: rebroadcast %u unconfirmed transactions\n", __func__, relayed.size());
}

/** @} */ // end of mapWallet




/** @defgroup Actions
 *
 * @{
 */


CAmount CWallet::GetBalance(bool includeIDLocked) const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableCredit(includeIDLocked, includeIDLocked);
        }
    }

    return nTotal;
}

CCurrencyValueMap CWallet::GetReserveBalance(bool includeIDLocked) const
{
    CCurrencyValueMap retVal;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                retVal += pcoin->GetAvailableReserveCredit(includeIDLocked, includeIDLocked);
        }
    }

    return retVal;
}

CAmount CWallet::GetUnconfirmedBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!CheckFinalTx(*pcoin) || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
                nTotal += pcoin->GetAvailableCredit();
        }
    }
    return nTotal;
}

CCurrencyValueMap CWallet::GetUnconfirmedReserveBalance() const
{
    CCurrencyValueMap retVal;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!CheckFinalTx(*pcoin) || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
                retVal += pcoin->GetAvailableReserveCredit();
        }
    }
    return retVal;
}

CAmount CWallet::GetImmatureBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureCredit();
        }
    }
    return nTotal;
}

CCurrencyValueMap CWallet::GetImmatureReserveBalance() const
{
    CCurrencyValueMap retVal;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            retVal += pcoin->GetImmatureReserveCredit();
        }
    }
    return retVal;
}

CAmount CWallet::GetWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }

    return nTotal;
}

CCurrencyValueMap CWallet::GetWatchOnlyReserveBalance() const
{
    CCurrencyValueMap retVal;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (pcoin->IsTrusted())
                retVal += pcoin->GetAvailableWatchOnlyReserveCredit();
        }
    }

    return retVal;
}

CAmount CWallet::GetUnconfirmedWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!CheckFinalTx(*pcoin) || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
                nTotal += pcoin->GetAvailableWatchOnlyCredit();
        }
    }
    return nTotal;
}

CCurrencyValueMap CWallet::GetUnconfirmedWatchOnlyReserveBalance() const
{
    CCurrencyValueMap retVal;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            if (!CheckFinalTx(*pcoin) || (!pcoin->IsTrusted() && pcoin->GetDepthInMainChain() == 0))
                retVal += pcoin->GetAvailableWatchOnlyReserveCredit();
        }
    }
    return retVal;
}

CAmount CWallet::GetImmatureWatchOnlyBalance() const
{
    CAmount nTotal = 0;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            nTotal += pcoin->GetImmatureWatchOnlyCredit();
        }
    }
    return nTotal;
}

CCurrencyValueMap CWallet::GetImmatureWatchOnlyReserveBalance() const
{
    CCurrencyValueMap retVal;
    {
        LOCK2(cs_main, cs_wallet);
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const CWalletTx* pcoin = &(*it).second;
            retVal += pcoin->GetImmatureWatchOnlyReserveCredit();
        }
    }
    return retVal;
}

/**
 * populate vCoins with vector of available COutputs.
 */
uint64_t komodo_interestnew(int32_t txheight,uint64_t nValue,uint32_t nLockTime,uint32_t tiptime);
uint64_t komodo_accrued_interest(int32_t *txheightp,uint32_t *locktimep,uint256 hash,int32_t n,int32_t checkheight,uint64_t checkvalue,int32_t tipheight);

void CWallet::AvailableCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl, bool fIncludeZeroValue, bool fIncludeCoinBase, bool fIncludeProtectedCoinbase, bool fIncludeImmatureCoins, bool fIncludeIDLockedCoins) const
{
    uint64_t interest,*ptr;
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);
        uint32_t nHeight = chainActive.Height() + 1;
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            if (!CheckFinalTx(*pcoin))
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            bool isCoinbase = pcoin->IsCoinBase();
            if (!fIncludeCoinBase && isCoinbase)
                continue;
            
            if (!fIncludeImmatureCoins && isCoinbase && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;
 
            uint32_t coinHeight = nHeight - nDepth;
            // even if we should include coinbases, we may opt to exclude protected coinbases, which must only be included when shielding
            if (isCoinbase && 
                !fIncludeProtectedCoinbase && 
                Params().GetConsensus().fCoinbaseMustBeProtected && 
                CConstVerusSolutionVector::GetVersionByHeight(coinHeight) < CActivationHeight::SOLUTION_VERUSV4 &&
                CConstVerusSolutionVector::GetVersionByHeight(nHeight) < CActivationHeight::SOLUTION_VERUSV5)
                continue;

            for (int i = 0; i < pcoin->vout.size(); i++)
            {
                isminetype mine = IsMine(pcoin->vout[i]);
                if (!(IsSpent(wtxid, i)) && mine != ISMINE_NO &&
                    !IsLockedCoin((*it).first, i) && (pcoin->vout[i].nValue > 0 || fIncludeZeroValue) &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
                {
                    COptCCParams p;
                    CCurrencyValueMap rOut = pcoin->vout[i].scriptPubKey.ReserveOutValue(p, true);

                    if (p.IsValid() && !pcoin->vout[i].scriptPubKey.IsSpendableOutputType(p))
                    {
                        continue;
                    }

                    if (!fIncludeIDLockedCoins)
                    {
                        // if this is sent to an ID in this wallet, ensure that the ID is unlocked or skip it
                        CTxDestination checkDest;
                        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
                        if (ExtractDestination(pcoin->vout[i].scriptPubKey, checkDest) &&
                            checkDest.which() == COptCCParams::ADDRTYPE_ID)
                        {
                            if (GetIdentity(GetDestinationID(checkDest), keyAndIdentity))
                            {
                                if (keyAndIdentity.second.IsLocked(nHeight))
                                {
                                    continue;
                                }
                            }
                            else
                            {
                                //LogPrintf("%s: unable to locate ID %s that should be present in wallet\n", __func__, EncodeDestination(checkDest).c_str());
                                continue;
                            }
                        }
                    }

                    if ( KOMODO_EXCHANGEWALLET == 0 )
                    {
                        uint32_t locktime; int32_t txheight; CBlockIndex *tipindex;
                        if ( ASSETCHAINS_SYMBOL[0] == 0 && chainActive.LastTip() != 0 && chainActive.LastTip()->GetHeight() >= 60000 )
                        {
                            if ( pcoin->vout[i].nValue >= 10*COIN )
                            {
                                if ( (tipindex= chainActive.LastTip()) != 0 )
                                {
                                    komodo_accrued_interest(&txheight,&locktime,wtxid,i,0,pcoin->vout[i].nValue,(int32_t)tipindex->GetHeight());
                                    interest = komodo_interestnew(txheight,pcoin->vout[i].nValue,locktime,tipindex->nTime);
                                } else interest = 0;
                                //interest = komodo_interestnew(chainActive.LastTip()->GetHeight()+1,pcoin->vout[i].nValue,pcoin->nLockTime,chainActive.LastTip()->nTime);
                                if ( interest != 0 )
                                {
                                    //printf("wallet nValueRet %.8f += interest %.8f ht.%d lock.%u/%u tip.%u\n",(double)pcoin->vout[i].nValue/COIN,(double)interest/COIN,txheight,locktime,pcoin->nLockTime,tipindex->nTime);
                                    //fprintf(stderr,"wallet nValueRet %.8f += interest %.8f ht.%d lock.%u tip.%u\n",(double)pcoin->vout[i].nValue/COIN,(double)interest/COIN,chainActive.LastTip()->GetHeight()+1,pcoin->nLockTime,chainActive.LastTip()->nTime);
                                    //ptr = (uint64_t *)&pcoin->vout[i].nValue;
                                    //(*ptr) += interest;
                                    ptr = (uint64_t *)&pcoin->vout[i].interest;
                                    (*ptr) = interest;
                                    //pcoin->vout[i].nValue += interest;
                                }
                                else
                                {
                                    ptr = (uint64_t *)&pcoin->vout[i].interest;
                                    (*ptr) = 0;
                                }
                            }
                            else
                            {
                                ptr = (uint64_t *)&pcoin->vout[i].interest;
                                (*ptr) = 0;
                            }
                        }
                        else
                        {
                            ptr = (uint64_t *)&pcoin->vout[i].interest;
                            (*ptr) = 0;
                        }
                    }
                    vCoins.push_back(COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO));
                }
            }
        }
    }
}

void CWallet::AvailableReserveCoins(vector<COutput>& vCoins, bool fOnlyConfirmed, const CCoinControl *coinControl, bool fIncludeCoinBase, bool fIncludeNative, const CTxDestination *pOnlyFromDest, const CCurrencyValueMap *pOnlyTheseCurrencies, bool fIncludeIDLockedCoins) const
{
    vCoins.clear();

    {
        LOCK2(cs_main, cs_wallet);
        uint32_t nHeight = chainActive.Height() + 1;
        for (map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); ++it)
        {
            const uint256& wtxid = it->first;
            const CWalletTx* pcoin = &(*it).second;

            if (!CheckFinalTx(*pcoin))
                continue;

            if (fOnlyConfirmed && !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && !fIncludeCoinBase)
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < 0)
                continue;
 
            for (int i = 0; i < pcoin->vout.size(); i++)
            {
                isminetype mine = IsMine(pcoin->vout[i]);
                if (!(IsSpent(wtxid, i)) &&
                    mine != ISMINE_NO &&
                    !IsLockedCoin((*it).first, i) &&
                    (!coinControl || !coinControl->HasSelected() || coinControl->IsSelected((*it).first, i)))
                {
                    COptCCParams p;
                    CCurrencyValueMap rOut = pcoin->vout[i].scriptPubKey.ReserveOutValue(p, true);

                    if (p.IsValid() && !pcoin->vout[i].scriptPubKey.IsSpendableOutputType(p))
                    {
                        continue;
                    }

                    // no zero valued outputs
                    if (pOnlyTheseCurrencies && 
                        !(pOnlyTheseCurrencies->Intersects(rOut) ||
                          (fIncludeNative && pcoin->vout[i].nValue)))
                    {
                        continue;
                    }

                    if (pOnlyFromDest)
                    {
                        if (p.IsValid())
                        {
                            bool found = false;
                            for (auto &oneDest : p.vKeys)
                            {
                                if (GetDestinationID(oneDest) == GetDestinationID(*pOnlyFromDest))
                                {
                                    found = true;
                                    break;
                                }
                            }
                            if (!found)
                            {
                                continue;
                            }
                        }
                        else
                        {
                            // support P2PK or P2PKH
                            CTxDestination dest;
                            if (!ExtractDestination(pcoin->vout[i].scriptPubKey, dest) || GetDestinationID(dest) != GetDestinationID(*pOnlyFromDest))
                            {
                                continue;
                            }
                        }
                    }

                    if (!fIncludeIDLockedCoins)
                    {
                        // if this is sent to an ID in this wallet, ensure that the ID is unlocked or skip it
                        CTxDestination checkDest;
                        std::pair<CIdentityMapKey, CIdentityMapValue> keyAndIdentity;
                        if (ExtractDestination(pcoin->vout[i].scriptPubKey, checkDest) &&
                            checkDest.which() == COptCCParams::ADDRTYPE_ID)
                        {
                            if (GetIdentity(GetDestinationID(checkDest), keyAndIdentity))
                            {
                                if (keyAndIdentity.second.IsLocked(nHeight))
                                {
                                    continue;
                                }
                            }
                            else
                            {
                                //LogPrintf("%s: unable to locate ID %s that should be present in wallet\n", __func__, EncodeDestination(checkDest).c_str());
                                continue;
                            }
                        }
                    }

                    vCoins.push_back(COutput(pcoin, i, nDepth, (mine & ISMINE_SPENDABLE) != ISMINE_NO));
                }
            }
        }
    }
}

bool CWallet::GetAndValidateSaplingZAddress(const std::string &addressStr, libzcash::PaymentAddress &zaddress)
{
    std::string addrCopy = addressStr;
    std::vector<std::string> addressParts;
    boost::split(addressParts, addrCopy, boost::is_any_of(":"));

    if (addressParts.size() == 2 && addressParts[1] == "private")
    {
        // look up to see if this is the private address of an ID. if not, or if the ID does not have a valid, Sapling address, it is invalid
        CTxDestination destination = DecodeDestination(addressParts[0]);
        if (destination.which() == COptCCParams::ADDRTYPE_ID)
        {
            AssertLockHeld(cs_main);
            CIdentity idSource = CIdentity::LookupIdentity(GetDestinationID(destination));
            if (idSource.IsValid() && idSource.privateAddresses.size() > 0)
            {
                zaddress = idSource.privateAddresses[0];
                return true;
            }
        }
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ID or ID that does not have valid z-address specified");
    }

    zaddress = DecodePaymentAddress(addrCopy);
    bool hasZSource = boost::get<libzcash::SaplingPaymentAddress>(&zaddress) != nullptr;
    if (!hasZSource && boost::get<libzcash::SproutPaymentAddress>(&zaddress) != nullptr)
    {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Legacy Sprout address not supported. Use a transparent or Sapling compatible address");
    }
    return hasZSource;
}

static void ApproximateBestSubset(vector<pair<CAmount, pair<const CWalletTx*,unsigned int> > >vValue, const CAmount& nTotalLower, const CAmount& nTargetValue,vector<char>& vfBest, CAmount& nBest, int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    nBest = nTotalLower;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && nBest != nTargetValue; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CAmount nTotal = 0;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                if (nPass == 0 ? insecure_rand()&1 : !vfIncluded[i])
                {
                    nTotal += vValue[i].first;
                    vfIncluded[i] = true;
                    if (nTotal >= nTargetValue)
                    {
                        fReachedTarget = true;
                        if (nTotal < nBest)
                        {
                            nBest = nTotal;
                            vfBest = vfIncluded;
                        }
                        nTotal -= vValue[i].first;
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

// returns true if the selection contributes to getting any closer to the target. for example,
// if a candidate value map contains more of currencies already present and none of those that are needed
// but not present, it will return false. if it contains currencies that are needed, it will return
// true.
bool CloserToTarget(const CCurrencyValueMap &target, const CCurrencyValueMap &current, const CCurrencyValueMap &candidate)
{
    CCurrencyValueMap workingTarget = target.SubtractToZero(current);
    CCurrencyValueMap candidateTarget = workingTarget.SubtractToZero(candidate);
    if (candidateTarget < workingTarget)
    {
        return true;
    }
    return false;
}

static void ApproximateBestReserveSubset(vector<pair<CCurrencyValueMap, pair<const CWalletTx*,unsigned int>>> vValue, 
                                         const CCurrencyValueMap &totalToOptimize, 
                                         const CCurrencyValueMap &targetValues,
                                         vector<char>& vfBest, 
                                         CCurrencyValueMap& bestTotals, 
                                         int iterations = 1000)
{
    vector<char> vfIncluded;

    vfBest.assign(vValue.size(), true);
    bestTotals = totalToOptimize;

    seed_insecure_rand();

    for (int nRep = 0; nRep < iterations && bestTotals != targetValues; nRep++)
    {
        vfIncluded.assign(vValue.size(), false);
        CCurrencyValueMap totals;
        std::set<uint160> satisfied;
        bool fReachedTarget = false;
        for (int nPass = 0; nPass < 2 && !fReachedTarget; nPass++)
        {
            CCurrencyValueMap adjustedTarget(targetValues);
            CCurrencyValueMap presentValues;
            for (unsigned int i = 0; i < vValue.size(); i++)
            {
                std::set<uint160> satisfied;
                //The solver here uses a randomized algorithm,
                //the randomness serves no real security purpose but is just
                //needed to prevent degenerate behavior and it is important
                //that the rng is fast. We do not use a constant random sequence,
                //because there may be some privacy improvement by making
                //the selection random.
                /* printf("targetValues\n%s\ntotals\n%s\nvValue[i].first\n%s\n", targetValues.ToUniValue().write(1,2).c_str(), 
                                                                              totals.ToUniValue().write(1,2).c_str(), 
                                                                              vValue[i].first.ToUniValue().write(1,2).c_str());
                printf("iscloser: %d\n", CloserToTarget(targetValues, totals, vValue[i].first)); */

                if ((nPass == 0 ? insecure_rand()&1 : !vfIncluded[i]) && CloserToTarget(targetValues, totals, vValue[i].first))
                {
                    CCurrencyValueMap relevantDelta = vValue[i].first.IntersectingValues(targetValues);
                    totals += relevantDelta;
                    vfIncluded[i] = true;
                    // we reached the target if we fulfill all currencies

                    adjustedTarget = targetValues.SubtractToZero(totals);

                    // loop through all those that have been zeroed in the adjusted target, and mark as satisfied
                    for (auto &oneCur : targetValues.NonIntersectingValues(adjustedTarget).valueMap)
                    {
                        satisfied.insert(oneCur.first);
                    }

                    if (satisfied.size() == targetValues.valueMap.size())
                    {
                        fReachedTarget = true;
                        CompareValueMap comparator(targetValues);
                        if (comparator.CompareMaps(totals, bestTotals))
                        {
                            bestTotals = totals;
                            vfBest = vfIncluded;

                            int bestcount = 0;
                            for (auto oneBool : vfBest)
                            {
                                if (oneBool) bestcount++;
                            }
                        }
                        totals = (totals - relevantDelta).CanonicalMap();
                        vfIncluded[i] = false;
                    }
                }
            }
        }
    }
}

bool CWallet::SelectCoinsMinConf(const CAmount& nTargetValue, int nConfMine, int nConfTheirs, vector<COutput> vCoins,set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet) const
{
    int32_t count = 0; //uint64_t lowest_interest = 0;
    setCoinsRet.clear();
    //memset(interests,0,sizeof(interests));
    nValueRet = 0;
    // List of values less than target
    pair<CAmount, pair<const CWalletTx*,unsigned int> > coinLowestLarger;
    coinLowestLarger.first = std::numeric_limits<CAmount>::max();
    coinLowestLarger.second.first = NULL;
    vector<pair<CAmount, pair<const CWalletTx*,unsigned int> > > vValue;
    CAmount nTotalLower = 0;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    BOOST_FOREACH(const COutput &output, vCoins)
    {
        if (!output.fSpendable)
            continue;

        if (output.tx->vout[output.i].nValue == 0)
        {
            continue;
        }

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        CAmount n = pcoin->vout[i].nValue;

        pair<CAmount,pair<const CWalletTx*,unsigned int> > coin = make_pair(n,make_pair(pcoin, i));

        if (n == nTargetValue)
        {
            setCoinsRet.insert(coin.second);
            nValueRet += coin.first;
            //if ( KOMODO_EXCHANGEWALLET == 0 )
            //    *interestp += pcoin->vout[i].interest;
            return true;
        }
        else if (n < nTargetValue + CENT)
        {
            vValue.push_back(coin);
            nTotalLower += n;
            //if ( KOMODO_EXCHANGEWALLET == 0 && count < sizeof(interests)/sizeof(*interests) )
            //{
                //fprintf(stderr,"count.%d %.8f\n",count,(double)pcoin->vout[i].interest/COIN);
                //interests[count++] = pcoin->vout[i].interest;
            //}
            if ( nTotalLower > 4*nTargetValue + CENT )
            {
                //fprintf(stderr,"why bother with all the utxo if we have double what is needed?\n");
                break;
            }
        }
        else if (n < coinLowestLarger.first)
        {
            coinLowestLarger = coin;
            //if ( KOMODO_EXCHANGEWALLET == 0 )
            //    lowest_interest = pcoin->vout[i].interest;
        }
    }

    if (nTotalLower == nTargetValue)
    {
        for (unsigned int i = 0; i < vValue.size(); ++i)
        {
            setCoinsRet.insert(vValue[i].second);
            nValueRet += vValue[i].first;
            //if ( KOMODO_EXCHANGEWALLET == 0 && i < count )
            //    *interestp += interests[i];
        }
        return true;
    }

    if (nTotalLower < nTargetValue)
    {
        if (coinLowestLarger.second.first == NULL)
            return false;
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        //if ( KOMODO_EXCHANGEWALLET == 0 )
        //    *interestp += lowest_interest;
        return true;
    }

    // Solve subset sum by stochastic approximation
    sort(vValue.rbegin(), vValue.rend(), CompareValueOnly());
    vector<char> vfBest;
    CAmount nBest;

    ApproximateBestSubset(vValue, nTotalLower, nTargetValue, vfBest, nBest, 1000);
    if (nBest != nTargetValue && nTotalLower >= nTargetValue + CENT)
        ApproximateBestSubset(vValue, nTotalLower, nTargetValue + CENT, vfBest, nBest, 1000);

    // If we have a bigger coin and (either the stochastic approximation didn't find a good solution,
    //                                   or the next bigger coin is closer), return the bigger coin
    if (coinLowestLarger.second.first &&
        ((nBest != nTargetValue && nBest < nTargetValue + CENT) || coinLowestLarger.first <= nBest))
    {
        setCoinsRet.insert(coinLowestLarger.second);
        nValueRet += coinLowestLarger.first;
        //if ( KOMODO_EXCHANGEWALLET == 0 )
        //    *interestp += lowest_interest;
    }
    else {
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
            {
                setCoinsRet.insert(vValue[i].second);
                nValueRet += vValue[i].first;
                //if ( KOMODO_EXCHANGEWALLET == 0 && i < count )
                //    *interestp += interests[i];
            }

        LogPrint("selectcoins", "SelectCoins() best subset: ");
        for (unsigned int i = 0; i < vValue.size(); i++)
            if (vfBest[i])
                LogPrint("selectcoins", "%s", FormatMoney(vValue[i].first));
        LogPrint("selectcoins", "total %s\n", FormatMoney(nBest));
    }

    return true;
}

bool CWallet::SelectCoins(const CAmount& nTargetValue, set<pair<const CWalletTx*,unsigned int> >& setCoinsRet, CAmount& nValueRet, CCurrencyValueMap &reserveChange,  bool& fOnlyProtectedCoinbaseCoinsRet, bool& fNeedProtectedCoinbaseCoinsRet, const CCoinControl* coinControl) const
{
    // Output parameter fOnlyProtectedCoinbaseCoinsRet is set to true when the only available coins are coinbase utxos.
    uint64_t tmp; int32_t retval;
    //if ( interestp == 0 )
    //{
    //    interestp = &tmp;
    //    *interestp = 0;
    //}
    vector<COutput> vCoinsNoCoinbase, vCoinsWithCoinbase;
    AvailableCoins(vCoinsNoCoinbase, true, coinControl, false, true, false, false, false);
    AvailableCoins(vCoinsWithCoinbase, true, coinControl, false, true, true, false, false);
    fOnlyProtectedCoinbaseCoinsRet = vCoinsNoCoinbase.size() == 0 && vCoinsWithCoinbase.size() > 0;

    // If coinbase utxos can only be sent to zaddrs, exclude any coinbase utxos from coin selection.
    bool fProtectCoinbase = Params().GetConsensus().fCoinbaseMustBeProtected;
    vector<COutput> vCoins = (fProtectCoinbase) ? vCoinsNoCoinbase : vCoinsWithCoinbase;

    // Output parameter fNeedProtectedCoinbaseCoinsRet is set to true if coinbase utxos that must be shielded need to be spent to meet target amount
    if (fProtectCoinbase && vCoinsWithCoinbase.size() > vCoinsNoCoinbase.size()) {
        CAmount value = 0;
        for (const COutput& out : vCoinsNoCoinbase) {
            if (!out.fSpendable) {
                continue;
            }
            value += out.tx->vout[out.i].nValue;
            if ( KOMODO_EXCHANGEWALLET == 0 )
                value += out.tx->vout[out.i].interest;
        }
        if (value <= nTargetValue) {
            CAmount valueWithCoinbase = 0;
            for (const COutput& out : vCoinsWithCoinbase) {
                if (!out.fSpendable) {
                    continue;
                }
                valueWithCoinbase += out.tx->vout[out.i].nValue;
                if ( KOMODO_EXCHANGEWALLET == 0 )
                    valueWithCoinbase += out.tx->vout[out.i].interest;
            }
            fNeedProtectedCoinbaseCoinsRet = (valueWithCoinbase >= nTargetValue);
        }
    }
    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            if (!out.fSpendable)
                 continue;
            nValueRet += out.tx->vout[out.i].nValue;
            reserveChange += out.tx->vout[out.i].ReserveOutValue();
            //if ( KOMODO_EXCHANGEWALLET == 0 )
            //    *interestp += out.tx->vout[out.i].interest;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (nValueRet >= nTargetValue);
    }
    // calculate value from preset inputs and store them
    set<pair<const CWalletTx*, uint32_t> > setPresetCoins;
    CAmount nValueFromPresetInputs = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    BOOST_FOREACH(const COutPoint& outpoint, vPresetInputs)
    {
        map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->vout.size() <= outpoint.n)
                return false;
            nValueFromPresetInputs += pcoin->vout[outpoint.n].nValue;
            if ( KOMODO_EXCHANGEWALLET == 0 )
                nValueFromPresetInputs += pcoin->vout[outpoint.n].interest;
            setPresetCoins.insert(make_pair(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(make_pair(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }
    retval = false;
    if ( nTargetValue <= nValueFromPresetInputs )
        retval = true;
    else if ( SelectCoinsMinConf(nTargetValue, 1, 6, vCoins, setCoinsRet, nValueRet) != 0 )
        retval = true;
    else if ( SelectCoinsMinConf(nTargetValue, 1, 1, vCoins, setCoinsRet, nValueRet) != 0 )
        retval = true;
    else if ( bSpendZeroConfChange && SelectCoinsMinConf(nTargetValue, 0, 1, vCoins, setCoinsRet, nValueRet) != 0 )
        retval = true;

    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());

    // return the total reserve, which will all be change, since this is used by native-only aware code
    for (auto &oneOut : setCoinsRet)
    {
        reserveChange += oneOut.first->vout[oneOut.second].ReserveOutValue();
    }

    // add preset inputs to the total value selected
    nValueRet += nValueFromPresetInputs;
    return retval;
}

bool CWallet::SelectReserveCoinsMinConf(const CCurrencyValueMap& targetValues, 
                                        CAmount targetNativeValue, 
                                        int nConfMine, 
                                        int nConfTheirs, 
                                        std::vector<COutput> vCoins, 
                                        std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, 
                                        CCurrencyValueMap& valueRet,
                                        CAmount &nativeValueRet) const
{
    int32_t count = 0; //uint64_t lowest_interest = 0;
    setCoinsRet.clear();
    valueRet.valueMap.clear();
    nativeValueRet = 0;
    //memset(interests,0,sizeof(interests));

    // for each currency type being looked for, store the lowest larger outputs found in order, up to a maximum of the number of
    // different currencies being looked for
    std::map<uint160, std::multimap<CAmount, CReserveOutSelectionInfo>> coinsLowestLarger;
    std::map<std::pair<const CWalletTx *, int>, CCurrencyValueMap> largerOuts;       // all those that are >= than amount requested in at least one currency
    std::multimap<int, std::pair<std::vector<uint160>, CReserveOutSelectionInfo>> multiSatisfy;  // for outputs that satisfy >= one currency
    CCurrencyValueMap largerTotal;
    std::map<uint160, std::multimap<CAmount, CReserveOutSelectionInfo>> coinsLargestLower;
    std::map<std::pair<const CWalletTx *, int>, CCurrencyValueMap> lowerOuts;        // all those that are lower or unneeded for larger and helpful
    CCurrencyValueMap lowerTotal;

    CCurrencyValueMap nativeCent(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<CAmount>({CENT}));

    CCurrencyValueMap totalToOptimize;
    std::vector<std::pair<CCurrencyValueMap, std::pair<const CWalletTx*, unsigned int>>> vOutputsToOptimize;

    random_shuffle(vCoins.begin(), vCoins.end(), GetRandInt);

    CCurrencyValueMap nTotalTarget = (targetValues + CCurrencyValueMap(std::vector<uint160>({ASSETCHAINS_CHAINID}), std::vector<CAmount>({targetNativeValue}))).CanonicalMap();

    // printf("totaltarget: %s\n", nTotalTarget.ToUniValue().write().c_str());

    // currencies in the target that are satisfied x4 in the lower list
    std::set<uint160> satisfied_x4;
    CCurrencyValueMap targetx4(nTotalTarget * 4 + nativeCent);

    for (const COutput &output : vCoins)
    {
        if (!output.fSpendable)
            continue;

        const CWalletTx *pcoin = output.tx;

        if (output.nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? nConfMine : nConfTheirs))
            continue;

        int i = output.i;
        CCurrencyValueMap nAll(pcoin->vout[i].scriptPubKey.ReserveOutValue());  // all currencies, whether in target or not
        CCurrencyValueMap nTotal = nAll.IntersectingValues(targetValues); // nTotal will be all currencies, including native, that are also in target
        CAmount nativeN = pcoin->vout[i].nValue;
        if (nativeN)
        {
            nAll.valueMap[ASSETCHAINS_CHAINID] = nativeN;
            if (targetNativeValue)
            {
                nTotal.valueMap[ASSETCHAINS_CHAINID] = nativeN;
            }
        }

        // if it has no output types we care about, next
        if (!nTotal.valueMap.size())
        {
            continue;
        }

        // printf("nTotal: %s\n", nTotal.ToUniValue().write().c_str());

        CReserveOutSelectionInfo coin(pcoin, i, nAll);

        // if all values are equivalent to targets, we've found the perfect output, no more searching needed
        // TODO: should we early out, even if we have extra currencies? If so, use nTotal to commpare
        if (nTotal == nTotalTarget)
        {
            setCoinsRet.insert(std::make_pair(coin.pWtx, coin.n));
            valueRet = pcoin->vout[i].scriptPubKey.ReserveOutValue();
            nativeValueRet = nativeN;
            return true;
        }

        CCurrencyValueMap subtractedFromTarget(nTotalTarget.SubtractToZero(nTotal));

        // now, we need to loop through all targets to see if this satisfies any single currency requirement completely
        // if so, we will include it in the largest lower list for that currency
        int numLarger = 0;
        std::vector<uint160> multiCurrencies;

        COutput sanitizedOutput(output.tx, output.i, 0, true);

        // if we have some entries larger than target
        if (subtractedFromTarget.valueMap.size() < nTotalTarget.valueMap.size())
        {
            // printf("subtractedFromTarget:\n%s\nnTotal:\n%s\nnTotal.NonIntersectingValues(subtractedFromTarget):\n%s\n", subtractedFromTarget.ToUniValue().write().c_str(), nTotal.ToUniValue().write().c_str(), nTotalTarget.NonIntersectingValues(subtractedFromTarget).ToUniValue().write().c_str());
            for (auto oneCur : nTotal.NonIntersectingValues(subtractedFromTarget).valueMap)
            {
                coinsLowestLarger[oneCur.first].insert(std::make_pair(oneCur.second, CReserveOutSelectionInfo(output.tx, output.i, nAll)));
                multiCurrencies.push_back(oneCur.first);
                numLarger++;
            }
        }
        if (numLarger)
        {
            largerOuts.insert(std::make_pair(std::make_pair(output.tx, output.i), nAll));
            largerTotal += nTotal;
            multiSatisfy.insert(std::make_pair(numLarger, std::make_pair(multiCurrencies, coin)));
        }
        else
        {
            bool neededCurrency = false;
            for (auto &oneCur : nTotal.valueMap)
            {
                if (satisfied_x4.count(oneCur.first))
                {
                    continue;
                }
                neededCurrency = true;
                coinsLargestLower[oneCur.first].insert(std::make_pair(oneCur.second, coin));
            }
            if (!neededCurrency)
            {
                continue;
            }

            lowerOuts.insert(std::make_pair(std::make_pair(output.tx, output.i), nAll));
            lowerTotal += nTotal;

            CCurrencyValueMap adjTargetx4 = targetx4.SubtractToZero(lowerTotal);
            // printf("targetx4:\n%s\nadjTargetx4:\n%s\n", targetx4.ToUniValue().write().c_str(), adjTargetx4.ToUniValue().write().c_str());

            // loop through all those that have been zeroed in the adjusted target, and mark as satisfied
            for (auto &oneCur : targetx4.NonIntersectingValues(adjTargetx4).valueMap)
            {
                // printf("satisfied x 4: %s\n", EncodeDestination(CIdentityID(oneCur.first)).c_str());
                satisfied_x4.insert(oneCur.first);
            }

            if (satisfied_x4.size() == nTotalTarget.valueMap.size())
            {
                // printf("short circuit lower: lowerTotal:\n%s\nTotalTarget:\n%s\n", lowerTotal.ToUniValue().write().c_str(), nTotalTarget.ToUniValue().write().c_str());
                break;
            }
        }
    }

    std::set<uint160> satisfied_larger;

    CCurrencyValueMap newLargerTotal;
    CCurrencyValueMap adjTotalTarget;
    std::map<std::pair<const CWalletTx *, int>, CCurrencyValueMap> largerCoins; // int is the index into the vOutputsToOptimize to remove

    // if our lower total + larger total are not enough, no way we have enough
    if ((lowerTotal + largerTotal) < nTotalTarget)
    {
        // printf("AVAILABLE < nTotalTarget:\nlowerTotal:\n%s\nlargerTotal:\n%s\nnewLargerTotal:\n%s\nTotalTarget:\n%s\n", lowerTotal.ToUniValue().write().c_str(), largerTotal.ToUniValue().write().c_str(), newLargerTotal.ToUniValue().write().c_str(), nTotalTarget.ToUniValue().write().c_str());
        return false;
    }

    // printf("\nlowerTotal:\n%s\nlargerTotal:\n%s\nnewLargerTotal:\n%s\nTotalTarget:\n%s\n", lowerTotal.ToUniValue().write().c_str(), largerTotal.ToUniValue().write().c_str(), newLargerTotal.ToUniValue().write().c_str(), nTotalTarget.ToUniValue().write().c_str());

    for (auto &lowerOut : lowerOuts)
    {
        totalToOptimize += lowerOut.second;
        vOutputsToOptimize.push_back(std::make_pair(lowerOut.second, std::make_pair(lowerOut.first.first, lowerOut.first.second)));
    }

    // if all the lower amounts are just what we need, and we don't add too many inputs in the process, use them all
    size_t numInputsLimit = (size_t)GetArg("-mempooltxinputlimit", MAX_NUM_INPUTS_LIMIT);

    if ((lowerTotal >= nTotalTarget && lowerTotal <= (nTotalTarget + nativeCent)) && lowerOuts.size() <= numInputsLimit)
    {
        // printf("selecting all lowers\nlowerTotal:\n%s\nTotalTarget:\n%s\n", lowerTotal.ToUniValue().write().c_str(), nTotalTarget.ToUniValue().write().c_str());

        for (auto oneOut : lowerOuts)
        {
            setCoinsRet.insert(std::make_pair(oneOut.first.first, oneOut.first.second));
            valueRet += oneOut.first.first->vout[oneOut.first.second].ReserveOutValue();
            nativeValueRet += oneOut.first.first->vout[oneOut.first.second].nValue;
        }
        return true;
    }

    // printf("\nlowerTotal:\n%s\nlargerTotal:\n%s\nTotalTarget:\n%s\n", lowerTotal.ToUniValue().write().c_str(), largerTotal.ToUniValue().write().c_str(), nTotalTarget.ToUniValue().write().c_str());

    std::map<std::pair<const CWalletTx *, int>, CReserveOutSelectionInfo> added;
    largerTotal.valueMap.clear();
    CCurrencyValueMap adjustedTarget(nTotalTarget);
    std::set<uint160> satisfied;

    // short circuit best fit check with any exact amounts we may have
    if (multiSatisfy.size())
    {
        // each output for each currency will satisfy one or more currency requirements
        // first check those that satisfy more than one currency, then select those which are lowest value in currencies they satisfy

        // check in reverse to check those that satisfy most first
        for (auto multiIt = multiSatisfy.rbegin(); multiIt != multiSatisfy.rend(); multiIt++)
        {
            // if we have 0 left, we're done
            if (nTotalTarget.valueMap.size() == satisfied.size())
            {
                // printf("satisfied all currencies. lowerTotal:\n%s\n", largerTotal.ToUniValue().write().c_str());
                break;
            }

            // consider "satisfying" an exact match of any currency in the adjusted request, otherwise, we should fall through to the best fit solver
            int newFound = 0;
            for (auto &oneCurID : multiIt->second.first)
            {
                if (!satisfied.count(oneCurID) &&
                    multiIt->second.second.outVal.valueMap[oneCurID] == adjustedTarget.valueMap[oneCurID])
                {
                    newFound++;
                }
            }

            std::pair<const CWalletTx *, unsigned int> outPair({multiIt->second.second.pWtx, multiIt->second.second.n});

            // if we don't satisfy any new currency with this output, don't add it as we care more if singles are lower as a priotity
            if (!newFound || added.count(outPair))
            {
                continue;
            }

            // this satisfies at least 1 new currency, so use it and also reduce other currencies by all amounts that it includes
            // don't check it again when looking later
            added.insert(std::make_pair(outPair, multiIt->second.second));

            // add all currency values in the transaction, as some may partially satisfy, and we should early out when we have enough
            // printf("multiIt->second.second.outVal:\n%s\n", multiIt->second.second.outVal.ToUniValue().write().c_str());
            CCurrencyValueMap newAdded(multiIt->second.second.outVal.IntersectingValues(nTotalTarget));
            largerTotal += newAdded;
            largerOuts.erase(outPair);

            //printf("adjustedTarget:\n%s\n", adjustedTarget.ToUniValue().write().c_str());
            //printf("nTotalTarget.NonIntersectingValues(adjustedTarget):\n%s\n", nTotalTarget.NonIntersectingValues(adjustedTarget).ToUniValue().write().c_str());

            adjustedTarget = nTotalTarget.SubtractToZero(largerTotal);

            // loop through all those that have been zeroed in the adjusted target, and mark as satisfied
            for (auto &oneCur : nTotalTarget.NonIntersectingValues(adjustedTarget).valueMap)
            {
                //printf("satisfied: %s\n", EncodeDestination(CIdentityID(oneCur.first)).c_str());
                satisfied.insert(oneCur.first);
            }
        }
    }

    // if we've satisfied all currency requirements with larger outputs that fit well, use what we have and be done
    if (satisfied.size() == nTotalTarget.valueMap.size())
    {
        for (auto &oneOut : added)
        {
            setCoinsRet.insert(std::make_pair(oneOut.second.pWtx, oneOut.second.n));
            valueRet += oneOut.second.outVal;
        }
        auto vRetIt = valueRet.valueMap.find(ASSETCHAINS_CHAINID);
        if (vRetIt != valueRet.valueMap.end())
        {
            nativeValueRet = vRetIt->second;
            valueRet.valueMap.erase(vRetIt);
        }
        return true;
    }

    // fill up lower outputs with larger as well to ensure fill
    // those we add from multisatisfy check will be removed from optimized selection
    for (auto &oneCurID : satisfied)
    {
        satisfied_x4.insert(oneCurID);
    }
    for (auto &largerOut : largerOuts)
    {
        COutput thisOutput(largerOut.first.first, largerOut.first.second, 0, true);
        if (lowerOuts.count(std::make_pair(largerOut.first.first, largerOut.first.second)))
        {
            continue;
        }
        // if we have more, they only go into the lower, if they have
        // coins in the currencies where we are not satisfied

        // printf("targetx4:\n%s\nlowerTotal:\n%s\nlargerOut.second:\n%s\n", targetx4.ToUniValue().write().c_str(), lowerTotal.ToUniValue().write().c_str(), largerOut.second.ToUniValue().write().c_str());

        bool useThis = false;
        for (auto &oneCur : largerOut.second.IntersectingValues(nTotalTarget).valueMap)
        {
            if (!satisfied.count(oneCur.first) && !satisfied_x4.count(oneCur.first))
            {
                useThis = true;
            }
        }

        if (useThis)
        {
            CReserveOutSelectionInfo coin(largerOut.first.first, largerOut.first.second, largerOut.second);

            for (auto &oneCur : largerOut.second.valueMap)
            {
                coinsLargestLower[oneCur.first].insert(std::make_pair(oneCur.second, coin));
            }

            lowerOuts.insert(std::make_pair(std::make_pair(largerOut.first.first, largerOut.first.second), largerOut.second));

            lowerTotal += largerOut.second;

            CCurrencyValueMap adjTargetx4 = targetx4.SubtractToZero(lowerTotal);
            //printf("targetx4:\n%s\nadjTargetx4:\n%s\n", targetx4.ToUniValue().write().c_str(), adjTargetx4.ToUniValue().write().c_str());

            // loop through all those that have been zeroed in the adjusted target, and mark as satisfied
            for (auto &oneCur : targetx4.NonIntersectingValues(adjTargetx4).valueMap)
            {
                // don't consider it satisfied x4, unless we have at least 4 entries to choose from
                if (coinsLargestLower.count(oneCur.first) && coinsLargestLower[oneCur.first].size() >= 4)
                {
                    //printf("satisfied x 4: %s\n", EncodeDestination(CIdentityID(oneCur.first)).c_str());
                    satisfied_x4.insert(oneCur.first);
                }
            }
            totalToOptimize += largerOut.second;
            vOutputsToOptimize.push_back(std::make_pair(largerOut.second, std::make_pair(largerOut.first.first, largerOut.first.second)));
        }
    }

    // printf("\nlargerTotal:\n%s\n", largerTotal.ToUniValue().write().c_str());
    // printf("adjustedTarget:\n%s\n", adjustedTarget.ToUniValue().write().c_str());

    // make new vector without those we have added due to exact fit, and use remaining and adjusted target to satisfy requests
    std::vector<int> vOutputsToRemove;
    CCurrencyValueMap removedValue;
    if (added.size())
    {
        for (int i = 0; i < vOutputsToOptimize.size(); i++)
        {
            if (added.count(vOutputsToOptimize[i].second))
            {
                vOutputsToRemove.push_back(i);
                removedValue += vOutputsToOptimize[i].first;
            }
        }

        for (auto &oneOutput : added)
        {
            setCoinsRet.insert(std::make_pair(oneOutput.second.pWtx, oneOutput.second.n));
            valueRet += oneOutput.second.outVal;
        }
        auto vRetIt = valueRet.valueMap.find(ASSETCHAINS_CHAINID);
        if (vRetIt != valueRet.valueMap.end())
        {
            nativeValueRet = vRetIt->second;
            valueRet.valueMap.erase(vRetIt);
        }
    }

    // remove all that we've already added leaving a vector of those that we need to optimize
    for (int i = vOutputsToRemove.size() - 1; i >= 0; i--)
    {
        vOutputsToOptimize.erase(vOutputsToOptimize.begin() + vOutputsToRemove[i]);
    }

    totalToOptimize = totalToOptimize.SubtractToZero(removedValue);
    CCurrencyValueMap newOptimizationTarget = nTotalTarget.SubtractToZero(largerTotal);

    /* printf("totalToOptimize:\n%s\nnewOptimizationTarget:\n%s\n", totalToOptimize.ToUniValue().write().c_str(), newOptimizationTarget.ToUniValue().write().c_str());
    for (int i = 0; i < vOutputsToOptimize.size(); i++)
    {
        printf("output #%d:\nreserves:\n%s\nnative:\n%s\n", 
            i, 
            vOutputsToOptimize[i].first.ToUniValue().write().c_str(), 
            ValueFromAmount(vOutputsToOptimize[i].second.first->vout[vOutputsToOptimize[i].second.second].nValue).write().c_str());
    } */

    vector<char> vfBest;
    CCurrencyValueMap bestTotals;

    //printf("totalToOptimize:\n%s\nnewOptimizationTarget:\n%s\n", totalToOptimize.ToUniValue().write().c_str(), (newOptimizationTarget + nativeCent).ToUniValue().write().c_str());

    ApproximateBestReserveSubset(vOutputsToOptimize, totalToOptimize, newOptimizationTarget, vfBest, bestTotals, 1000);
    if (bestTotals != newOptimizationTarget && totalToOptimize >= (newOptimizationTarget + nativeCent))
    {
        //printf("bestTotals:\n%s\ntotalToOptimize:\n%s\nnewOptimizationTarget:\n%s\n", bestTotals.ToUniValue().write().c_str(), totalToOptimize.ToUniValue().write().c_str(), (newOptimizationTarget + nativeCent).ToUniValue().write().c_str());
        ApproximateBestReserveSubset(vOutputsToOptimize, totalToOptimize, newOptimizationTarget + nativeCent, vfBest, bestTotals, 1000);
    }

    for (unsigned int i = 0; i < vOutputsToOptimize.size(); i++)
    {
        if (vfBest[i])
        {
            setCoinsRet.insert(vOutputsToOptimize[i].second);
            valueRet += vOutputsToOptimize[i].second.first->vout[vOutputsToOptimize[i].second.second].ReserveOutValue();
            nativeValueRet += vOutputsToOptimize[i].second.first->vout[vOutputsToOptimize[i].second.second].nValue;

            /* printf("one selected\ntxid: %s, output: %d\nvalueOut: %s\n", 
                    vOutputsToOptimize[i].second.first->GetHash().GetHex().c_str(), 
                    vOutputsToOptimize[i].second.second, 
                    vOutputsToOptimize[i].first.ToUniValue().write(1,2).c_str()); */
        }
    }

    CCurrencyValueMap checkReturn(valueRet);
    checkReturn.valueMap[ASSETCHAINS_CHAINID] = nativeValueRet;

    // printf("setCoinsRet.size(): %lu, checkReturn: %s\n", setCoinsRet.size(), checkReturn.ToUniValue().write(1,2).c_str());

    if (checkReturn.IntersectingValues(nTotalTarget) < nTotalTarget)
    {
        return false;
    }

    LogPrint("selectcoins", "SelectCoins() best subset: ");
    for (unsigned int i = 0; i < vOutputsToOptimize.size(); i++)
    {
        if (vfBest[i])
        {
            LogPrint("selectcoins", "%s", FormatMoney(vOutputsToOptimize[i].first.valueMap[targetValues.valueMap.begin()->first]));
        }
    }
    LogPrint("selectcoins", "total %s\n", FormatMoney(bestTotals.valueMap[targetValues.valueMap.begin()->first]));

    return true;
}

bool CWallet::SelectReserveCoins(const CCurrencyValueMap& targetReserveValues, 
                                 CAmount targetNativeValue,
                                 set<pair<const CWalletTx*,unsigned int> >& setCoinsRet,
                                 CCurrencyValueMap &valueRet,
                                 CAmount &nativeRet,
                                 bool& fOnlyCoinbaseCoinsRet,
                                 bool& fNeedCoinbaseCoinsRet,
                                 const CCoinControl* coinControl,
                                 const CTxDestination *pOnlyFromDest) const
{
    // Output parameter fOnlyCoinbaseCoinsRet is set to true when the only available coins are coinbase utxos.

    vector<COutput> vCoinsNoCoinbase, vCoinsWithCoinbase;
    AvailableReserveCoins(vCoinsNoCoinbase, true, coinControl, false, true, pOnlyFromDest, &targetReserveValues, false);
    AvailableReserveCoins(vCoinsWithCoinbase, true, coinControl, true, true, pOnlyFromDest, &targetReserveValues, false);
    fOnlyCoinbaseCoinsRet = vCoinsNoCoinbase.size() == 0 && vCoinsWithCoinbase.size() > 0;

    // coinbase protection forcing them to be spent only to z-addresses ended
    // when identities were released
    bool fProtectCoinbase = false;

    vector<COutput> vCoins = (fProtectCoinbase) ? vCoinsNoCoinbase : vCoinsWithCoinbase;

    // Output parameter fNeedCoinbaseCoinsRet is set to true if coinbase utxos need to be spent to meet target amount
    if (fProtectCoinbase && vCoinsWithCoinbase.size() > vCoinsNoCoinbase.size()) {
        CCurrencyValueMap reserveValues;
        CAmount nativeValue = 0;
        for (const COutput& out : vCoinsNoCoinbase) {
            if (!out.fSpendable) {
                continue;
            }
            nativeValue += out.tx->vout[out.i].nValue;
            reserveValues += out.tx->vout[out.i].ReserveOutValue();
        }
        if (reserveValues < targetReserveValues || nativeValue < targetNativeValue) {
            CCurrencyValueMap reserveValuesWithCoinbase;
            CAmount nativeValueWithCoinbase = 0;
            for (const COutput& out : vCoinsWithCoinbase) {
                if (!out.fSpendable) {
                    continue;
                }
                reserveValuesWithCoinbase += out.tx->vout[out.i].ReserveOutValue();
                nativeValueWithCoinbase += out.tx->vout[out.i].nValue;
            }
            fNeedCoinbaseCoinsRet = (reserveValuesWithCoinbase >= targetReserveValues) && (nativeValueWithCoinbase >= targetNativeValue);
        }
    }

    // coin control -> return all selected outputs (we want all selected to go into the transaction for sure)
    if (coinControl && coinControl->HasSelected() && !coinControl->fAllowOtherInputs)
    {
        BOOST_FOREACH(const COutput& out, vCoins)
        {
            if (!out.fSpendable)
                 continue;
            valueRet += out.tx->vout[out.i].ReserveOutValue();
            nativeRet += out.tx->vout[out.i].nValue;
            setCoinsRet.insert(make_pair(out.tx, out.i));
        }
        return (valueRet >= targetReserveValues) && (nativeRet >= targetNativeValue);
    }

    // calculate value from preset inputs and store them
    set<pair<const CWalletTx*, uint32_t> > setPresetCoins;
    CCurrencyValueMap valueFromPresetInputs;
    CAmount nativeValueFromPresets = 0;

    std::vector<COutPoint> vPresetInputs;
    if (coinControl)
        coinControl->ListSelected(vPresetInputs);
    BOOST_FOREACH(const COutPoint& outpoint, vPresetInputs)
    {
        map<uint256, CWalletTx>::const_iterator it = mapWallet.find(outpoint.hash);
        if (it != mapWallet.end())
        {
            const CWalletTx* pcoin = &it->second;
            // Clearly invalid input, fail
            if (pcoin->vout.size() <= outpoint.n)
                return false;
            valueFromPresetInputs += pcoin->vout[outpoint.n].ReserveOutValue();
            nativeValueFromPresets += pcoin->vout[outpoint.n].nValue;
            setPresetCoins.insert(make_pair(pcoin, outpoint.n));
        } else
            return false; // TODO: Allow non-wallet inputs
    }

    // remove preset inputs from vCoins
    for (vector<COutput>::iterator it = vCoins.begin(); it != vCoins.end() && coinControl && coinControl->HasSelected();)
    {
        if (setPresetCoins.count(make_pair(it->tx, it->i)))
            it = vCoins.erase(it);
        else
            ++it;
    }

    bool retval = false;
    if ( targetNativeValue <= nativeRet &&
         targetReserveValues <= targetReserveValues.IntersectingValues(valueFromPresetInputs) && targetNativeValue <= nativeValueFromPresets )
        retval = true;
    else if (SelectReserveCoinsMinConf(targetReserveValues, targetNativeValue, 1, 6, vCoins, setCoinsRet, valueRet, nativeRet))
        retval = true;
    else if (SelectReserveCoinsMinConf(targetReserveValues, targetNativeValue, 1, 1, vCoins, setCoinsRet, valueRet, nativeRet))
        retval = true;
    else if (bSpendZeroConfChange && SelectReserveCoinsMinConf(targetReserveValues, targetNativeValue, 0, 1, vCoins, setCoinsRet, valueRet, nativeRet))
        retval = true;
    // because SelectCoinsMinConf clears the setCoinsRet, we now add the possible inputs to the coinset
    setCoinsRet.insert(setPresetCoins.begin(), setPresetCoins.end());
    // add preset inputs to the total value selected
    valueRet += valueFromPresetInputs;
    nativeRet += nativeValueFromPresets;
    return retval;
}

bool CWallet::FundTransaction(CMutableTransaction& tx, CAmount &nFeeRet, int& nChangePosRet, std::string& strFailReason)
{
    vector<CRecipient> vecSend;

    // Turn the txout set into a CRecipient vector
    BOOST_FOREACH(const CTxOut& txOut, tx.vout)
    {
        CRecipient recipient = {txOut.scriptPubKey, txOut.nValue, false};
        vecSend.push_back(recipient);
    }

    CCoinControl coinControl;
    coinControl.fAllowOtherInputs = true;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        coinControl.Select(txin.prevout);

    CReserveKey reservekey(this);
    CWalletTx wtx;

    if (!CreateTransaction(vecSend, wtx, reservekey, nFeeRet, nChangePosRet, strFailReason, &coinControl, false))
        return false;

    if (nChangePosRet != -1)
        tx.vout.insert(tx.vout.begin() + nChangePosRet, wtx.vout[nChangePosRet]);

    // Add new txins (keeping original txin scriptSig/order)
    BOOST_FOREACH(const CTxIn& txin, wtx.vin)
    {
        bool found = false;
        BOOST_FOREACH(const CTxIn& origTxIn, tx.vin)
        {
            if (txin.prevout.hash == origTxIn.prevout.hash && txin.prevout.n == origTxIn.prevout.n)
            {
                found = true;
                break;
            }
        }
        if (!found)
            tx.vin.push_back(txin);
    }

    return true;
}

bool CWallet::CreateTransaction(const vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet,
                                int& nChangePosRet, std::string& strFailReason, const CCoinControl* coinControl, bool sign)
{
    uint64_t interest2 = 0; CAmount nValue = 0; unsigned int nSubtractFeeFromAmount = 0;
    BOOST_FOREACH (const CRecipient& recipient, vecSend)
    {
        if (nValue < 0 || recipient.nAmount < 0)
        {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += recipient.nAmount;

        if (recipient.fSubtractFeeFromAmount)
            nSubtractFeeFromAmount++;
    }
    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    int nextBlockHeight = chainActive.Height() + 1;

    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nextBlockHeight);
    txNew.nLockTime = (uint32_t)chainActive.LastTip()->nTime + 1; // set to a time close to now

    // Activates after Overwinter network upgrade
    if (Params().GetConsensus().NetworkUpgradeActive(nextBlockHeight, Consensus::UPGRADE_OVERWINTER)) {
        if (txNew.nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD){
            strFailReason = _("nExpiryHeight must be less than TX_EXPIRY_HEIGHT_THRESHOLD.");
            return false;
        }
    }

    unsigned int max_tx_size = MAX_TX_SIZE_AFTER_SAPLING;
    if (!Params().GetConsensus().NetworkUpgradeActive(nextBlockHeight, Consensus::UPGRADE_SAPLING)) {
        max_tx_size = MAX_TX_SIZE_BEFORE_SAPLING;
    }

    // Discourage fee sniping.
    //
    // However because of a off-by-one-error in previous versions we need to
    // neuter it by setting nLockTime to at least one less than nBestHeight.
    // Secondly currently propagation of transactions created for block heights
    // corresponding to blocks that were just mined may be iffy - transactions
    // aren't re-accepted into the mempool - we additionally neuter the code by
    // going ten blocks back. Doesn't yet do anything for sniping, but does act
    // to shake out wallet bugs like not showing nLockTime'd transactions at
    // all.
    txNew.nLockTime = std::max(0, chainActive.Height() - 10);

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    {
        LOCK2(cs_main, cs_wallet);
        {
            nFeeRet = 0;
            while (true)
            {
                //interest = 0;
                txNew.vin.clear();
                txNew.vout.clear();
                wtxNew.fFromMe = true;
                nChangePosRet = -1;
                bool fFirst = true;

                CAmount nTotalValue = nValue;
                if (nSubtractFeeFromAmount == 0)
                    nTotalValue += nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH (const CRecipient& recipient, vecSend)
                {
                    CTxOut txout(recipient.nAmount, recipient.scriptPubKey);

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        txout.nValue -= nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            txout.nValue -= nFeeRet % nSubtractFeeFromAmount;
                        }
                    }

                    COptCCParams p;

                    if (txout.IsDust(::minRelayTxFee) && !(txout.nValue == 0 && txout.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode != EVAL_NONE))
                    {
                        if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                        {
                            if (txout.nValue < 0)
                                strFailReason = _("The transaction amount is too small to pay the fee");
                            else
                                strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                        }
                        else
                            strFailReason = _("Transaction amount too small");
                        return false;
                    }
                    txNew.vout.push_back(txout);
                }

                // Choose coins to use
                set<pair<const CWalletTx*,unsigned int> > setCoins;
                CAmount nValueIn = 0;
                bool fOnlyProtectedCoinbaseCoins = false;
                bool fNeedProtectedCoinbaseCoins = false;
                interest2 = 0;
                CCurrencyValueMap reserveChange;
                if (!SelectCoins(nTotalValue, setCoins, nValueIn, reserveChange, fOnlyProtectedCoinbaseCoins, fNeedProtectedCoinbaseCoins, coinControl))
                {
                    if (fOnlyProtectedCoinbaseCoins) {
                        strFailReason = _("Coinbase funds earned while shielding protection is active can only be sent to a zaddr");
                    } else if (fNeedProtectedCoinbaseCoins) {
                        strFailReason = _("Insufficient funds, protected coinbase funds can only be spent after they have been sent to a zaddr");
                    } else {
                        strFailReason = _("Insufficient funds");
                    }
                    return false;
                }
                BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int) pcoin, setCoins)
                {
                    CAmount nCredit = pcoin.first->vout[pcoin.second].nValue;
                    //The coin age after the next block (depth+1) is used instead of the current,
                    //reflecting an assumption the user would accept a bit more delay for
                    //a chance at a free transaction.
                    //But mempool inputs might still be in the mempool, so their age stays 0
                    //fprintf(stderr,"nCredit %.8f interest %.8f\n",(double)nCredit/COIN,(double)pcoin.first->vout[pcoin.second].interest/COIN);
                    if ( KOMODO_EXCHANGEWALLET == 0 && ASSETCHAINS_SYMBOL[0] == 0 )
                    {
                        interest2 += pcoin.first->vout[pcoin.second].interest;
                        //fprintf(stderr,"%.8f ",(double)pcoin.first->vout[pcoin.second].interest/COIN);
                    }
                    int age = pcoin.first->GetDepthInMainChain();
                    if (age != 0)
                        age += 1;
                    dPriority += (double)nCredit * age;
                }
                //if ( KOMODO_EXCHANGEWALLET != 0 )
                //{
                    //fprintf(stderr,"KOMODO_EXCHANGEWALLET disable interest sum %.8f, interest2 %.8f\n",(double)interest/COIN,(double)interest2/COIN);
                    //interest = 0; // interest2 also
                //}
                if ( ASSETCHAINS_SYMBOL[0] == 0 && DONATION_PUBKEY.size() == 66 && interest2 > 5000 )
                {
                    CScript scriptDonation = CScript() << ParseHex(DONATION_PUBKEY) << OP_CHECKSIG;
                    CTxOut newTxOut(interest2,scriptDonation);
                    int32_t nDonationPosRet = txNew.vout.size() - 1; // dont change first or last
                    vector<CTxOut>::iterator position = txNew.vout.begin()+nDonationPosRet;
                    txNew.vout.insert(position, newTxOut);
                    interest2 = 0;
                }
                CAmount nChange = (nValueIn - nValue + interest2);
                //fprintf(stderr,"wallet change %.8f (%.8f - %.8f) interest2 %.8f total %.8f\n",(double)nChange/COIN,(double)nValueIn/COIN,(double)nValue/COIN,(double)interest2/COIN,(double)nTotalValue/COIN);
                if (nSubtractFeeFromAmount == 0)
                    nChange -= nFeeRet;

                CCurrencyValueMap nullCurrencyMap;
                if (reserveChange > nullCurrencyMap || nChange > 0)
                {
                    // Fill a vout to ourself
                    // TODO: pass in scriptChange instead of reservekey so
                    // change transaction isn't always pay-to-bitcoin-address
                    CScript scriptChange;

                    // coin control: send change to custom address
                    if (coinControl && !boost::get<CNoDestination>(&coinControl->destChange))
                    {
                        if (reserveChange > nullCurrencyMap)
                        {
                            std::vector<CTxDestination> dest({coinControl->destChange});

                            // one output for all reserves, change gets combined
                            // we should separate, or remove any currency that is not whitelisted if specified after whitelist is supported
                            CTokenOutput to(reserveChange);
                            scriptChange = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dest, 1, &to));
                        }
                        else
                        {
                            scriptChange = GetScriptForDestination(coinControl->destChange);
                        }
                    }
                    // no coin control: send change to newly generated address
                    else
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey;
                        extern int32_t USE_EXTERNAL_PUBKEY; extern std::string NOTARY_PUBKEY;

                        CTxDestination dest;
                        if ( USE_EXTERNAL_PUBKEY == 0 )
                        {
                            bool ret;
                            ret = reservekey.GetReservedKey(vchPubKey);
                            assert(ret); // should never fail, as we just unlocked
                            dest = CKeyID(vchPubKey.GetID());
                        }
                        else
                        {
                            //fprintf(stderr,"use notary pubkey\n");
                            dest = CPubKey(ParseHex(NOTARY_PUBKEY));
                        }

                        if (reserveChange > nullCurrencyMap)
                        {
                            std::vector<CTxDestination> dests({dest});

                            // one output for all reserves, change gets combined
                            // we should separate, or remove any currency that is not whitelisted if specified after whitelist is supported
                            CTokenOutput to(reserveChange);
                            scriptChange = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &to));
                        }
                        else
                        {
                            scriptChange = GetScriptForDestination(dest);
                        }
                    }

                    CTxOut newTxOut(nChange, scriptChange);

                    // We do not move dust-change to fees, because the sender would end up paying more than requested.
                    // This would be against the purpose of the all-inclusive feature.
                    // So instead we raise the change and deduct from the recipient.
                    if (nSubtractFeeFromAmount > 0 && newTxOut.IsDust(::minRelayTxFee))
                    {
                        CAmount nDust = newTxOut.GetDustThreshold(::minRelayTxFee) - newTxOut.nValue;
                        newTxOut.nValue += nDust; // raise change until no more dust
                        for (unsigned int i = 0; i < vecSend.size(); i++) // subtract from first recipient
                        {
                            if (vecSend[i].fSubtractFeeFromAmount)
                            {
                                txNew.vout[i].nValue -= nDust;
                                if (txNew.vout[i].IsDust(::minRelayTxFee))
                                {
                                    strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                                    return false;
                                }
                                break;
                            }
                        }
                    }

                    // Never create dust outputs; if we would, just
                    // add the dust to the fee. Valid cryptoconditions with a valid eval function are allowed to create outputs of 0
                    if (newTxOut.IsDust(::minRelayTxFee))
                    {
                        nFeeRet += nChange;
                        reservekey.ReturnKey();
                    }
                    else
                    {
                        nChangePosRet = txNew.vout.size() - 1; // dont change first or last
                        vector<CTxOut>::iterator position = txNew.vout.begin()+nChangePosRet;
                        txNew.vout.insert(position, newTxOut);
                    }
                } else reservekey.ReturnKey();

                // Fill vin
                //
                // Note how the sequence number is set to max()-1 so that the
                // nLockTime set above actually works.
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                    txNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second,CScript(),
                                              std::numeric_limits<unsigned int>::max()-1));

                // Check mempooltxinputlimit to avoid creating a transaction which the local mempool rejects
                size_t limit = (size_t)GetArg("-mempooltxinputlimit", 0);
                {
                    if (Params().GetConsensus().NetworkUpgradeActive(chainActive.Height() + 1, Consensus::UPGRADE_OVERWINTER)) {
                        limit = 0;
                    }
                }
                if (limit > 0) {
                    size_t n = txNew.vin.size();
                    if (n > limit) {
                        strFailReason = _(strprintf("Too many transparent inputs %zu > limit %zu", n, limit).c_str());
                        return false;
                    }
                }

                // Grab the current consensus branch ID
                auto consensusBranchId = CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());

                // Sign
                int nIn = 0;
                CTransaction txNewConst(txNew);
                BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                {
                    bool signSuccess;
                    const CScript& scriptPubKey = coin.first->vout[coin.second].scriptPubKey;
                    SignatureData sigdata;
                    if (sign)
                        signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.first->vout[coin.second].nValue, scriptPubKey), scriptPubKey, sigdata, consensusBranchId);
                    else
                        signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, sigdata, consensusBranchId);

                    if (!signSuccess)
                    {
                        strFailReason = _("Signing transaction failed");
                        return false;
                    } else {
                        UpdateTransaction(txNew, nIn, sigdata);
                    }

                    nIn++;
                }

                unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

                // Remove scriptSigs if we used dummy signatures for fee calculation
                if (!sign) {
                    BOOST_FOREACH (CTxIn& vin, txNew.vin)
                        vin.scriptSig = CScript();
                }

                // Embed the constructed transaction data in wtxNew.
                *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);

                // Limit size
                if (nBytes >= max_tx_size)
                {
                    strFailReason = _("Transaction too large");
                    return false;
                }

                dPriority = wtxNew.ComputePriority(dPriority, nBytes);

                // Can we complete this as a free transaction?
                if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE)
                {
                    // Not enough fee: enough priority?
                    double dPriorityNeeded = mempool.estimatePriority(nTxConfirmTarget);
                    // Not enough mempool history to estimate: use hard-coded AllowFree.
                    if (dPriorityNeeded <= 0 && AllowFree(dPriority))
                        break;

                    // Small enough, and priority high enough, to send for free
                    if (dPriorityNeeded > 0 && dPriority >= dPriorityNeeded)
                        break;
                }

                CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
                if ( nFeeNeeded < 5000 )
                    nFeeNeeded = 5000;

                // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
                // because we must be at the maximum allowed fee.
                if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
                {
                    strFailReason = _("Transaction too large for fee policy");
                    return false;
                }

                if (nFeeRet >= nFeeNeeded)
                    break; // Done, enough fee included.

                // Include more fee and try again.
                nFeeRet = nFeeNeeded;
                continue;
            }
        }
    }

    return true;
}

// almost the same as CreateTransaction with the difference being that input and output are assumed to be
// tokens/reserve currencies, not the native currency of this chain, represented as reserve outputs for both input and output.
// That means that all outputs must be reserve consuming outputs. Fee is added or converted from reserves if this is a
// fractional reserve chain. Fees are calculated based on the current reserve conversion price.
int CWallet::CreateReserveTransaction(const vector<CRecipient>& vecSend, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet,
                                       int& nChangePosRet, int &nChangeOutputs, std::string& strFailReason, const CCoinControl* coinControl, 
                                       const CTxDestination *pOnlyFromDest, bool sign)
{
    CCurrencyValueMap totalReserveOutput;
    CAmount totalNativeOutput = 0;

    unsigned int nSubtractFeeFromAmount = 0;

    // fees can only be deducted from fractional reserve outputs on fractional currency blockchains, otherwise,
    // Verus/Verustest must be used to cover fees.
    bool isVerusActive = IsVerusActive();

    // make sure we have some outputs
    if (vecSend.empty())
    {
        strFailReason = _("Transaction must have outputs");
        return RPC_INVALID_PARAMETER;
    }

    // make sure that there are recipients, all recipients expect reserve inputs, and amounts are all non-negative
    BOOST_FOREACH (const CRecipient& recipient, vecSend)
    {
        CCurrencyValueMap values = recipient.scriptPubKey.ReserveOutValue();
        CCurrencyValueMap zeroes = values - values; // zero values of the same currencies

        if (!values.IsValid())
        {
            strFailReason = _("Output cannot have NULL currency type");
            return RPC_INVALID_PARAMETER;
        }
        if (values.HasNegative())
        {
            strFailReason = _("Transaction output amounts must not be negative");
            return RPC_INVALID_PARAMETER;
        }

        totalNativeOutput += recipient.nAmount;

        totalReserveOutput += values;

        // if we should take from this output, it must be able to pay the fee. fail if it does not
        if (recipient.fSubtractFeeFromAmount && (recipient.nAmount > 0))
        {
            nSubtractFeeFromAmount++;
        }
        else if (recipient.fSubtractFeeFromAmount)
        {
            strFailReason = _("Cannot specify to subtract fee from amount on non-native, non-reserve currency outputs");
            return RPC_INVALID_PARAMETER;
        }

        // make sure we have no negative totals. we do not move this outside the loop, so we can check against overflow on every iteration
        if (totalReserveOutput.HasNegative())
        {
            strFailReason = _("Transaction amounts must not be negative");
            return RPC_INVALID_PARAMETER;
        }
    }

    //printf("totalReserveOutput: %s\n", totalReserveOutput.ToUniValue().write(1,2).c_str());

    int nextBlockHeight = chainActive.Height() + 1;

    CMutableTransaction txNew = CreateNewContextualCMutableTransaction(Params().GetConsensus(), nextBlockHeight);

    std::vector<CTxIn> extraInputs = wtxNew.vin;

    wtxNew.fTimeReceivedIsTxTime = true;
    wtxNew.BindWallet(this);
    txNew.nLockTime = (uint32_t)chainActive.LastTip()->nTime + 1; // set to a time close to now

    // Activates after Overwinter network upgrade
    if (Params().GetConsensus().NetworkUpgradeActive(nextBlockHeight, Consensus::UPGRADE_OVERWINTER)) {
        if (txNew.nExpiryHeight >= TX_EXPIRY_HEIGHT_THRESHOLD){
            strFailReason = "nExpiryHeight must be less than" + std::to_string((uint32_t)TX_EXPIRY_HEIGHT_THRESHOLD);
            return RPC_INVALID_PARAMETER;
        }
    }

    unsigned int max_tx_size = MAX_TX_SIZE_AFTER_SAPLING;
    if (!Params().GetConsensus().NetworkUpgradeActive(nextBlockHeight, Consensus::UPGRADE_SAPLING)) {
        max_tx_size = MAX_TX_SIZE_BEFORE_SAPLING;
    }

    // Discourage fee sniping.
    //
    // However because of a off-by-one-error in previous versions we need to
    // neuter it by setting nLockTime to at least one less than nBestHeight.
    // Secondly currently propagation of transactions created for block heights
    // corresponding to blocks that were just mined may be iffy - transactions
    // aren't re-accepted into the mempool - we additionally neuter the code by
    // going ten blocks back. Doesn't yet do anything for sniping, but does act
    // to shake out wallet bugs like not showing nLockTime'd transactions at
    // all.
    txNew.nLockTime = std::max(0, chainActive.Height() - 10);

    // Secondly occasionally randomly pick a nLockTime even further back, so
    // that transactions that are delayed after signing for whatever reason,
    // e.g. high-latency mix networks and some CoinJoin implementations, have
    // better privacy.
    if (GetRandInt(10) == 0)
        txNew.nLockTime = std::max(0, (int)txNew.nLockTime - GetRandInt(100));

    assert(txNew.nLockTime <= (unsigned int)chainActive.Height());
    assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

    CCurrencyValueMap exchangeRates;
    {
        LOCK2(cs_main, cs_wallet);

        auto currencyState = ConnectedChains.GetCurrencyState(nextBlockHeight - 1);
        for (int i = 0; i < currencyState.currencies.size(); i++)
        {
            exchangeRates.valueMap[currencyState.currencies[i]] = currencyState.PriceInReserve(i);
        }

        nFeeRet = 5000;
        while (true)
        {
            //interest = 0;
            txNew.vin.clear();
            txNew.vout.clear();
            wtxNew.fFromMe = true;
            nChangePosRet = -1;
            nChangeOutputs = 0;
            bool fFirst = true;

            // dust threshold of reserve may be different than native coin, if so, convert
            CAmount dustThreshold;

            CAmount nTotalNativeValue = totalNativeOutput;
            CCurrencyValueMap totalReserveValue = totalReserveOutput;

            if (nSubtractFeeFromAmount == 0)
                nTotalNativeValue += nFeeRet;

            double dPriority = 0;
            // vouts to the payees
            BOOST_FOREACH (const CRecipient& recipient, vecSend)
            {
                // native output value for a reserve output is generally 0. fees are paid by converting from
                // reserve token and the difference between input and output in reserve is the fee
                // the actual reserve token output value is in the scriptPubKey
                CTxOut txout(recipient.nAmount, recipient.scriptPubKey);
                CAmount nativeEquivalent = txout.nValue;

                // here, if we know that it isn't an opret, it will have an output that expects input
                if (!recipient.scriptPubKey.IsOpReturn())
                {
                    COptCCParams p;
                    CCurrencyValueMap reserveOutput = recipient.scriptPubKey.ReserveOutValue(p);
                    CCurrencyValueMap relevantReserves;

                    if (recipient.fSubtractFeeFromAmount)
                    {
                        CAmount subFee = nFeeRet / nSubtractFeeFromAmount; // Subtract fee equally from each selected recipient

                        if (fFirst) // first receiver pays the remainder not divisible by output count
                        {
                            fFirst = false;
                            subFee += nFeeRet % nSubtractFeeFromAmount;
                        }

                        if (subFee <= txout.nValue)
                        {
                            txout.nValue -= subFee;
                        }
                        else
                        {
                            // asking to pay a fee on an output, but not being able to is not accepted, should
                            // never get here, as it should have been checked above
                            strFailReason = "Cannot subtract fee from amount on non-native, non-reserve currency outputs";
                            return RPC_INVALID_PARAMETER;
                        }
                    }

                    dustThreshold = txout.GetDustThreshold(::minRelayTxFee);

                    // only non-crypto condition, and normal reserve outputs are subject to dust limitations
                    if (!p.IsValid() || 
                        p.evalCode == EVAL_RESERVE_OUTPUT || 
                        p.evalCode == EVAL_RESERVE_DEPOSIT || 
                        p.evalCode == EVAL_NONE)
                    {
                        // add all values to a native equivalent
                        // reserve currencies have a native value as well
                        if (exchangeRates.IntersectingValues(reserveOutput).valueMap.size())
                        {
                            nativeEquivalent += currencyState.ReserveToNativeRaw(relevantReserves, exchangeRates.AsCurrencyVector(currencyState.currencies));
                        }
                        else
                        {
                            nativeEquivalent += reserveOutput.valueMap.size() ? reserveOutput.valueMap.begin()->second : 0;
                        }

                        if (nativeEquivalent < dustThreshold)
                        {
                            if (recipient.fSubtractFeeFromAmount && nFeeRet > 0)
                            {
                                if (nativeEquivalent < 0)
                                    strFailReason = _("The transaction amount is too small to pay the fee");
                                else
                                    strFailReason = _("The transaction amount is too small to send after the fee has been deducted");
                            }
                            else
                                strFailReason = _("Transaction amount too small");
                            return RPC_INVALID_PARAMETER;
                        }
                    }
                }
                txNew.vout.push_back(txout);
            }

            // Choose coins to use
            set<pair<const CWalletTx*,unsigned int> > setCoins;
            CCurrencyValueMap totalValueIn;
            CAmount totalNativeValueIn = 0;
            bool fOnlyCoinbaseCoins = false;
            bool fNeedCoinbaseCoins = false;

            if (!SelectReserveCoins(totalReserveValue, 
                                    nTotalNativeValue, 
                                    setCoins, 
                                    totalValueIn, 
                                    totalNativeValueIn, 
                                    fOnlyCoinbaseCoins, 
                                    fNeedCoinbaseCoins, 
                                    coinControl,
                                    pOnlyFromDest))
            {
                strFailReason = _("Insufficient funds");
                return RPC_WALLET_INSUFFICIENT_FUNDS;
            }

            /*
            if (totalValueIn.valueMap.count(ASSETCHAINS_CHAINID))
            {
                for (auto oneOut : setCoins)
                {
                    UniValue oneTxObj(UniValue::VOBJ);
                    TxToUniv(*oneOut.first, uint256(), oneTxObj);
                    printf("TRANSACTION\n%s\n", oneTxObj.write(1,2).c_str());
                }
                printf("totalValueIn: %s\ntotalReserveValue: %s\n", totalValueIn.ToUniValue().write().c_str(), totalReserveValue.ToUniValue().write().c_str());
            }
            */

            CCurrencyValueMap reserveChange = totalValueIn - totalReserveValue;

            //printf("reservechange: %s\ntotalvaluein: %s\n", reserveChange.ToUniValue().write(1,2).c_str(), totalValueIn.ToUniValue().write(1,2).c_str());
            CAmount nChange = totalNativeValueIn - nTotalNativeValue;

            // /printf("tokenChange: %s\nnativeChange: %s\n", reserveChange.ToUniValue().write().c_str(), ValueFromAmount(nChange).write().c_str());

            // if we will try to take the fee from change
            if (nSubtractFeeFromAmount == 0)
            {
                nChange -= nFeeRet;
            }

            if ((nChange > 0) || (reserveChange > CCurrencyValueMap()))
            {
                // coin control: send change to custom address

                // reserve tokens can currently only be sent to public keys or addresses that are in the current wallet
                // since reserve token outputs are CCs by definition
                CTxDestination changeDest;
                if (coinControl && coinControl->destChange.which() != COptCCParams::ADDRTYPE_INVALID)
                {
                    changeDest = coinControl->destChange;
                }
                else
                {
                    // no coin control: send change to newly generated address

                    // Note: We use a new key here to keep it from being obvious which side is the change.
                    //  The drawback is that by not reusing a previous key, the change may be lost if a
                    //  backup is restored, if the backup doesn't have the new private key for the change.
                    //  If we reused the old key, it would be possible to add code to look for and
                    //  rediscover unknown transactions that were written with keys of ours to recover
                    //  post-backup change.

                    // Reserve a new key pair from key pool
                    extern int32_t USE_EXTERNAL_PUBKEY; extern std::string NOTARY_PUBKEY;
                    CPubKey pubKey;
                    if ( USE_EXTERNAL_PUBKEY != 0 )
                    {
                        //fprintf(stderr,"use notary pubkey\n");
                        pubKey = CPubKey(ParseHex(NOTARY_PUBKEY));
                        changeDest = CTxDestination(pubKey);
                    }
                    else if (pOnlyFromDest && pOnlyFromDest->which() == COptCCParams::ADDRTYPE_ID)
                    {
                        changeDest = *pOnlyFromDest;
                    }
                    else
                    {
                        bool ret;
                        ret = reservekey.GetReservedKey(pubKey);
                        assert(ret); // should never fail, as we just unlocked
                        changeDest = CTxDestination(pubKey);
                    }
                }

                // generate all necessary change outputs for all currencies
                // first determine if any outputs left are dust. if so, just add them to the fee
                if (nChange < dustThreshold && reserveChange.CanonicalMap() == CCurrencyValueMap())
                {
                    nFeeRet += nChange;
                    nChange = 0;
                }
                else
                {
                    nChangePosRet = txNew.vout.size() - 1; // dont change first or last
                    if (nChange > 0)
                    {
                        nChangeOutputs++;
                        vector<CTxOut>::iterator position = txNew.vout.begin() + nChangePosRet;
                        txNew.vout.insert(position, CTxOut(nChange, GetScriptForDestination(changeDest)));
                    }
                }

                // now, loop through the remaining reserve currencies and make a change output for each separately
                // if dust, just remove
                auto reserveIndexMap = currencyState.GetReserveMap();
                for (auto &curChangeOut : reserveChange.valueMap)
                {
                    if (!curChangeOut.second)
                    {
                        continue;
                    }
                    CAmount outVal;
                    assert(curChangeOut.first != ASSETCHAINS_CHAINID);
                    auto curIt = reserveIndexMap.find(curChangeOut.first);
                    if (curIt != reserveIndexMap.end())
                    {
                        outVal = currencyState.ReserveToNative(curChangeOut.second, curIt->second);
                    }
                    else
                    {
                        outVal = curChangeOut.second;
                    }
                    
                    nChangeOutputs++;
                    vector<CTxOut>::iterator position = txNew.vout.begin() + (nChangePosRet + nChangeOutputs++);
                    CTokenOutput to = CTokenOutput(curChangeOut.first, curChangeOut.second);
                    txNew.vout.insert(position, CTxOut(0, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, {changeDest}, 1, &to))));
                }

                // if we made no change outputs, return the key
                if (!nChangeOutputs)
                {
                    reservekey.ReturnKey();
                }
            } else reservekey.ReturnKey();

            // Fill vin
            //
            // Note how the sequence number is set to max()-1 so that the
            // nLockTime set above actually works.
            for (auto &oneIn : extraInputs)
            {
                auto wit = mapWallet.find(oneIn.prevout.hash);
                if (wit != mapWallet.end() &&
                    wit->second.vout.size() > oneIn.prevout.n &&
                    !wit->second.vout[oneIn.prevout.n].nValue &&
                    wit->second.vout[oneIn.prevout.n].ReserveOutValue() == CCurrencyValueMap())
                {
                    setCoins.insert(std::make_pair(&(wit->second), oneIn.prevout.n));
                }
                else
                {
                    setCoins.clear();
                    break;
                }
            }
            BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
                txNew.vin.push_back(CTxIn(coin.first->GetHash(),coin.second,CScript(),
                                            std::numeric_limits<unsigned int>::max()-1));

            // Check mempooltxinputlimit to avoid creating a transaction which the local mempool rejects
            size_t limit = (size_t)GetArg("-mempooltxinputlimit", 0);
            {
                LOCK(cs_main);
                if (Params().GetConsensus().NetworkUpgradeActive(chainActive.Height() + 1, Consensus::UPGRADE_OVERWINTER)) {
                    limit = 0;
                }
            }
            if (limit > 0) {
                size_t n = txNew.vin.size();
                if (n > limit) {
                    strFailReason = _(strprintf("Too many transparent inputs %zu > limit %zu", n, limit).c_str());
                    return RPC_INVALID_PARAMETER;
                }
            }

            // Grab the current consensus branch ID
            auto consensusBranchId = CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());

            // Sign
            int nIn = 0;
            CTransaction txNewConst(txNew);
            BOOST_FOREACH(const PAIRTYPE(const CWalletTx*,unsigned int)& coin, setCoins)
            {
                bool signSuccess;
                const CScript& scriptPubKey = coin.first->vout[coin.second].scriptPubKey;
                SignatureData sigdata;
                if (sign)
                    signSuccess = ProduceSignature(TransactionSignatureCreator(this, &txNewConst, nIn, coin.first->vout[coin.second].nValue, scriptPubKey), scriptPubKey, sigdata, consensusBranchId);
                else
                    signSuccess = ProduceSignature(DummySignatureCreator(this), scriptPubKey, sigdata, consensusBranchId);

                if (!signSuccess)
                {
                    strFailReason = _("Signing transaction failed");
                    return RPC_TRANSACTION_ERROR;
                } else {
                    UpdateTransaction(txNew, nIn, sigdata);
                }

                nIn++;
            }

            unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);

            // Remove scriptSigs if we used dummy signatures for fee calculation
            if (!sign) {
                BOOST_FOREACH (CTxIn& vin, txNew.vin)
                    vin.scriptSig = CScript();
            }

            // Embed the constructed transaction data in wtxNew.
            *static_cast<CTransaction*>(&wtxNew) = CTransaction(txNew);

            // Limit size
            if (nBytes >= max_tx_size)
            {
                strFailReason = _("Transaction too large");
                return RPC_TRANSACTION_ERROR;
            }

            dPriority = wtxNew.ComputePriority(dPriority, nBytes);

            // Can we complete this as a free transaction?
            if (fSendFreeTransactions && nBytes <= MAX_FREE_TRANSACTION_CREATE_SIZE)
            {
                // Not enough fee: enough priority?
                double dPriorityNeeded = mempool.estimatePriority(nTxConfirmTarget);
                // Not enough mempool history to estimate: use hard-coded AllowFree.
                if (dPriorityNeeded <= 0 && AllowFree(dPriority))
                    break;

                // Small enough, and priority high enough, to send for free
                if (dPriorityNeeded > 0 && dPriority >= dPriorityNeeded)
                    break;
            }

            CAmount nFeeNeeded = GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
            if ( nFeeNeeded < 5000 )
                nFeeNeeded = 5000;

            // If we made it here and we aren't even able to meet the relay fee on the next pass, give up
            // because we must be at the maximum allowed fee.
            if (nFeeNeeded < ::minRelayTxFee.GetFee(nBytes))
            {
                strFailReason = _("Transaction too large for fee policy");
                return RPC_TRANSACTION_ERROR;
            }

            if (nFeeRet >= nFeeNeeded)
                break; // Done, enough fee included.

            // Include more fee and try again.
            nFeeRet = nFeeNeeded;
            continue;
        }
    }
    return RPC_OK;
}

/**
 * Call after CreateTransaction unless you want to abort
 */
bool CWallet::CommitTransaction(CWalletTx& wtxNew, boost::optional<CReserveKey&> reservekey)
{
    {
        LOCK2(cs_main, cs_wallet);
        LogPrintf("CommitTransaction:\n%s", wtxNew.ToString());
        {
            // This is only to keep the database open to defeat the auto-flush for the
            // duration of this scope.  This is the only place where this optimization
            // maybe makes sense; please don't do it anywhere else.
            CWalletDB* pwalletdb = fFileBacked ? new CWalletDB(strWalletFile,"r+") : NULL;

            if (reservekey) {
                // Take key pair from key pool so it won't be used again
                reservekey.get().KeepKey();
            }

            // Add tx to wallet, because if it has change it's also ours,
            // otherwise just for transaction history.
            AddToWallet(wtxNew, false, pwalletdb);

            // Notify that old coins are spent
            set<CWalletTx*> setCoins;
            BOOST_FOREACH(const CTxIn& txin, wtxNew.vin)
            {
                CWalletTx &coin = mapWallet[txin.prevout.hash];
                coin.BindWallet(this);
                NotifyTransactionChanged(this, coin.GetHash(), CT_UPDATED);
            }

            if (fFileBacked)
                delete pwalletdb;
        }

        // Track how many getdata requests our transaction gets
        mapRequestCount[wtxNew.GetHash()] = 0;

        if (fBroadcastTransactions)
        {
            // Broadcast
            if (!wtxNew.AcceptToMemoryPool(false))
            {
                fprintf(stderr,"commit failed\n");
                // This must not fail. The transaction has already been signed and recorded.
                LogPrintf("CommitTransaction(): Error: Transaction not valid\n");
                return false;
            }
            wtxNew.RelayWalletTransaction();
        }
    }
    return true;
}

CAmount CWallet::GetMinimumFee(unsigned int nTxBytes, unsigned int nConfirmTarget, const CTxMemPool& pool)
{
    // payTxFee is user-set "I want to pay this much"
    CAmount nFeeNeeded = payTxFee.GetFee(nTxBytes);
    // user selected total at least (default=true)
    if (fPayAtLeastCustomFee && nFeeNeeded > 0 && nFeeNeeded < payTxFee.GetFeePerK())
        nFeeNeeded = payTxFee.GetFeePerK();
    // User didn't set: use -txconfirmtarget to estimate...
    if (nFeeNeeded == 0)
        nFeeNeeded = pool.estimateFee(nConfirmTarget).GetFee(nTxBytes);
    // ... unless we don't have enough mempool data, in which case fall
    // back to a hard-coded fee
    if (nFeeNeeded == 0)
        nFeeNeeded = minTxFee.GetFee(nTxBytes);
    // prevent user from paying a non-sense fee (like 1 satoshi): 0 < fee < minRelayFee
    if (nFeeNeeded < ::minRelayTxFee.GetFee(nTxBytes))
        nFeeNeeded = ::minRelayTxFee.GetFee(nTxBytes);
    // But always obey the maximum
    if (nFeeNeeded > maxTxFee)
        nFeeNeeded = maxTxFee;
    return nFeeNeeded;
}


void komodo_prefetch(FILE *fp);

DBErrors CWallet::InitalizeCryptedLoad()
{
    return CWalletDB(strWalletFile,"cr+").InitalizeCryptedLoad(this);
}

DBErrors CWallet::LoadCryptedSeedFromDB()
{
    return CWalletDB(strWalletFile,"cr+").LoadCryptedSeedFromDB(this);
}

DBErrors CWallet::LoadWallet(bool& fFirstRunRet)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    fFirstRunRet = false;
    if ( 0 ) // doesnt help
    {
        fprintf(stderr,"loading wallet %s %u\n",strWalletFile.c_str(),(uint32_t)time(NULL));
        FILE *fp;
        if ( (fp= fopen(strWalletFile.c_str(),"rb")) != 0 )
        {
            komodo_prefetch(fp);
            fclose(fp);
        }
    }
    //fprintf(stderr,"prefetched wallet %s %u\n",strWalletFile.c_str(),(uint32_t)time(NULL));
    DBErrors nLoadWalletRet = CWalletDB(strWalletFile,"cr+").LoadWallet(this);
    //fprintf(stderr,"loaded wallet %s %u\n",strWalletFile.c_str(),(uint32_t)time(NULL));
    if (nLoadWalletRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nLoadWalletRet != DB_LOAD_OK)
        return nLoadWalletRet;
    fFirstRunRet = !vchDefaultKey.IsValid();

    uiInterface.LoadWallet(this);

    return DB_LOAD_OK;
}


DBErrors CWallet::ZapWalletTx(std::vector<CWalletTx>& vWtx)
{
    if (!fFileBacked)
        return DB_LOAD_OK;
    DBErrors nZapWalletTxRet = CWalletDB(strWalletFile,"cr+").ZapWalletTx(this, vWtx);
    if (nZapWalletTxRet == DB_NEED_REWRITE)
    {
        if (CDB::Rewrite(strWalletFile, "\x04pool"))
        {
            LOCK(cs_wallet);
            setKeyPool.clear();
            // Note: can't top-up keypool here, because wallet is locked.
            // User will be prompted to unlock wallet the next operation
            // that requires a new key.
        }
    }

    if (nZapWalletTxRet != DB_LOAD_OK)
        return nZapWalletTxRet;

    return DB_LOAD_OK;
}


bool CWallet::SetAddressBook(const CTxDestination& address, const string& strName, const string& strPurpose)
{
    bool fUpdated = false;
    {
        LOCK(cs_wallet); // mapAddressBook
        std::map<CTxDestination, CAddressBookData>::iterator mi = mapAddressBook.find(address);
        fUpdated = mi != mapAddressBook.end();
        mapAddressBook[address].name = strName;
        if (!strPurpose.empty()) /* update purpose only if requested */
            mapAddressBook[address].purpose = strPurpose;
    }
    NotifyAddressBookChanged(this, address, strName, ::IsMine(*this, address) != ISMINE_NO,
                             strPurpose, (fUpdated ? CT_UPDATED : CT_NEW) );
    if (!fFileBacked)
        return false;
    if (!strPurpose.empty() && !CWalletDB(strWalletFile).WritePurpose(EncodeDestination(address), strPurpose))
        return false;
    return CWalletDB(strWalletFile).WriteName(EncodeDestination(address), strName);
}

bool CWallet::DelAddressBook(const CTxDestination& address)
{
    {
        LOCK(cs_wallet); // mapAddressBook

        if(fFileBacked)
        {
            // Delete destdata tuples associated with address
            std::string strAddress = EncodeDestination(address);
            BOOST_FOREACH(const PAIRTYPE(string, string) &item, mapAddressBook[address].destdata)
            {
                CWalletDB(strWalletFile).EraseDestData(strAddress, item.first);
            }
        }
        mapAddressBook.erase(address);
    }

    NotifyAddressBookChanged(this, address, "", ::IsMine(*this, address) != ISMINE_NO, "", CT_DELETED);

    if (!fFileBacked)
        return false;
    CWalletDB(strWalletFile).ErasePurpose(EncodeDestination(address));
    return CWalletDB(strWalletFile).EraseName(EncodeDestination(address));
}

bool CWallet::SetDefaultKey(const CPubKey &vchPubKey)
{
    if (fFileBacked)
    {
        if (!CWalletDB(strWalletFile).WriteDefaultKey(vchPubKey))
            return false;
    }
    vchDefaultKey = vchPubKey;
    return true;
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool CWallet::NewKeyPool()
{
    {
        LOCK(cs_wallet);
        CWalletDB walletdb(strWalletFile);
        BOOST_FOREACH(int64_t nIndex, setKeyPool)
            walletdb.ErasePool(nIndex);
        setKeyPool.clear();

        if (IsLocked())
            return false;

        int64_t nKeys = max(GetArg("-keypool", 100), (int64_t)0);
        for (int i = 0; i < nKeys; i++)
        {
            int64_t nIndex = i+1;
            walletdb.WritePool(nIndex, CKeyPool(GenerateNewKey()));
            setKeyPool.insert(nIndex);
        }
        LogPrintf("CWallet::NewKeyPool wrote %d new keys\n", nKeys);
    }
    return true;
}

bool CWallet::TopUpKeyPool(unsigned int kpSize)
{
    {
        LOCK(cs_wallet);

        if (IsLocked())
            return false;

        CWalletDB walletdb(strWalletFile);

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = max(GetArg("-keypool", 100), (int64_t) 0);

        while (setKeyPool.size() < (nTargetSize + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
                nEnd = *(--setKeyPool.end()) + 1;
            if (!walletdb.WritePool(nEnd, CKeyPool(GenerateNewKey())))
                throw runtime_error("TopUpKeyPool(): writing generated key failed");
            setKeyPool.insert(nEnd);
            LogPrintf("keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
        }
    }
    return true;
}

void CWallet::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_wallet);

        if (!IsLocked())
            TopUpKeyPool();

        // Get the oldest key
        if(setKeyPool.empty())
            return;

        CWalletDB walletdb(strWalletFile);

        nIndex = *(setKeyPool.begin());
        setKeyPool.erase(setKeyPool.begin());
        if (!walletdb.ReadPool(nIndex, keypool))
            throw runtime_error("ReserveKeyFromKeyPool(): read failed");
        if (!HaveKey(keypool.vchPubKey.GetID()))
            throw runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        //LogPrintf("keypool reserve %d\n", nIndex);
    }
}

void CWallet::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    if (fFileBacked)
    {
        CWalletDB walletdb(strWalletFile);
        walletdb.ErasePool(nIndex);
    }
    LogPrintf("keypool keep %d\n", nIndex);
}

void CWallet::ReturnKey(int64_t nIndex)
{
    // Return to key pool
    {
        LOCK(cs_wallet);
        setKeyPool.insert(nIndex);
    }
    //LogPrintf("keypool return %d\n", nIndex);
}

bool CWallet::GetKeyFromPool(CPubKey& result)
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    {
        LOCK(cs_wallet);
        ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex == -1)
        {
            if (IsLocked()) return false;
            result = GenerateNewKey();
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

int64_t CWallet::GetOldestKeyPoolTime()
{
    int64_t nIndex = 0;
    CKeyPool keypool;
    ReserveKeyFromKeyPool(nIndex, keypool);
    if (nIndex == -1)
        return GetTime();
    ReturnKey(nIndex);
    return keypool.nTime;
}

std::map<CTxDestination, CAmount> CWallet::GetAddressBalances()
{
    map<CTxDestination, CAmount> balances;

    {
        LOCK(cs_wallet);
        BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
        {
            CWalletTx *pcoin = &walletEntry.second;

            if (!CheckFinalTx(*pcoin) || !pcoin->IsTrusted())
                continue;

            if (pcoin->IsCoinBase() && pcoin->GetBlocksToMaturity() > 0)
                continue;

            int nDepth = pcoin->GetDepthInMainChain();
            if (nDepth < (pcoin->IsFromMe(ISMINE_ALL) ? 0 : 1))
                continue;

            for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            {
                CTxDestination addr;
                if (!IsMine(pcoin->vout[i]))
                    continue;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, addr))
                    continue;

                CAmount n = IsSpent(walletEntry.first, i) ? 0 : pcoin->vout[i].nValue;

                if (!balances.count(addr))
                    balances[addr] = 0;
                balances[addr] += n;
            }
        }
    }

    return balances;
}

set< set<CTxDestination> > CWallet::GetAddressGroupings()
{
    AssertLockHeld(cs_wallet); // mapWallet
    set< set<CTxDestination> > groupings;
    set<CTxDestination> grouping;

    BOOST_FOREACH(PAIRTYPE(uint256, CWalletTx) walletEntry, mapWallet)
    {
        CWalletTx *pcoin = &walletEntry.second;

        if (pcoin->vin.size() > 0)
        {
            bool any_mine = false;
            // group all input addresses with each other
            BOOST_FOREACH(CTxIn txin, pcoin->vin)
            {
                CTxDestination address;
                if(!IsMine(txin)) /* If this input isn't mine, ignore it */
                    continue;
                if(!ExtractDestination(mapWallet[txin.prevout.hash].vout[txin.prevout.n].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                any_mine = true;
            }

            // group change with input addresses
            if (any_mine)
            {
               BOOST_FOREACH(CTxOut txout, pcoin->vout)
                   if (IsChange(txout))
                   {
                       CTxDestination txoutAddr;
                       if(!ExtractDestination(txout.scriptPubKey, txoutAddr))
                           continue;
                       grouping.insert(txoutAddr);
                   }
            }
            if (grouping.size() > 0)
            {
                groupings.insert(grouping);
                grouping.clear();
            }
        }

        // group lone addrs by themselves
        for (unsigned int i = 0; i < pcoin->vout.size(); i++)
            if (IsMine(pcoin->vout[i]))
            {
                CTxDestination address;
                if(!ExtractDestination(pcoin->vout[i].scriptPubKey, address))
                    continue;
                grouping.insert(address);
                groupings.insert(grouping);
                grouping.clear();
            }
    }

    set< set<CTxDestination>* > uniqueGroupings; // a set of pointers to groups of addresses
    map< CTxDestination, set<CTxDestination>* > setmap;  // map addresses to the unique group containing it
    BOOST_FOREACH(set<CTxDestination> grouping, groupings)
    {
        // make a set of all the groups hit by this new group
        set< set<CTxDestination>* > hits;
        map< CTxDestination, set<CTxDestination>* >::iterator it;
        BOOST_FOREACH(CTxDestination address, grouping)
            if ((it = setmap.find(address)) != setmap.end())
                hits.insert((*it).second);

        // merge all hit groups into a new single group and delete old groups
        set<CTxDestination>* merged = new set<CTxDestination>(grouping);
        BOOST_FOREACH(set<CTxDestination>* hit, hits)
        {
            merged->insert(hit->begin(), hit->end());
            uniqueGroupings.erase(hit);
            delete hit;
        }
        uniqueGroupings.insert(merged);

        // update setmap
        BOOST_FOREACH(CTxDestination element, *merged)
            setmap[element] = merged;
    }

    set< set<CTxDestination> > ret;
    BOOST_FOREACH(set<CTxDestination>* uniqueGrouping, uniqueGroupings)
    {
        ret.insert(*uniqueGrouping);
        delete uniqueGrouping;
    }

    return ret;
}

std::set<CTxDestination> CWallet::GetAccountAddresses(const std::string& strAccount) const
{
    LOCK(cs_wallet);
    set<CTxDestination> result;
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, mapAddressBook)
    {
        const CTxDestination& address = item.first;
        const string& strName = item.second.name;
        if (strName == strAccount)
            result.insert(address);
    }
    return result;
}

bool CReserveKey::GetReservedKey(CPubKey& pubkey)
{
    if (nIndex == -1)
    {
        CKeyPool keypool;
        pwallet->ReserveKeyFromKeyPool(nIndex, keypool);
        if (nIndex != -1)
            vchPubKey = keypool.vchPubKey;
        else {
            return false;
        }
    }
    assert(vchPubKey.IsValid());
    pubkey = vchPubKey;
    return true;
}

void CReserveKey::KeepKey()
{
    if (nIndex != -1)
        pwallet->KeepKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CReserveKey::ReturnKey()
{
    if (nIndex != -1)
        pwallet->ReturnKey(nIndex);
    nIndex = -1;
    vchPubKey = CPubKey();
}

void CWallet::GetAllReserveKeys(set<CKeyID>& setAddress) const
{
    setAddress.clear();

    CWalletDB walletdb(strWalletFile);

    LOCK2(cs_main, cs_wallet);
    BOOST_FOREACH(const int64_t& id, setKeyPool)
    {
        CKeyPool keypool;
        if (!walletdb.ReadPool(id, keypool))
            throw runtime_error("GetAllReserveKeyHashes(): read failed");
        assert(keypool.vchPubKey.IsValid());
        CKeyID keyID = keypool.vchPubKey.GetID();
        if (!HaveKey(keyID))
            throw runtime_error("GetAllReserveKeyHashes(): unknown key in key pool");
        setAddress.insert(keyID);
    }
}

void CWallet::UpdatedTransaction(const uint256 &hashTx)
{
    {
        LOCK(cs_wallet);
        // Only notify UI if this transaction is in this wallet
        map<uint256, CWalletTx>::const_iterator mi = mapWallet.find(hashTx);
        if (mi != mapWallet.end())
            NotifyTransactionChanged(this, hashTx, CT_UPDATED);
    }
}

class MiningAddressScript : public CReserveScript
{
    // CReserveScript requires implementing this function, so that if an
    // internal (not-visible) wallet address is used, the wallet can mark it as
    // important when a block is mined (so it then appears to the user).
    // If -mineraddress is set, the user already knows about and is managing the
    // address, so we don't need to do anything here.
    void KeepScript() {}
};

void GetScriptForMiningAddress(boost::shared_ptr<CReserveScript> &script)
{
    CTxDestination addr = DecodeDestination(GetArg("-mineraddress", ""));
    if (!IsValidDestination(addr)) {
        return;
    }

    boost::shared_ptr<MiningAddressScript> mAddr(new MiningAddressScript());
    script = mAddr;
    script->reserveScript = GetScriptForDestination(addr);
}

void CWallet::GetScriptForMining(boost::shared_ptr<CReserveScript> &script)
{
    if (!GetArg("-mineraddress", "").empty())
    {
        GetScriptForMiningAddress(script);
        return;
    }

    boost::shared_ptr<CReserveKey> rKey(new CReserveKey(this));
    CPubKey pubkey;
    if (!rKey->GetReservedKey(pubkey))
        return;

    script = rKey;
    script->reserveScript = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
}

void CWallet::LockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.insert(output);
}

void CWallet::UnlockCoin(COutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.erase(output);
}

void CWallet::UnlockAllCoins()
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    setLockedCoins.clear();
}

bool CWallet::IsLockedCoin(uint256 hash, unsigned int n) const
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    COutPoint outpt(hash, n);

    return (setLockedCoins.count(outpt) > 0);
}

void CWallet::ListLockedCoins(std::vector<COutPoint>& vOutpts)
{
    AssertLockHeld(cs_wallet); // setLockedCoins
    for (std::set<COutPoint>::iterator it = setLockedCoins.begin();
         it != setLockedCoins.end(); it++) {
        COutPoint outpt = (*it);
        vOutpts.push_back(outpt);
    }
}


// Note Locking Operations

void CWallet::LockNote(const JSOutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedSproutNotes
    setLockedSproutNotes.insert(output);
}

void CWallet::UnlockNote(const JSOutPoint& output)
{
    AssertLockHeld(cs_wallet); // setLockedSproutNotes
    setLockedSproutNotes.erase(output);
}

void CWallet::UnlockAllSproutNotes()
{
    AssertLockHeld(cs_wallet); // setLockedSproutNotes
    setLockedSproutNotes.clear();
}

bool CWallet::IsLockedNote(const JSOutPoint& outpt) const
{
    AssertLockHeld(cs_wallet); // setLockedSproutNotes

    return (setLockedSproutNotes.count(outpt) > 0);
}

std::vector<JSOutPoint> CWallet::ListLockedSproutNotes()
{
    AssertLockHeld(cs_wallet); // setLockedSproutNotes
    std::vector<JSOutPoint> vOutpts(setLockedSproutNotes.begin(), setLockedSproutNotes.end());
    return vOutpts;
}

void CWallet::LockNote(const SaplingOutPoint& output)
{
    AssertLockHeld(cs_wallet);
    setLockedSaplingNotes.insert(output);
}

void CWallet::UnlockNote(const SaplingOutPoint& output)
{
    AssertLockHeld(cs_wallet);
    setLockedSaplingNotes.erase(output);
}

void CWallet::UnlockAllSaplingNotes()
{
    AssertLockHeld(cs_wallet);
    setLockedSaplingNotes.clear();
}

bool CWallet::IsLockedNote(const SaplingOutPoint& output) const
{
    AssertLockHeld(cs_wallet);
    return (setLockedSaplingNotes.count(output) > 0);
}

std::vector<SaplingOutPoint> CWallet::ListLockedSaplingNotes()
{
    AssertLockHeld(cs_wallet);
    std::vector<SaplingOutPoint> vOutputs(setLockedSaplingNotes.begin(), setLockedSaplingNotes.end());
    return vOutputs;
}

/** @} */ // end of Actions

class CAffectedKeysVisitor : public boost::static_visitor<void> {
private:
    const CKeyStore &keystore;
    std::vector<CKeyID> &vKeys;

public:
    CAffectedKeysVisitor(const CKeyStore &keystoreIn, std::vector<CKeyID> &vKeysIn) : keystore(keystoreIn), vKeys(vKeysIn) {}

    void Process(const CScript &script) {
        txnouttype type;
        std::vector<CTxDestination> vDest;
        int nRequired;
        if (ExtractDestinations(script, type, vDest, nRequired)) {
            BOOST_FOREACH(const CTxDestination &dest, vDest)
                boost::apply_visitor(*this, dest);
        }
    }

    void operator()(const CKeyID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CPubKey &key) {
        CKeyID keyId = key.GetID();
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    // TODO: need to finish storage of quantum public key in wallet
    void operator()(const CQuantumID &keyId) {
        if (keystore.HaveKey(keyId))
            vKeys.push_back(keyId);
    }

    void operator()(const CIndexID &keyId) {
    }

    void operator()(const CScriptID &scriptId) {
        CScript script;
        if (keystore.GetCScript(scriptId, script))
            Process(script);
    }

    void operator()(const CIdentityID &idId) {
        std::pair<CIdentityMapKey, CIdentityMapValue> identity;
        if (keystore.GetIdentity(idId, identity))
        {
            for (auto dest : identity.second.primaryAddresses)
            {
                boost::apply_visitor(*this, dest);
            }
        }
    }

    void operator()(const CNoDestination &none) {}
};

void CWallet::GetKeyBirthTimes(std::map<CKeyID, int64_t> &mapKeyBirth) const {
    AssertLockHeld(cs_wallet); // mapKeyMetadata
    mapKeyBirth.clear();

    // get birth times for keys with metadata
    for (std::map<CKeyID, CKeyMetadata>::const_iterator it = mapKeyMetadata.begin(); it != mapKeyMetadata.end(); it++)
        if (it->second.nCreateTime)
            mapKeyBirth[it->first] = it->second.nCreateTime;

    // map in which we'll infer heights of other keys
    CBlockIndex *pindexMax = chainActive[std::max(0, chainActive.Height() - 144)]; // the tip can be reorganised; use a 144-block safety margin
    std::map<CKeyID, CBlockIndex*> mapKeyFirstBlock;
    std::set<CKeyID> setKeys;
    GetKeys(setKeys);
    BOOST_FOREACH(const CKeyID &keyid, setKeys) {
        if (mapKeyBirth.count(keyid) == 0)
            mapKeyFirstBlock[keyid] = pindexMax;
    }
    setKeys.clear();

    // if there are no such keys, we're done
    if (mapKeyFirstBlock.empty())
        return;

    // find first block that affects those keys, if there are any left
    std::vector<CKeyID> vAffected;
    for (std::map<uint256, CWalletTx>::const_iterator it = mapWallet.begin(); it != mapWallet.end(); it++) {
        // iterate over all wallet transactions...
        const CWalletTx &wtx = (*it).second;
        BlockMap::const_iterator blit = mapBlockIndex.find(wtx.hashBlock);
        if (blit != mapBlockIndex.end() && chainActive.Contains(blit->second)) {
            // ... which are already in a block
            int nHeight = blit->second->GetHeight();
            BOOST_FOREACH(const CTxOut &txout, wtx.vout) {
                // iterate over all their outputs
                CAffectedKeysVisitor(*this, vAffected).Process(txout.scriptPubKey);
                BOOST_FOREACH(const CKeyID &keyid, vAffected) {
                    // ... and all their affected keys
                    std::map<CKeyID, CBlockIndex*>::iterator rit = mapKeyFirstBlock.find(keyid);
                    if (rit != mapKeyFirstBlock.end() && nHeight < rit->second->GetHeight())
                        rit->second = blit->second;
                }
                vAffected.clear();
            }
        }
    }

    // Extract block timestamps for those keys
    for (std::map<CKeyID, CBlockIndex*>::const_iterator it = mapKeyFirstBlock.begin(); it != mapKeyFirstBlock.end(); it++)
        mapKeyBirth[it->first] = it->second->GetBlockTime() - 7200; // block times can be 2h off
}

bool CWallet::AddDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    if (boost::get<CNoDestination>(&dest))
        return false;

    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).WriteDestData(EncodeDestination(dest), key, value);
}

bool CWallet::EraseDestData(const CTxDestination &dest, const std::string &key)
{
    if (!mapAddressBook[dest].destdata.erase(key))
        return false;
    if (!fFileBacked)
        return true;
    return CWalletDB(strWalletFile).EraseDestData(EncodeDestination(dest), key);
}

bool CWallet::LoadDestData(const CTxDestination &dest, const std::string &key, const std::string &value)
{
    mapAddressBook[dest].destdata.insert(std::make_pair(key, value));
    return true;
}

bool CWallet::GetDestData(const CTxDestination &dest, const std::string &key, std::string *value) const
{
    std::map<CTxDestination, CAddressBookData>::const_iterator i = mapAddressBook.find(dest);
    if(i != mapAddressBook.end())
    {
        CAddressBookData::StringMap::const_iterator j = i->second.destdata.find(key);
        if(j != i->second.destdata.end())
        {
            if(value)
                *value = j->second;
            return true;
        }
    }
    return false;
}

CKeyPool::CKeyPool()
{
    nTime = GetTime();
}

CKeyPool::CKeyPool(const CPubKey& vchPubKeyIn)
{
    nTime = GetTime();
    vchPubKey = vchPubKeyIn;
}

CWalletKey::CWalletKey(int64_t nExpires)
{
    nTimeCreated = (nExpires ? GetTime() : 0);
    nTimeExpires = nExpires;
}

void CMerkleTx::SetMerkleBranch(const CBlock& block)
{
    CBlock blockTmp;

    // Update the tx's hashBlock
    hashBlock = block.GetHash();

    // Locate the transaction
    for (nIndex = 0; nIndex < (int)block.vtx.size(); nIndex++)
        if (block.vtx[nIndex] == *(CTransaction*)this)
            break;
    if (nIndex == (int)block.vtx.size())
    {
        vMerkleBranch.clear();
        nIndex = -1;
        LogPrintf("ERROR: %s: couldn't find tx (%s) in block (%s)\n", __func__, GetHash().GetHex().c_str(), hashBlock.GetHex().c_str());
    }

    // Fill in merkle branch
    vMerkleBranch = block.GetMerkleBranch(nIndex);
}

int CMerkleTx::GetDepthInMainChainINTERNAL(const CBlockIndex* &pindexRet) const
{
    if (hashBlock.IsNull() || nIndex == -1)
        return 0;
    AssertLockHeld(cs_main);

    // Find the block it claims to be in
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !chainActive.Contains(pindex))
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return chainActive.Height() - pindex->GetHeight() + 1;
}

int CMerkleTx::GetDepthInMainChain(const CBlockIndex* &pindexRet) const
{
    AssertLockHeld(cs_main);
    int nResult = GetDepthInMainChainINTERNAL(pindexRet);
    if (nResult == 0 && !mempool.exists(GetHash()))
        return -1; // Not in chain, not in mempool

    return nResult;
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if ( ASSETCHAINS_SYMBOL[0] == 0 )
        COINBASE_MATURITY = _COINBASE_MATURITY;
    if (!IsCoinBase())
        return 0;
    int32_t depth = GetDepthInMainChain();
    if (!IsVerusActive() &&
        (chainActive.Height() - depth) == 0)
    {
        return 0;
    }
    int32_t ut = UnlockTime(0);
    int32_t toMaturity = (ut - chainActive.Height()) < 0 ? 0 : ut - chainActive.Height();
    //printf("depth.%i, unlockTime.%i, toMaturity.%i\n", depth, ut, toMaturity);
    ut = (COINBASE_MATURITY - depth) < 0 ? 0 : COINBASE_MATURITY - depth;
    return(ut < toMaturity ? toMaturity : ut);
}

bool CMerkleTx::AcceptToMemoryPool(bool fLimitFree, bool fRejectAbsurdFee)
{
    CValidationState state;
    return ::AcceptToMemoryPool(mempool, state, *this, fLimitFree, NULL, fRejectAbsurdFee);
}

/**
 * Find notes in the wallet filtered by payment address, min depth and ability to spend.
 * These notes are decrypted and added to the output parameter vector, outEntries.
 */
void CWallet::GetFilteredNotes(
    std::vector<SproutNoteEntry>& sproutEntries,
    std::vector<SaplingNoteEntry>& saplingEntries,
    std::string address,
    int minDepth,
    bool ignoreSpent,
    bool requireSpendingKey)
{
    std::set<PaymentAddress> filterAddresses;

    if (address.length() > 0) {
        filterAddresses.insert(DecodePaymentAddress(address));
    }

    GetFilteredNotes(sproutEntries, saplingEntries, filterAddresses, minDepth, INT_MAX, ignoreSpent, requireSpendingKey);
}

/**
 * Find notes in the wallet filtered by payment addresses, min depth, max depth, 
 * if the note is spent, if a spending key is required, and if the notes are locked.
 * These notes are decrypted and added to the output parameter vector, outEntries.
 */
void CWallet::GetFilteredNotes(
    std::vector<SproutNoteEntry>& sproutEntries,
    std::vector<SaplingNoteEntry>& saplingEntries,
    std::set<PaymentAddress>& filterAddresses,
    int minDepth,
    int maxDepth,
    bool ignoreSpent,
    bool requireSpendingKey,
    bool ignoreLocked)
{
    LOCK2(cs_main, cs_wallet);

    for (auto & p : mapWallet) {
        CWalletTx wtx = p.second;

        // Filter the transactions before checking for notes
        if (!CheckFinalTx(wtx) ||
            wtx.GetBlocksToMaturity() > 0 ||
            wtx.GetDepthInMainChain() < minDepth ||
            wtx.GetDepthInMainChain() > maxDepth) {
            continue;
        }

        for (auto & pair : wtx.mapSproutNoteData) {
            JSOutPoint jsop = pair.first;
            SproutNoteData nd = pair.second;
            SproutPaymentAddress pa = nd.address;

            // skip notes which belong to a different payment address in the wallet
            if (!(filterAddresses.empty() || filterAddresses.count(pa))) {
                continue;
            }

            // skip note which has been spent
            if (ignoreSpent && nd.nullifier && IsSproutSpent(*nd.nullifier)) {
                continue;
            }

            // skip notes which cannot be spent
            if (requireSpendingKey && !HaveSproutSpendingKey(pa)) {
                continue;
            }

            // skip locked notes
            if (ignoreLocked && IsLockedNote(jsop)) {
                continue;
            }

            int i = jsop.js; // Index into CTransaction.vJoinSplit
            int j = jsop.n; // Index into JSDescription.ciphertexts

            // Get cached decryptor
            ZCNoteDecryption decryptor;
            if (!GetNoteDecryptor(pa, decryptor)) {
                // Note decryptors are created when the wallet is loaded, so it should always exist
                throw std::runtime_error(strprintf("Could not find note decryptor for payment address %s", EncodePaymentAddress(pa)));
            }

            // determine amount of funds in the note
            auto hSig = wtx.vJoinSplit[i].h_sig(*pzcashParams, wtx.joinSplitPubKey);
            try {
                SproutNotePlaintext plaintext = SproutNotePlaintext::decrypt(
                        decryptor,
                        wtx.vJoinSplit[i].ciphertexts[j],
                        wtx.vJoinSplit[i].ephemeralKey,
                        hSig,
                        (unsigned char) j);

                sproutEntries.push_back(SproutNoteEntry {
                    jsop, pa, plaintext.note(pa), plaintext.memo(), wtx.GetDepthInMainChain() });

            } catch (const note_decryption_failed &err) {
                // Couldn't decrypt with this spending key
                throw std::runtime_error(strprintf("Could not decrypt note for payment address %s", EncodePaymentAddress(pa)));
            } catch (const std::exception &exc) {
                // Unexpected failure
                throw std::runtime_error(strprintf("Error while decrypting note for payment address %s: %s", EncodePaymentAddress(pa), exc.what()));
            }
        }

        for (auto & pair : wtx.mapSaplingNoteData) {
            SaplingOutPoint op = pair.first;
            SaplingNoteData nd = pair.second;

            auto maybe_pt = SaplingNotePlaintext::decrypt(
                wtx.vShieldedOutput[op.n].encCiphertext,
                nd.ivk,
                wtx.vShieldedOutput[op.n].ephemeralKey,
                wtx.vShieldedOutput[op.n].cm);
            assert(static_cast<bool>(maybe_pt));
            auto notePt = maybe_pt.get();

            auto maybe_pa = nd.ivk.address(notePt.d);
            assert(static_cast<bool>(maybe_pa));
            auto pa = maybe_pa.get();

            // skip notes which belong to a different payment address in the wallet
            if (!(filterAddresses.empty() || filterAddresses.count(pa))) {
                continue;
            }

            if (ignoreSpent && nd.nullifier && IsSaplingSpent(*nd.nullifier)) {
                continue;
            }

            // skip notes which cannot be spent
            if (requireSpendingKey) {
                libzcash::SaplingIncomingViewingKey ivk;
                libzcash::SaplingExtendedFullViewingKey extfvk;
                if (!(GetSaplingIncomingViewingKey(pa, ivk) &&
                    GetSaplingFullViewingKey(ivk, extfvk) &&
                    HaveSaplingSpendingKey(extfvk))) {
                    continue;
                }
            }

            // skip locked notes
            if (ignoreLocked && IsLockedNote(op)) {
                continue;
            }

            auto note = notePt.note(nd.ivk).get();
            saplingEntries.push_back(SaplingNoteEntry {
                op, pa, note, notePt.memo(), wtx.GetDepthInMainChain() });
        }
    }
}


//
// Shielded key and address generalizations
//

bool PaymentAddressBelongsToWallet::operator()(const libzcash::SproutPaymentAddress &zaddr) const
{
    return m_wallet->HaveSproutSpendingKey(zaddr) || m_wallet->HaveSproutViewingKey(zaddr);
}

bool PaymentAddressBelongsToWallet::operator()(const libzcash::SaplingPaymentAddress &zaddr) const
{
    libzcash::SaplingIncomingViewingKey ivk;

    // If we have a SaplingExtendedSpendingKey in the wallet, then we will
    // also have the corresponding SaplingFullViewingKey.
    return m_wallet->GetSaplingIncomingViewingKey(zaddr, ivk) &&
        m_wallet->HaveSaplingFullViewingKey(ivk);
}

bool PaymentAddressBelongsToWallet::operator()(const libzcash::InvalidEncoding& no) const
{
    return false;
}

boost::optional<libzcash::ViewingKey> GetViewingKeyForPaymentAddress::operator()(
    const libzcash::SproutPaymentAddress &zaddr) const
{
    libzcash::SproutViewingKey vk;
    if (!m_wallet->GetSproutViewingKey(zaddr, vk)) {
        libzcash::SproutSpendingKey k;
        if (!m_wallet->GetSproutSpendingKey(zaddr, k)) {
            return boost::none;
        }
        vk = k.viewing_key();
    }
    return libzcash::ViewingKey(vk);
}

boost::optional<libzcash::ViewingKey> GetViewingKeyForPaymentAddress::operator()(
    const libzcash::SaplingPaymentAddress &zaddr) const
{
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingExtendedFullViewingKey extfvk;

    if (m_wallet->GetSaplingIncomingViewingKey(zaddr, ivk) &&
        m_wallet->GetSaplingFullViewingKey(ivk, extfvk))
    {
        return libzcash::ViewingKey(extfvk);
    } else {
        return boost::none;
    }
}

boost::optional<libzcash::ViewingKey> GetViewingKeyForPaymentAddress::operator()(
    const libzcash::InvalidEncoding& no) const
{
    // Defaults to InvalidEncoding
    return libzcash::ViewingKey();
}

bool HaveSpendingKeyForPaymentAddress::operator()(const libzcash::SproutPaymentAddress &zaddr) const
{
    return m_wallet->HaveSproutSpendingKey(zaddr);
}

bool HaveSpendingKeyForPaymentAddress::operator()(const libzcash::SaplingPaymentAddress &zaddr) const
{
    libzcash::SaplingIncomingViewingKey ivk;
    libzcash::SaplingExtendedFullViewingKey extfvk;

    return m_wallet->GetSaplingIncomingViewingKey(zaddr, ivk) &&
        m_wallet->GetSaplingFullViewingKey(ivk, extfvk) &&
        m_wallet->HaveSaplingSpendingKey(extfvk);
}

bool HaveSpendingKeyForPaymentAddress::operator()(const libzcash::InvalidEncoding& no) const
{
    return false;
}

boost::optional<libzcash::SpendingKey> GetSpendingKeyForPaymentAddress::operator()(
    const libzcash::SproutPaymentAddress &zaddr) const
{
    libzcash::SproutSpendingKey k;
    if (m_wallet->GetSproutSpendingKey(zaddr, k)) {
        return libzcash::SpendingKey(k);
    } else {
        return boost::none;
    }
}

boost::optional<libzcash::SpendingKey> GetSpendingKeyForPaymentAddress::operator()(
    const libzcash::SaplingPaymentAddress &zaddr) const
{
    libzcash::SaplingExtendedSpendingKey extsk;
    if (m_wallet->GetSaplingExtendedSpendingKey(zaddr, extsk)) {
        return libzcash::SpendingKey(extsk);
    } else {
        return boost::none;
    }
}

boost::optional<libzcash::SpendingKey> GetSpendingKeyForPaymentAddress::operator()(
    const libzcash::InvalidEncoding& no) const
{
    // Defaults to InvalidEncoding
    return libzcash::SpendingKey();
}

KeyAddResult AddViewingKeyToWallet::operator()(const libzcash::SproutViewingKey &vkey) const {
    auto addr = vkey.address();

    if (m_wallet->HaveSproutSpendingKey(addr)) {
        return SpendingKeyExists;
    } else if (m_wallet->HaveSproutViewingKey(addr)) {
        return KeyAlreadyExists;
    } else if (m_wallet->AddSproutViewingKey(vkey)) {
        return KeyAdded;
    } else {
        return KeyNotAdded;
    }
}

KeyAddResult AddViewingKeyToWallet::operator()(const libzcash::SaplingExtendedFullViewingKey &extfvk) const {
    if (m_wallet->HaveSaplingSpendingKey(extfvk)) {
        return SpendingKeyExists;
    } else if (m_wallet->HaveSaplingFullViewingKey(extfvk.fvk.in_viewing_key())) {
        return KeyAlreadyExists;
    } else if (m_wallet->AddSaplingFullViewingKey(extfvk)) {
        return KeyAdded;
    } else {
        return KeyNotAdded;
    }
}

KeyAddResult AddViewingKeyToWallet::operator()(const libzcash::InvalidEncoding& no) const {
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid viewing key");
}

KeyAddResult AddSpendingKeyToWallet::operator()(const libzcash::SproutSpendingKey &sk) const {
    auto addr = sk.address();
    if (log){
        LogPrint("zrpc", "Importing zaddr %s...\n", EncodePaymentAddress(addr));
    }
    if (m_wallet->HaveSproutSpendingKey(addr)) {
        return KeyAlreadyExists;
    } else if (m_wallet-> AddSproutZKey(sk)) {
        m_wallet->mapSproutZKeyMetadata[addr].nCreateTime = nTime;
        return KeyAdded;
    } else {
        return KeyNotAdded;
    }
}

KeyAddResult AddSpendingKeyToWallet::operator()(const libzcash::SaplingExtendedSpendingKey &sk) const {
    auto extfvk = sk.ToXFVK();
    auto ivk = extfvk.fvk.in_viewing_key();
    auto addr = sk.DefaultAddress();
    {
        if (log){
            LogPrint("zrpc", "Importing zaddr %s...\n", EncodePaymentAddress(addr));
        }
        // Don't throw error in case a key is already there
        if (m_wallet->HaveSaplingSpendingKey(extfvk)) {
            return KeyAlreadyExists;
        } else {
            if (!m_wallet-> AddSaplingZKey(sk, addr)) {
                return KeyNotAdded;
            }

            // Sapling addresses can't have been used in transactions prior to activation.
            if (params.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight == Consensus::NetworkUpgrade::ALWAYS_ACTIVE) {
                m_wallet->mapSaplingZKeyMetadata[ivk].nCreateTime = nTime;
            } else {
                // 154051200 seconds from epoch is Friday, 26 October 2018 00:00:00 GMT - definitely before Sapling activates
                m_wallet->mapSaplingZKeyMetadata[ivk].nCreateTime = std::max((int64_t) 154051200, nTime);
            }
            if (hdKeypath) {
                m_wallet->mapSaplingZKeyMetadata[ivk].hdKeypath = hdKeypath.get();
            }
            if (seedFpStr) {
                uint256 seedFp;
                seedFp.SetHex(seedFpStr.get());
                m_wallet->mapSaplingZKeyMetadata[ivk].seedFp = seedFp;
            }
            return KeyAdded;
        }    
    }
}

KeyAddResult AddSpendingKeyToWallet::operator()(const libzcash::InvalidEncoding& no) const {
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid spending key");
}
