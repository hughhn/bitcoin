// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key_io.h>
#include <outputtype.h>
#include <script/descriptor.h>
#include <util/bip32.h>
#include <util/strencodings.h>
#include <wallet/scriptpubkeyman.h>

bool LegacyScriptPubKeyMan::GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error)
{
    TopUpKeyPool();

    // Generate a new key that is added to wallet
    CPubKey new_key;
    if (!GetKeyFromPool(new_key)) {
        error = "Error: Keypool ran out, please call keypoolrefill first";
        return false;
    }
    LearnRelatedScripts(new_key, type);
    dest = GetDestinationForKey(new_key, type);
    return true;
}

typedef std::vector<unsigned char> valtype;

namespace {

/**
 * This is an enum that tracks the execution context of a script, similar to
 * SigVersion in script/interpreter. It is separate however because we want to
 * distinguish between top-level scriptPubKey execution and P2SH redeemScript
 * execution (a distinction that has no impact on consensus rules).
 */
enum class IsMineSigVersion
{
    TOP = 0,        //!< scriptPubKey execution
    P2SH = 1,       //!< P2SH redeemScript
    WITNESS_V0 = 2, //!< P2WSH witness script execution
};

/**
 * This is an internal representation of isminetype + invalidity.
 * Its order is significant, as we return the max of all explored
 * possibilities.
 */
enum class IsMineResult
{
    NO = 0,         //!< Not ours
    WATCH_ONLY = 1, //!< Included in watch-only balance
    SPENDABLE = 2,  //!< Included in all balances
    INVALID = 3,    //!< Not spendable by anyone (uncompressed pubkey in segwit, P2SH inside P2SH or witness, witness inside witness)
};

bool PermitsUncompressed(IsMineSigVersion sigversion)
{
    return sigversion == IsMineSigVersion::TOP || sigversion == IsMineSigVersion::P2SH;
}

bool HaveKeys(const std::vector<valtype>& pubkeys, const LegacyScriptPubKeyMan& keystore)
{
    for (const valtype& pubkey : pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (!keystore.HaveKey(keyID)) return false;
    }
    return true;
}

IsMineResult IsMineInner(const LegacyScriptPubKeyMan& keystore, const CScript& scriptPubKey, IsMineSigVersion sigversion)
{
    IsMineResult ret = IsMineResult::NO;

    std::vector<valtype> vSolutions;
    txnouttype whichType = Solver(scriptPubKey, vSolutions);

    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
    case TX_WITNESS_UNKNOWN:
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (!PermitsUncompressed(sigversion) && vSolutions[0].size() != 33) {
            return IsMineResult::INVALID;
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    case TX_WITNESS_V0_KEYHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WPKH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            // We do not support bare witness outputs unless the P2SH version of it would be
            // acceptable as well. This protects against matching before segwit activates.
            // This also applies to the P2WSH case.
            break;
        }
        ret = std::max(ret, IsMineInner(keystore, GetScriptForDestination(PKHash(uint160(vSolutions[0]))), IsMineSigVersion::WITNESS_V0));
        break;
    }
    case TX_PUBKEYHASH:
    {
        keyID = CKeyID(uint160(vSolutions[0]));
        CPubKey pubkey;
        if (keystore.GetPubKey(keyID, pubkey)) {
            if (!PermitsUncompressed(sigversion) && !pubkey.IsCompressed()) {
                return IsMineResult::INVALID;
            } else {
                ret = std::max(ret, IsMineResult::WATCH_ONLY);
            }
        }
        if (keystore.HaveKey(keyID)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    }
    case TX_SCRIPTHASH:
    {
        if (sigversion != IsMineSigVersion::TOP) {
            // P2SH inside P2WSH or P2SH is invalid.
            return IsMineResult::INVALID;
        }
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, IsMineInner(keystore, subscript, IsMineSigVersion::P2SH));
        }
        break;
    }
    case TX_WITNESS_V0_SCRIPTHASH:
    {
        if (sigversion == IsMineSigVersion::WITNESS_V0) {
            // P2WSH inside P2WSH is invalid.
            return IsMineResult::INVALID;
        }
        if (sigversion == IsMineSigVersion::TOP && !keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            break;
        }
        uint160 hash;
        CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(hash.begin());
        CScriptID scriptID = CScriptID(hash);
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            ret = std::max(ret, IsMineInner(keystore, subscript, IsMineSigVersion::WITNESS_V0));
        }
        break;
    }

    case TX_MULTISIG:
    {
        // Never treat bare multisig outputs as ours (they can still be made watchonly-though)
        if (sigversion == IsMineSigVersion::TOP) {
            break;
        }

        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (!PermitsUncompressed(sigversion)) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    return IsMineResult::INVALID;
                }
            }
        }
        if (HaveKeys(keys, keystore)) {
            ret = std::max(ret, IsMineResult::SPENDABLE);
        }
        break;
    }
    }

    if (ret == IsMineResult::NO && keystore.HaveWatchOnly(scriptPubKey)) {
        ret = std::max(ret, IsMineResult::WATCH_ONLY);
    }
    return ret;
}

} // namespace

isminetype LegacyScriptPubKeyMan::IsMine(const CScript& script) const
{
    switch (IsMineInner(*this, script, IsMineSigVersion::TOP)) {
    case IsMineResult::INVALID:
    case IsMineResult::NO:
        return ISMINE_NO;
    case IsMineResult::WATCH_ONLY:
        return ISMINE_WATCH_ONLY;
    case IsMineResult::SPENDABLE:
        return ISMINE_SPENDABLE;
    }
    assert(false);
}

bool LegacyScriptPubKeyMan::IsCrypted() const
{
    return fUseCrypto;
}

bool LegacyScriptPubKeyMan::SetCrypted()
{
    LOCK(cs_KeyStore);
    if (fUseCrypto)
        return true;
    if (!mapKeys.empty())
        return false;
    fUseCrypto = true;
    return true;
}

bool LegacyScriptPubKeyMan::IsLocked() const
{
    if (!IsCrypted()) {
        return false;
    }
    LOCK(cs_KeyStore);
    return vMasterKey.empty();
}

bool LegacyScriptPubKeyMan::Lock()
{
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_KeyStore);
        vMasterKey.clear();
    }

    return true;
}

bool LegacyScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool)
{
    if (!CanGetAddresses(internal)) {
        return false;
    }

    {
        LOCK(cs_KeyStore);
        if (!ReserveKeyFromKeyPool(index, keypool, internal) && !IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            return false;
        }
        address = GetDestinationForKey(keypool.vchPubKey, type);
    }
    return true;
}

void LegacyScriptPubKeyMan::KeepDestination(int64_t index)
{
    KeepKey(index);
}

void LegacyScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
    ReturnKey(index, internal, m_reserved_key_to_index[index]);
    m_reserved_key_to_index.erase(index);
}

bool LegacyScriptPubKeyMan::TopUp(unsigned int size)
{
    return TopUpKeyPool(size);
}

void LegacyScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
    LOCK(cs_KeyStore);
    // extract addresses and check if they match with an unused keypool key
    for (const auto& keyid : GetAffectedKeys(script, *this)) {
        std::map<CKeyID, int64_t>::const_iterator mi = m_pool_key_to_index.find(keyid);
        if (mi != m_pool_key_to_index.end()) {
            WalletLogPrintf("%s: Detected a used keypool key, mark all keypool key up to this key as used\n", __func__);
            MarkReserveKeysAsUsed(mi->second);

            if (!TopUpKeyPool()) {
                WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
            }
        }
    }
}

void LegacyScriptPubKeyMan::UpgradeKeyMetadata()
{
    LOCK(cs_KeyStore);
    if (IsLocked() || IsWalletFlagSet(WALLET_FLAG_KEY_ORIGIN_METADATA)) {
        return;
    }

    std::unique_ptr<WalletBatch> batch = MakeUnique<WalletBatch>(*m_database);
    for (auto& meta_pair : mapKeyMetadata) {
        CKeyMetadata& meta = meta_pair.second;
        if (!meta.hd_seed_id.IsNull() && !meta.has_key_origin && meta.hdKeypath != "s") { // If the hdKeypath is "s", that's the seed and it doesn't have a key origin
            CKey key;
            GetKey(meta.hd_seed_id, key);
            CExtKey masterKey;
            masterKey.SetSeed(key.begin(), key.size());
            // Add to map
            CKeyID master_id = masterKey.key.GetPubKey().GetID();
            std::copy(master_id.begin(), master_id.begin() + 4, meta.key_origin.fingerprint);
            if (!ParseHDKeypath(meta.hdKeypath, meta.key_origin.path)) {
                throw std::runtime_error("Invalid stored hdKeypath");
            }
            meta.has_key_origin = true;
            if (meta.nVersion < CKeyMetadata::VERSION_WITH_KEY_ORIGIN) {
                meta.nVersion = CKeyMetadata::VERSION_WITH_KEY_ORIGIN;
            }

            // Write meta to wallet
            CPubKey pubkey;
            if (GetPubKey(meta_pair.first, pubkey)) {
                batch->WriteKeyMetadata(meta, pubkey, true);
            }
        }
    }
    batch.reset(); //write before setting the flag
}

bool LegacyScriptPubKeyMan::SetupGeneration(bool force)
{
    if ((CanGenerateKeys() && !force) || IsLocked()) {
        return false;
    }

    SetHDSeed(GenerateNewSeed());
    if (!NewKeyPool()) {
        return false;
    }
    return true;
}

bool LegacyScriptPubKeyMan::IsHDEnabled() const
{
    return !hdChain.seed_id.IsNull();
}

bool LegacyScriptPubKeyMan::CanGetAddresses(bool internal)
{
    LOCK(cs_KeyStore);
    // Check if the keypool has keys
    bool keypool_has_keys;
    if (internal && CanSupportFeature(FEATURE_HD_SPLIT)) {
        keypool_has_keys = setInternalKeyPool.size() > 0;
    } else {
        keypool_has_keys = KeypoolCountExternalKeys() > 0;
    }
    // If the keypool doesn't have keys, check if we can generate them
    if (!keypool_has_keys) {
        return CanGenerateKeys();
    }
    return keypool_has_keys;
}

bool LegacyScriptPubKeyMan::Upgrade(int prev_version, int new_version)
{
    LOCK(cs_KeyStore);
    bool hd_upgrade = false;
    bool split_upgrade = false;
    if (CanSupportFeature(FEATURE_HD) && !IsHDEnabled()) {
        WalletLogPrintf("Upgrading wallet to HD\n");
        SetMinVersion(FEATURE_HD, nullptr, false);

        // generate a new master key
        SetHDSeed(GenerateNewSeed());
        hd_upgrade = true;
    }
    // Upgrade to HD chain split if necessary
    if (CanSupportFeature(FEATURE_HD_SPLIT) && hdChain.nVersion < 2 /* VERSION_HD_CHAIN_SPLIT */) {
        WalletLogPrintf("Upgrading wallet to use HD chain split\n");
        SetMinVersion(FEATURE_PRE_SPLIT_KEYPOOL, nullptr, false);
        split_upgrade = FEATURE_HD_SPLIT > prev_version;
    }
    // Mark all keys currently in the keypool as pre-split
    if (split_upgrade) {
        MarkPreSplitKeys();
    }
    // Regenerate the keypool if upgraded to HD
    if (hd_upgrade) {
        if (!TopUpKeyPool()) {
            return false;
        }
    }
    return true;
}

bool LegacyScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_KeyStore);
    return !mapKeys.empty() || !mapCryptedKeys.empty();
}

void LegacyScriptPubKeyMan::RewriteDB()
{
    LOCK(cs_KeyStore);
    setInternalKeyPool.clear();
    setExternalKeyPool.clear();
    m_pool_key_to_index.clear();
    // Note: can't top-up keypool here, because wallet is locked.
    // User will be prompted to unlock wallet the next operation
    // that requires a new key.
}

static int64_t GetOldestKeyTimeInPool(const std::set<int64_t>& setKeyPool, WalletBatch& batch) {
    if (setKeyPool.empty()) {
        return GetTime();
    }

    CKeyPool keypool;
    int64_t nIndex = *(setKeyPool.begin());
    if (!batch.ReadPool(nIndex, keypool)) {
        throw std::runtime_error(std::string(__func__) + ": read oldest key in keypool failed");
    }
    assert(keypool.vchPubKey.IsValid());
    return keypool.nTime;
}

int64_t LegacyScriptPubKeyMan::GetOldestKeyPoolTime()
{
    LOCK(cs_KeyStore);

    WalletBatch batch(*m_database);

    // load oldest key from keypool, get time and return
    int64_t oldestKey = GetOldestKeyTimeInPool(setExternalKeyPool, batch);
    if (IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT)) {
        oldestKey = std::max(GetOldestKeyTimeInPool(setInternalKeyPool, batch), oldestKey);
        if (!set_pre_split_keypool.empty()) {
            oldestKey = std::max(GetOldestKeyTimeInPool(set_pre_split_keypool, batch), oldestKey);
        }
    }

    return oldestKey;
}

size_t LegacyScriptPubKeyMan::KeypoolCountExternalKeys()
{
    LOCK(cs_KeyStore);
    return setExternalKeyPool.size() + set_pre_split_keypool.size();
}

unsigned int LegacyScriptPubKeyMan::GetKeypoolSize() const
{
    LOCK(cs_KeyStore);
    return setInternalKeyPool.size() + setExternalKeyPool.size() + set_pre_split_keypool.size();
}

int64_t LegacyScriptPubKeyMan::GetTimeFirstKey() const
{
    LOCK(cs_KeyStore);
    return nTimeFirstKey;
}

std::unique_ptr<SigningProvider> LegacyScriptPubKeyMan::GetSigningProvider(const CScript& script) const
{
    return MakeUnique<LegacySigningProvider>(this);
}

bool LegacyScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    if (IsMine(script) != ISMINE_NO) {
        return true;
    } else if (HaveCScript(CScriptID(script))) {
        return true;
    } else {
        ProduceSignature(*this, DUMMY_SIGNATURE_CREATOR, script, sigdata);
        if (!sigdata.signatures.empty()) {
            // If we could make signatures, make sure we have the private key
            bool has_privkeys = false;
            for (const auto& key_sig_pair : sigdata.signatures) {
                has_privkeys |= HaveKey(key_sig_pair.first);
            }
            return has_privkeys;
        }
        return false;
    }
}

const CKeyMetadata* LegacyScriptPubKeyMan::GetMetadata(uint160 id) const
{
    LOCK(cs_KeyStore);
    auto it = mapKeyMetadata.find(CKeyID(id));
    if (it != mapKeyMetadata.end()) {
        return &it->second;
    } else {
        auto it2 = m_script_metadata.find(CScriptID(id));
        if (it2 != m_script_metadata.end()) {
            return &it2->second;
        }
    }
    return nullptr;
}

uint256 LegacyScriptPubKeyMan::GetID() const
{
    return uint256S("0000000000000000000000000000000000000000000000000000000000000001");
}

/**
 * Update wallet first key creation time. This should be called whenever keys
 * are added to the wallet, with the oldest key creation time.
 */
void LegacyScriptPubKeyMan::UpdateTimeFirstKey(int64_t nCreateTime)
{
    AssertLockHeld(cs_KeyStore);
    if (nCreateTime <= 1) {
        // Cannot determine birthday information, so set the wallet birthday to
        // the beginning of time.
        nTimeFirstKey = 1;
    } else if (!nTimeFirstKey || nCreateTime < nTimeFirstKey) {
        nTimeFirstKey = nCreateTime;
    }
}

bool LegacyScriptPubKeyMan::LoadKey(const CKey& key, const CPubKey &pubkey)
{
    return AddKeyPubKeyInner(key, pubkey);
}

bool LegacyScriptPubKeyMan::AddKeyPubKey(const CKey& secret, const CPubKey &pubkey)
{
    WalletBatch batch(*m_database);
    return LegacyScriptPubKeyMan::AddKeyPubKeyWithDB(batch, secret, pubkey);
}

bool LegacyScriptPubKeyMan::AddKeyPubKeyWithDB(WalletBatch& batch, const CKey& secret, const CPubKey& pubkey)
{
    AssertLockHeld(cs_KeyStore);

    // Make sure we aren't adding private keys to private key disabled wallets
    assert(!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    // FillableSigningProvider has no concept of wallet databases, but calls AddCryptedKey
    // which is overridden below.  To avoid flushes, the database handle is
    // tunneled through to it.
    bool needsDB = !encrypted_batch;
    if (needsDB) {
        encrypted_batch = &batch;
    }
    if (!AddKeyPubKeyInner(secret, pubkey)) {
        if (needsDB) encrypted_batch = nullptr;
        return false;
    }
    if (needsDB) encrypted_batch = nullptr;

    // check if we need to remove from watch-only
    CScript script;
    script = GetScriptForDestination(PKHash(pubkey));
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }
    script = GetScriptForRawPubKey(pubkey);
    if (HaveWatchOnly(script)) {
        RemoveWatchOnly(script);
    }

    if (!IsCrypted()) {
        return batch.WriteKey(pubkey,
                                                 secret.GetPrivKey(),
                                                 mapKeyMetadata[pubkey.GetID()]);
    }
    UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
    return true;
}

bool LegacyScriptPubKeyMan::LoadCScript(const CScript& redeemScript)
{
    /* A sanity check was added in pull #3843 to avoid adding redeemScripts
     * that never can be redeemed. However, old wallets may still contain
     * these. Do not add them to the wallet and warn. */
    if (redeemScript.size() > MAX_SCRIPT_ELEMENT_SIZE)
    {
        std::string strAddr = EncodeDestination(ScriptHash(redeemScript));
        WalletLogPrintf("%s: Warning: This wallet contains a redeemScript of size %i which exceeds maximum size %i thus can never be redeemed. Do not use address %s.\n", __func__, redeemScript.size(), MAX_SCRIPT_ELEMENT_SIZE, strAddr);
        return true;
    }

    return FillableSigningProvider::AddCScript(redeemScript);
}

void LegacyScriptPubKeyMan::LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    UpdateTimeFirstKey(meta.nCreateTime);
    mapKeyMetadata[keyID] = meta;
}

void LegacyScriptPubKeyMan::LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata& meta)
{
    LOCK(cs_KeyStore);
    UpdateTimeFirstKey(meta.nCreateTime);
    m_script_metadata[script_id] = meta;
}

bool LegacyScriptPubKeyMan::AddKeyPubKeyInner(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return FillableSigningProvider::AddKeyPubKey(key, pubkey);
    }

    if (IsLocked()) {
        return false;
    }

    std::vector<unsigned char> vchCryptedSecret;
    CKeyingMaterial vchSecret(key.begin(), key.end());
    if (!EncryptSecret(vMasterKey, vchSecret, pubkey.GetHash(), vchCryptedSecret)) {
        return false;
    }

    if (!AddCryptedKey(pubkey, vchCryptedSecret)) {
        return false;
    }
    return true;
}

bool LegacyScriptPubKeyMan::Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch)
{
    LOCK(cs_KeyStore);
    encrypted_batch = batch;
    if (!mapCryptedKeys.empty() || IsCrypted()) {
        encrypted_batch = nullptr;
        return false;
    }

    fUseCrypto = true;
    for (const KeyMap::value_type& mKey : mapKeys)
    {
        const CKey &key = mKey.second;
        CPubKey vchPubKey = key.GetPubKey();
        CKeyingMaterial vchSecret(key.begin(), key.end());
        std::vector<unsigned char> vchCryptedSecret;
        if (!EncryptSecret(vMasterKeyIn, vchSecret, vchPubKey.GetHash(), vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
        if (!AddCryptedKey(vchPubKey, vchCryptedSecret)) {
            encrypted_batch = nullptr;
            return false;
        }
    }
    mapKeys.clear();
    encrypted_batch = nullptr;
    return true;
}

bool LegacyScriptPubKeyMan::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return AddCryptedKeyInner(vchPubKey, vchCryptedSecret);
}

bool LegacyScriptPubKeyMan::AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    LOCK(cs_KeyStore);
    if (!SetCrypted()) {
        return false;
    }

    mapCryptedKeys[vchPubKey.GetID()] = make_pair(vchPubKey, vchCryptedSecret);
    ImplicitlyLearnRelatedKeyScripts(vchPubKey);
    return true;
}

bool LegacyScriptPubKeyMan::AddCryptedKey(const CPubKey &vchPubKey,
                            const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!AddCryptedKeyInner(vchPubKey, vchCryptedSecret))
        return false;
    {
        LOCK(cs_KeyStore);
        if (encrypted_batch)
            return encrypted_batch->WriteCryptedKey(vchPubKey,
                                                        vchCryptedSecret,
                                                        mapKeyMetadata[vchPubKey.GetID()]);
        else
            return WalletBatch(*m_database).WriteCryptedKey(vchPubKey,
                                                            vchCryptedSecret,
                                                            mapKeyMetadata[vchPubKey.GetID()]);
    }
}

bool LegacyScriptPubKeyMan::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool LegacyScriptPubKeyMan::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    //TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || !CPubKey::ValidSize(vch))
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;
}

bool LegacyScriptPubKeyMan::RemoveWatchOnly(const CScript &dest)
{
    {
        LOCK(cs_KeyStore);
        setWatchOnly.erase(dest);
        CPubKey pubKey;
        if (ExtractPubKey(dest, pubKey)) {
            mapWatchKeys.erase(pubKey.GetID());
        }
        // Related CScripts are not removed; having superfluous scripts around is
        // harmless (see comment in ImplicitlyLearnRelatedKeyScripts).
    }

    if (!HaveWatchOnly())
        NotifyWatchonlyChanged(false);
    if (!WalletBatch(*m_database).EraseWatchOnly(dest))
        return false;

    return true;
}

bool LegacyScriptPubKeyMan::LoadWatchOnly(const CScript &dest)
{
    return AddWatchOnlyInMem(dest);
}

bool LegacyScriptPubKeyMan::AddWatchOnlyInMem(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey)) {
        mapWatchKeys[pubKey.GetID()] = pubKey;
        ImplicitlyLearnRelatedKeyScripts(pubKey);
    }
    return true;
}

bool LegacyScriptPubKeyMan::AddWatchOnlyWithDB(WalletBatch &batch, const CScript& dest)
{
    if (!AddWatchOnlyInMem(dest))
        return false;
    const CKeyMetadata& meta = m_script_metadata[CScriptID(dest)];
    UpdateTimeFirstKey(meta.nCreateTime);
    NotifyWatchonlyChanged(true);
    if (batch.WriteWatchOnly(dest, meta)) {
        UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
        return true;
    }
    return false;
}

bool LegacyScriptPubKeyMan::AddWatchOnlyWithDB(WalletBatch &batch, const CScript& dest, int64_t create_time)
{
    m_script_metadata[CScriptID(dest)].nCreateTime = create_time;
    return AddWatchOnlyWithDB(batch, dest);
}

bool LegacyScriptPubKeyMan::AddWatchOnly(const CScript& dest)
{
    WalletBatch batch(*m_database);
    return AddWatchOnlyWithDB(batch, dest);
}

bool LegacyScriptPubKeyMan::AddWatchOnly(const CScript& dest, int64_t nCreateTime)
{
    m_script_metadata[CScriptID(dest)].nCreateTime = nCreateTime;
    return AddWatchOnly(dest);
}

void LegacyScriptPubKeyMan::SetHDChain(const CHDChain& chain, bool memonly)
{
    LOCK(cs_KeyStore);
    if (!memonly && !WalletBatch(*m_database).WriteHDChain(chain))
        throw std::runtime_error(std::string(__func__) + ": writing chain failed");

    hdChain = chain;
}

bool LegacyScriptPubKeyMan::HaveKey(const CKeyID &address) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return FillableSigningProvider::HaveKey(address);
    }
    return mapCryptedKeys.count(address) > 0;
}

bool LegacyScriptPubKeyMan::GetKey(const CKeyID &address, CKey& keyOut) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        return FillableSigningProvider::GetKey(address, keyOut);
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        const CPubKey &vchPubKey = (*mi).second.first;
        const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
        return DecryptKey(vMasterKey, vchCryptedSecret, vchPubKey, keyOut);
    }
    return false;
}

bool LegacyScriptPubKeyMan::GetKeyOrigin(const CKeyID& keyID, KeyOriginInfo& info) const
{
    CKeyMetadata meta;
    {
        LOCK(cs_KeyStore);
        auto it = mapKeyMetadata.find(keyID);
        if (it != mapKeyMetadata.end()) {
            meta = it->second;
        }
    }
    if (meta.has_key_origin) {
        std::copy(meta.key_origin.fingerprint, meta.key_origin.fingerprint + 4, info.fingerprint);
        info.path = meta.key_origin.path;
    } else { // Single pubkeys get the master fingerprint of themselves
        std::copy(keyID.begin(), keyID.begin() + 4, info.fingerprint);
    }
    return true;
}

bool LegacyScriptPubKeyMan::Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys)
{
    {
        LOCK(cs_KeyStore);
        if (!SetCrypted())
            return false;

        bool keyPass = mapCryptedKeys.empty(); // Always pass when there are no encrypted keys
        bool keyFail = false;
        CryptedKeyMap::const_iterator mi = mapCryptedKeys.begin();
        for (; mi != mapCryptedKeys.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.first;
            const std::vector<unsigned char> &vchCryptedSecret = (*mi).second.second;
            CKey key;
            if (!DecryptKey(vMasterKeyIn, vchCryptedSecret, vchPubKey, key))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The wallet is probably corrupted: Some keys decrypt but not all.\n");
            throw std::runtime_error("Error unlocking wallet: some keys decrypt but not all. Your wallet file may be corrupt.");
        }
        if (keyFail || (!keyPass && !accept_no_keys))
            return false;
        vMasterKey = vMasterKeyIn;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

bool LegacyScriptPubKeyMan::GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const
{
    LOCK(cs_KeyStore);
    WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
    if (it != mapWatchKeys.end()) {
        pubkey_out = it->second;
        return true;
    }
    return false;
}

bool LegacyScriptPubKeyMan::GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    LOCK(cs_KeyStore);
    if (!IsCrypted()) {
        if (!FillableSigningProvider::GetPubKey(address, vchPubKeyOut)) {
            return GetWatchPubKey(address, vchPubKeyOut);
        }
        return true;
    }

    CryptedKeyMap::const_iterator mi = mapCryptedKeys.find(address);
    if (mi != mapCryptedKeys.end())
    {
        vchPubKeyOut = (*mi).second.first;
        return true;
    }
    // Check for watch-only pubkeys
    return GetWatchPubKey(address, vchPubKeyOut);
}

CPubKey LegacyScriptPubKeyMan::GenerateNewKey(WalletBatch &batch, bool internal)
{
    assert(!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    assert(!IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
    AssertLockHeld(cs_KeyStore);
    bool fCompressed = CanSupportFeature(FEATURE_COMPRPUBKEY); // default to compressed public keys if we want 0.6.0 wallets

    CKey secret;

    // Create new metadata
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // use HD key derivation if HD was enabled during wallet creation and a seed is present
    if (IsHDEnabled()) {
        DeriveNewChildKey(batch, metadata, secret, (CanSupportFeature(FEATURE_HD_SPLIT) ? internal : false));
    } else {
        secret.MakeNewKey(fCompressed);
    }

    // Compressed public keys were introduced in version 0.6.0
    if (fCompressed) {
        SetMinVersion(FEATURE_COMPRPUBKEY, nullptr, false);
    }

    CPubKey pubkey = secret.GetPubKey();
    assert(secret.VerifyPubKey(pubkey));

    mapKeyMetadata[pubkey.GetID()] = metadata;
    UpdateTimeFirstKey(nCreationTime);

    if (!AddKeyPubKeyWithDB(batch, secret, pubkey)) {
        throw std::runtime_error(std::string(__func__) + ": AddKey failed");
    }
    return pubkey;
}

const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

void LegacyScriptPubKeyMan::DeriveNewChildKey(WalletBatch &batch, CKeyMetadata& metadata, CKey& secret, bool internal)
{
    // for now we use a fixed keypath scheme of m/0'/0'/k
    CKey seed;                     //seed (256bit)
    CExtKey masterKey;             //hd master key
    CExtKey accountKey;            //key at m/0'
    CExtKey chainChildKey;         //key at m/0'/0' (external) or m/0'/1' (internal)
    CExtKey childKey;              //key at m/0'/0'/<n>'

    // try to get the seed
    if (!GetKey(hdChain.seed_id, seed))
        throw std::runtime_error(std::string(__func__) + ": seed not found");

    masterKey.SetSeed(seed.begin(), seed.size());

    // derive m/0'
    // use hardened derivation (child keys >= 0x80000000 are hardened after bip32)
    masterKey.Derive(accountKey, BIP32_HARDENED_KEY_LIMIT);

    // derive m/0'/0' (external chain) OR m/0'/1' (internal chain)
    assert(internal ? CanSupportFeature(FEATURE_HD_SPLIT) : true);
    accountKey.Derive(chainChildKey, BIP32_HARDENED_KEY_LIMIT+(internal ? 1 : 0));

    // derive child key at next index, skip keys already known to the wallet
    do {
        // always derive hardened keys
        // childIndex | BIP32_HARDENED_KEY_LIMIT = derive childIndex in hardened child-index-range
        // example: 1 | BIP32_HARDENED_KEY_LIMIT == 0x80000001 == 2147483649
        if (internal) {
            chainChildKey.Derive(childKey, hdChain.nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/1'/" + std::to_string(hdChain.nInternalChainCounter) + "'";
            metadata.key_origin.path.push_back(0 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(1 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(hdChain.nInternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            hdChain.nInternalChainCounter++;
        }
        else {
            chainChildKey.Derive(childKey, hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            metadata.hdKeypath = "m/0'/0'/" + std::to_string(hdChain.nExternalChainCounter) + "'";
            metadata.key_origin.path.push_back(0 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(0 | BIP32_HARDENED_KEY_LIMIT);
            metadata.key_origin.path.push_back(hdChain.nExternalChainCounter | BIP32_HARDENED_KEY_LIMIT);
            hdChain.nExternalChainCounter++;
        }
    } while (HaveKey(childKey.key.GetPubKey().GetID()));
    secret = childKey.key;
    metadata.hd_seed_id = hdChain.seed_id;
    CKeyID master_id = masterKey.key.GetPubKey().GetID();
    std::copy(master_id.begin(), master_id.begin() + 4, metadata.key_origin.fingerprint);
    metadata.has_key_origin = true;
    // update the chain model in the database
    if (!batch.WriteHDChain(hdChain))
        throw std::runtime_error(std::string(__func__) + ": Writing HD chain model failed");
}

void LegacyScriptPubKeyMan::LoadKeyPool(int64_t nIndex, const CKeyPool &keypool)
{
    LOCK(cs_KeyStore);
    if (keypool.m_pre_split) {
        set_pre_split_keypool.insert(nIndex);
    } else if (keypool.fInternal) {
        setInternalKeyPool.insert(nIndex);
    } else {
        setExternalKeyPool.insert(nIndex);
    }
    m_max_keypool_index = std::max(m_max_keypool_index, nIndex);
    m_pool_key_to_index[keypool.vchPubKey.GetID()] = nIndex;

    // If no metadata exists yet, create a default with the pool key's
    // creation time. Note that this may be overwritten by actually
    // stored metadata for that key later, which is fine.
    CKeyID keyid = keypool.vchPubKey.GetID();
    if (mapKeyMetadata.count(keyid) == 0)
        mapKeyMetadata[keyid] = CKeyMetadata(keypool.nTime);
}

bool LegacyScriptPubKeyMan::CanGenerateKeys()
{
    // A wallet can generate keys if it has an HD seed (IsHDEnabled) or it is a non-HD wallet (pre FEATURE_HD)
    LOCK(cs_KeyStore);
    return IsHDEnabled() || !CanSupportFeature(FEATURE_HD);
}

CPubKey LegacyScriptPubKeyMan::GenerateNewSeed()
{
    assert(!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    CKey key;
    key.MakeNewKey(true);
    return DeriveNewSeed(key);
}

CPubKey LegacyScriptPubKeyMan::DeriveNewSeed(const CKey& key)
{
    int64_t nCreationTime = GetTime();
    CKeyMetadata metadata(nCreationTime);

    // calculate the seed
    CPubKey seed = key.GetPubKey();
    assert(key.VerifyPubKey(seed));

    // set the hd keypath to "s" -> Seed, refers the seed to itself
    metadata.hdKeypath     = "s";
    metadata.has_key_origin = false;
    metadata.hd_seed_id = seed.GetID();

    {
        LOCK(cs_KeyStore);

        // mem store the metadata
        mapKeyMetadata[seed.GetID()] = metadata;

        // write the key&metadata to the database
        if (!AddKeyPubKey(key, seed))
            throw std::runtime_error(std::string(__func__) + ": AddKeyPubKey failed");
    }

    return seed;
}

void LegacyScriptPubKeyMan::SetHDSeed(const CPubKey& seed)
{
    LOCK(cs_KeyStore);
    // store the keyid (hash160) together with
    // the child index counter in the database
    // as a hdchain object
    CHDChain newHdChain;
    newHdChain.nVersion = CanSupportFeature(FEATURE_HD_SPLIT) ? CHDChain::VERSION_HD_CHAIN_SPLIT : CHDChain::VERSION_HD_BASE;
    newHdChain.seed_id = seed.GetID();
    SetHDChain(newHdChain, false);
    NotifyCanGetAddressesChanged();
    WalletBatch batch(*m_database);
    UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
}

/**
 * Mark old keypool keys as used,
 * and generate all new keys
 */
bool LegacyScriptPubKeyMan::NewKeyPool()
{
    if (IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
        return false;
    }
    {
        LOCK(cs_KeyStore);
        WalletBatch batch(*m_database);

        for (const int64_t nIndex : setInternalKeyPool) {
            batch.ErasePool(nIndex);
        }
        setInternalKeyPool.clear();

        for (const int64_t nIndex : setExternalKeyPool) {
            batch.ErasePool(nIndex);
        }
        setExternalKeyPool.clear();

        for (const int64_t nIndex : set_pre_split_keypool) {
            batch.ErasePool(nIndex);
        }
        set_pre_split_keypool.clear();

        m_pool_key_to_index.clear();

        if (!TopUpKeyPool()) {
            return false;
        }
        WalletLogPrintf("CWallet::NewKeyPool rewrote keypool\n");
    }
    return true;
}

bool LegacyScriptPubKeyMan::TopUpKeyPool(unsigned int kpSize)
{
    if (!CanGenerateKeys()) {
        return false;
    }
    {
        LOCK(cs_KeyStore);

        if (IsLocked()) return false;

        // Top up key pool
        unsigned int nTargetSize;
        if (kpSize > 0)
            nTargetSize = kpSize;
        else
            nTargetSize = std::max(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);

        // count amount of available keys (internal, external)
        // make sure the keypool of external and internal keys fits the user selected target (-keypool)
        int64_t missingExternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setExternalKeyPool.size(), (int64_t) 0);
        int64_t missingInternal = std::max(std::max((int64_t) nTargetSize, (int64_t) 1) - (int64_t)setInternalKeyPool.size(), (int64_t) 0);

        if (!IsHDEnabled() || !CanSupportFeature(FEATURE_HD_SPLIT))
        {
            // don't create extra internal keys
            missingInternal = 0;
        }
        bool internal = false;
        WalletBatch batch(*m_database);
        for (int64_t i = missingInternal + missingExternal; i--;)
        {
            if (i < missingInternal) {
                internal = true;
            }

            CPubKey pubkey(GenerateNewKey(batch, internal));
            AddKeypoolPubkeyWithDB(pubkey, internal, batch);
        }
        if (missingInternal + missingExternal > 0) {
            WalletLogPrintf("keypool added %d keys (%d internal), size=%u (%u internal)\n", missingInternal + missingExternal, missingInternal, setInternalKeyPool.size() + setExternalKeyPool.size() + set_pre_split_keypool.size(), setInternalKeyPool.size());
        }
    }
    NotifyCanGetAddressesChanged();
    return true;
}

void LegacyScriptPubKeyMan::AddKeypoolPubkeyWithDB(const CPubKey& pubkey, const bool internal, WalletBatch& batch)
{
    LOCK(cs_KeyStore);
    assert(m_max_keypool_index < std::numeric_limits<int64_t>::max()); // How in the hell did you use so many keys?
    int64_t index = ++m_max_keypool_index;
    if (!batch.WritePool(index, CKeyPool(pubkey, internal))) {
        throw std::runtime_error(std::string(__func__) + ": writing imported pubkey failed");
    }
    if (internal) {
        setInternalKeyPool.insert(index);
    } else {
        setExternalKeyPool.insert(index);
    }
    m_pool_key_to_index[pubkey.GetID()] = index;
}

void LegacyScriptPubKeyMan::KeepKey(int64_t nIndex)
{
    // Remove from key pool
    WalletBatch batch(*m_database);
    batch.ErasePool(nIndex);
    WalletLogPrintf("keypool keep %d\n", nIndex);
}

void LegacyScriptPubKeyMan::ReturnKey(int64_t nIndex, bool fInternal, const CKeyID& pubkey_id)
{
    // Return to key pool
    {
        LOCK(cs_KeyStore);
        if (fInternal) {
            setInternalKeyPool.insert(nIndex);
        } else if (!set_pre_split_keypool.empty()) {
            set_pre_split_keypool.insert(nIndex);
        } else {
            setExternalKeyPool.insert(nIndex);
        }
        m_pool_key_to_index[pubkey_id] = nIndex;
        NotifyCanGetAddressesChanged();
    }
    WalletLogPrintf("keypool return %d\n", nIndex);
}

bool LegacyScriptPubKeyMan::GetKeyFromPool(CPubKey& result, bool internal)
{
    if (!CanGetAddresses(internal)) {
        return false;
    }

    CKeyPool keypool;
    {
        LOCK(cs_KeyStore);
        int64_t nIndex;
        if (!ReserveKeyFromKeyPool(nIndex, keypool, internal) && !IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) {
            if (IsLocked()) return false;
            WalletBatch batch(*m_database);
            result = GenerateNewKey(batch, internal);
            return true;
        }
        KeepKey(nIndex);
        result = keypool.vchPubKey;
    }
    return true;
}

bool LegacyScriptPubKeyMan::ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fRequestedInternal)
{
    nIndex = -1;
    keypool.vchPubKey = CPubKey();
    {
        LOCK(cs_KeyStore);

        TopUpKeyPool();

        bool fReturningInternal = fRequestedInternal;
        fReturningInternal &= (IsHDEnabled() && CanSupportFeature(FEATURE_HD_SPLIT)) || IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        bool use_split_keypool = set_pre_split_keypool.empty();
        std::set<int64_t>& setKeyPool = use_split_keypool ? (fReturningInternal ? setInternalKeyPool : setExternalKeyPool) : set_pre_split_keypool;

        // Get the oldest key
        if (setKeyPool.empty()) {
            return false;
        }

        WalletBatch batch(*m_database);

        auto it = setKeyPool.begin();
        nIndex = *it;
        setKeyPool.erase(it);
        if (!batch.ReadPool(nIndex, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read failed");
        }
        CPubKey pk;
        if (!GetPubKey(keypool.vchPubKey.GetID(), pk)) {
            throw std::runtime_error(std::string(__func__) + ": unknown key in key pool");
        }
        // If the key was pre-split keypool, we don't care about what type it is
        if (use_split_keypool && keypool.fInternal != fReturningInternal) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry misclassified");
        }
        if (!keypool.vchPubKey.IsValid()) {
            throw std::runtime_error(std::string(__func__) + ": keypool entry invalid");
        }

        m_reserved_key_to_index[nIndex] = keypool.vchPubKey.GetID();
        m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        WalletLogPrintf("keypool reserve %d\n", nIndex);
    }
    NotifyCanGetAddressesChanged();
    return true;
}

void LegacyScriptPubKeyMan::LearnRelatedScripts(const CPubKey& key, OutputType type)
{
    if (key.IsCompressed() && (type == OutputType::P2SH_SEGWIT || type == OutputType::BECH32)) {
        CTxDestination witdest = WitnessV0KeyHash(key.GetID());
        CScript witprog = GetScriptForDestination(witdest);
        // Make sure the resulting program is solvable.
        assert(IsSolvable(*this, witprog));
        AddCScript(witprog);
    }
}

void LegacyScriptPubKeyMan::LearnAllRelatedScripts(const CPubKey& key)
{
    // OutputType::P2SH_SEGWIT always adds all necessary scripts for all types.
    LearnRelatedScripts(key, OutputType::P2SH_SEGWIT);
}

void LegacyScriptPubKeyMan::MarkReserveKeysAsUsed(int64_t keypool_id)
{
    AssertLockHeld(cs_KeyStore);
    bool internal = setInternalKeyPool.count(keypool_id);
    if (!internal) assert(setExternalKeyPool.count(keypool_id) || set_pre_split_keypool.count(keypool_id));
    std::set<int64_t> *setKeyPool = internal ? &setInternalKeyPool : (set_pre_split_keypool.empty() ? &setExternalKeyPool : &set_pre_split_keypool);
    auto it = setKeyPool->begin();

    WalletBatch batch(*m_database);
    while (it != std::end(*setKeyPool)) {
        const int64_t& index = *(it);
        if (index > keypool_id) break; // set*KeyPool is ordered

        CKeyPool keypool;
        if (batch.ReadPool(index, keypool)) { //TODO: This should be unnecessary
            m_pool_key_to_index.erase(keypool.vchPubKey.GetID());
        }
        LearnAllRelatedScripts(keypool.vchPubKey);
        batch.ErasePool(index);
        WalletLogPrintf("keypool index %d removed\n", index);
        it = setKeyPool->erase(it);
    }
}

std::vector<CKeyID> GetAffectedKeys(const CScript& spk, const SigningProvider& provider)
{
    std::vector<CScript> dummy;
    FlatSigningProvider out;
    InferDescriptor(spk, provider)->Expand(0, DUMMY_SIGNING_PROVIDER, dummy, out);
    std::vector<CKeyID> ret;
    for (const auto& entry : out.pubkeys) {
        ret.push_back(entry.first);
    }
    return ret;
}

void LegacyScriptPubKeyMan::MarkPreSplitKeys()
{
    WalletBatch batch(*m_database);
    for (auto it = setExternalKeyPool.begin(); it != setExternalKeyPool.end();) {
        int64_t index = *it;
        CKeyPool keypool;
        if (!batch.ReadPool(index, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": read keypool entry failed");
        }
        keypool.m_pre_split = true;
        if (!batch.WritePool(index, keypool)) {
            throw std::runtime_error(std::string(__func__) + ": writing modified keypool entry failed");
        }
        set_pre_split_keypool.insert(index);
        it = setExternalKeyPool.erase(it);
    }
}

bool LegacyScriptPubKeyMan::AddCScript(const CScript& redeemScript)
{
    WalletBatch batch(*m_database);
    return AddCScriptWithDB(batch, redeemScript);
}

bool LegacyScriptPubKeyMan::AddCScriptWithDB(WalletBatch& batch, const CScript& redeemScript)
{
    if (!FillableSigningProvider::AddCScript(redeemScript))
        return false;
    if (batch.WriteCScript(Hash160(redeemScript), redeemScript)) {
        UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
        return true;
    }
    return false;
}

bool LegacyScriptPubKeyMan::AddKeyOriginWithDB(WalletBatch& batch, const CPubKey& pubkey, const KeyOriginInfo& info)
{
    LOCK(cs_KeyStore);
    std::copy(info.fingerprint, info.fingerprint + 4, mapKeyMetadata[pubkey.GetID()].key_origin.fingerprint);
    mapKeyMetadata[pubkey.GetID()].key_origin.path = info.path;
    mapKeyMetadata[pubkey.GetID()].has_key_origin = true;
    mapKeyMetadata[pubkey.GetID()].hdKeypath = WriteHDKeypath(info.path);
    return batch.WriteKeyMetadata(mapKeyMetadata[pubkey.GetID()], pubkey, true);
}

bool LegacyScriptPubKeyMan::ImportScripts(const std::set<CScript> scripts, int64_t timestamp)
{
    WalletBatch batch(*m_database);
    for (const auto& entry : scripts) {
        CScriptID id(entry);
        if (HaveCScript(id)) {
            WalletLogPrintf("Already have script %s, skipping\n", HexStr(entry));
            continue;
        }
        if (!AddCScriptWithDB(batch, entry)) {
            return false;
        }

        if (timestamp > 0) {
            m_script_metadata[CScriptID(entry)].nCreateTime = timestamp;
        }
    }
    if (timestamp > 0) {
        UpdateTimeFirstKey(timestamp);
    }

    return true;
}

bool LegacyScriptPubKeyMan::ImportPrivKeys(const std::map<CKeyID, CKey>& privkey_map, const int64_t timestamp)
{
    WalletBatch batch(*m_database);
    for (const auto& entry : privkey_map) {
        const CKey& key = entry.second;
        CPubKey pubkey = key.GetPubKey();
        const CKeyID& id = entry.first;
        assert(key.VerifyPubKey(pubkey));
        // Skip if we already have the key
        if (HaveKey(id)) {
            WalletLogPrintf("Already have key with pubkey %s, skipping\n", HexStr(pubkey));
            continue;
        }
        mapKeyMetadata[id].nCreateTime = timestamp;
        // If the private key is not present in the wallet, insert it.
        if (!AddKeyPubKeyWithDB(batch, key, pubkey)) {
            return false;
        }
        UpdateTimeFirstKey(timestamp);
    }
    return true;
}

bool LegacyScriptPubKeyMan::ImportPubKeys(const std::vector<CKeyID>& ordered_pubkeys, const std::map<CKeyID, CPubKey>& pubkey_map, const std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>>& key_origins, const bool add_keypool, const bool internal, const int64_t timestamp)
{
    WalletBatch batch(*m_database);
    for (const auto& entry : key_origins) {
        AddKeyOriginWithDB(batch, entry.second.first, entry.second.second);
    }
    for (const CKeyID& id : ordered_pubkeys) {
        auto entry = pubkey_map.find(id);
        if (entry == pubkey_map.end()) {
            continue;
        }
        const CPubKey& pubkey = entry->second;
        CPubKey temp;
        if (GetPubKey(id, temp)) {
            // Already have pubkey, skipping
            WalletLogPrintf("Already have pubkey %s, skipping\n", HexStr(temp));
            continue;
        }
        if (!AddWatchOnlyWithDB(batch, GetScriptForRawPubKey(pubkey), timestamp)) {
            return false;
        }
        mapKeyMetadata[id].nCreateTime = timestamp;

        // Add to keypool only works with pubkeys
        if (add_keypool) {
            AddKeypoolPubkeyWithDB(pubkey, internal, batch);
            NotifyCanGetAddressesChanged();
        }
    }
    return true;
}

bool LegacyScriptPubKeyMan::ImportScriptPubKeys(const std::set<CScript>& script_pub_keys, const bool have_solving_data, const int64_t timestamp)
{
    WalletBatch batch(*m_database);
    for (const CScript& script : script_pub_keys) {
        if (!have_solving_data || !IsMine(script)) { // Always call AddWatchOnly for non-solvable watch-only, so that watch timestamp gets updated
            if (!AddWatchOnlyWithDB(batch, script, timestamp)) {
                return false;
            }
        }
    }
    return true;
}

void LegacyScriptPubKeyMan::SetType(OutputType type, bool internal) {}

bool DescriptorScriptPubKeyMan::GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error)
{
    if (!CanGetAddresses(internal)) {
        error = "No private keys available";
        return false;
    }
    {
        LOCK(cs_desc_man);
        if (descriptor.descriptor->IsSingleType() && type != address_type) {
            throw std::runtime_error(std::string(__func__) + ": Types are inconsistent");
        }

        TopUp();

        // Get the scriptPubKey from the descriptor
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        if (descriptor.cache.size() <= (unsigned int)(descriptor.next_index - descriptor.range_start) && !TopUp(1)) {
            // We can't generate anymore keys
            error = "Unable to generate more addresses, try unlocking your wallet";
            return false;
        }
        descriptor.descriptor->ExpandFromCache(descriptor.next_index, descriptor.cache[descriptor.next_index - descriptor.range_start], scripts_temp, out_keys);

        if (descriptor.descriptor->IsSingleType() && !ExtractDestination(scripts_temp[0], dest)) {
            throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Stored type does not match type of newly generated address");
        } else if (!descriptor.descriptor->IsSingleType()) {
            // This is a combo descriptor, get the correct type
            bool found = false;
            for (auto script : scripts_temp) {
                if (!ExtractDestination(script, dest)) return false;
                switch (type) {
                case OutputType::LEGACY: {
                    if (dest.which() == 1 /* PKHash */) {
                        found = true;
                    }
                    break;
                }
                case OutputType::P2SH_SEGWIT: {
                    // Combo only works for keys, so there is no ambiguity with p2sh
                    if (dest.which() == 2 /* ScriptHash */) {
                        found = true;
                    }
                    break;
                }
                case OutputType::BECH32: {
                    if (dest.which() == 4 /* WitnessV0KeyHash */) {
                        found = true;
                    }
                    break;
                }
                default:
                    throw std::runtime_error(std::string(__func__) + ": Types are inconsistent. Combo descriptor did not give an adress with the expected type");
                }
                if (found) break;
            }
            if (!found) return false;
        }
        descriptor.next_index++;
        WalletBatch(*m_database).WriteDescriptor(GetID(), descriptor);
        return true;
    }
}

isminetype DescriptorScriptPubKeyMan::IsMine(const CScript& script) const
{
    LOCK(cs_desc_man);
    if (m_map_script_pub_keys.count(script) > 0) {
        return ISMINE_SPENDABLE;
    }
    return ISMINE_NO;
}

bool DescriptorScriptPubKeyMan::IsCrypted() const
{
    return m_use_crypto;
}

bool DescriptorScriptPubKeyMan::IsLocked() const
{
    if (!IsCrypted()) {
        return false;
    }
    LOCK(cs_desc_man);
    return m_master_key.empty();
}

bool DescriptorScriptPubKeyMan::Lock()
{
    if (!SetCrypted())
        return false;

    {
        LOCK(cs_desc_man);
        m_master_key.clear();
    }

    return true;
}

bool DescriptorScriptPubKeyMan::Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys)
{
    return false;
}

bool DescriptorScriptPubKeyMan::Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch)
{
    return false;
}

bool DescriptorScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool)
{
    return false;
}

void DescriptorScriptPubKeyMan::KeepDestination(int64_t index)
{
}

void DescriptorScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
}

std::map<CKeyID, CKey> DescriptorScriptPubKeyMan::GetKeys() const
{
    AssertLockHeld(cs_desc_man);
    if (IsCrypted() && !IsLocked()) {
        KeyMap keys;
        for (auto key_pair : m_map_crypted_keys) {
            const CPubKey& pubkey = key_pair.second.first;
            const std::vector<unsigned char>& crypted_secret = key_pair.second.second;
            CKey key;
            DecryptKey(m_master_key, crypted_secret, pubkey, key);
            keys[pubkey.GetID()] = key;
        }
        return keys;
    }
    return m_map_keys;
}

bool DescriptorScriptPubKeyMan::TopUp(unsigned int size)
{
    if (IsLocked()) return false;

    LOCK(cs_desc_man);
    unsigned int target_size;
    if (size > 0)
        target_size = size;
    else
        target_size = std::max(gArgs.GetArg("-keypool", DEFAULT_KEYPOOL_SIZE), (int64_t) 0);

    int32_t missing = std::max(std::max((int)target_size, 1) - (descriptor.range_end - descriptor.next_index), 0);

    FlatSigningProvider provider;
    provider.keys = GetKeys();

    WalletBatch batch(*m_database);
    uint256 id = GetID();
    for (int32_t i = descriptor.range_end; i < descriptor.range_end + missing; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        std::vector<unsigned char> cache;
        if (!descriptor.descriptor->Expand(i, provider, scripts_temp, out_keys, &cache)) return false;
        // Add all of the scriptPubKeys to the scriptPubKey set
        for (const CScript& script : scripts_temp) {
            m_map_script_pub_keys[script] = i;
        }
        // Write the cache
        if (!batch.WriteDescriptorCache(id, i, cache)) {
            throw std::runtime_error(std::string(__func__) + ": writing cache item failed");
        }
        descriptor.cache.push_back(std::move(cache));
    }
    descriptor.range_end += missing;
    batch.WriteDescriptor(GetID(), descriptor);
    return true;
}

void DescriptorScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
    LOCK(cs_desc_man);
    if (IsMine(script)) {
        int32_t index = m_map_script_pub_keys[script];
        if (index >= descriptor.next_index) {
            WalletLogPrintf("%s: Detected a used keypool item, mark all keypool items up to this item as used\n", __func__);
            descriptor.next_index = index + 1;
        }
        if (!TopUp()) {
            WalletLogPrintf("%s: Topping up keypool failed (locked wallet)\n", __func__);
        }
    }
}

void DescriptorScriptPubKeyMan::UpgradeKeyMetadata() {}

bool DescriptorScriptPubKeyMan::AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey)
{
    AssertLockHeld(cs_desc_man);
    assert(!IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    if (IsCrypted()) {
        if (IsLocked()) {
            return false;
        }

        std::vector<unsigned char> crypted_secret;
        CKeyingMaterial secret(key.begin(), key.end());
        if (!EncryptSecret(m_master_key, secret, pubkey.GetHash(), crypted_secret)) {
            return false;
        }

        m_map_crypted_keys[pubkey.GetID()] = make_pair(pubkey, crypted_secret);
        batch.WriteCryptedDescriptorKey(GetID(), pubkey, crypted_secret);
        return true;
    } else {
        m_map_keys[pubkey.GetID()] = key;
        return batch.WriteDescriptorKey(GetID(), pubkey, key.GetPrivKey());
    }
}

bool DescriptorScriptPubKeyMan::SetupGeneration(bool force)
{
    LOCK(cs_desc_man);
    assert(IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));

    // Ignore when there is already a descriptor
    if (descriptor.descriptor && !force) {
        return false;
    }

    int64_t creation_time = GetTime();

    // Make a seed
    CKey seed_key;
    seed_key.MakeNewKey(true);
    CPubKey seed = seed_key.GetPubKey();
    assert(seed_key.VerifyPubKey(seed));

    // Get the extended key
    CExtKey master_key;
    master_key.SetSeed(seed_key.begin(), seed_key.size());
    std::string xpub = EncodeExtPubKey(master_key.Neuter());
    CPubKey master_pubkey = master_key.key.GetPubKey();
    assert(master_key.key.VerifyPubKey(master_pubkey));

    // Add the seed to the wallet
    std::string internal_path = internal ? "1" : "0";
    std::string desc_str;
    switch (address_type) {
    case OutputType::LEGACY: {
        desc_str = "pkh(" + xpub + "/44'/" + internal_path + "'/*')";
        break;
    }
    case OutputType::P2SH_SEGWIT: {
        desc_str = "sh(wpkh(" + xpub + "/49'/" + internal_path + "'/*'))";
        break;
    }
    case OutputType::BECH32: {
        desc_str = "wpkh(" + xpub + "/84'/" + internal_path + "'/*')";
        break;
    }
    default: assert(false);
    }

    // Make the descriptor
    FlatSigningProvider keys;
    std::unique_ptr<Descriptor> desc = Parse(desc_str, keys, false);
    WalletDescriptor w_desc(std::move(desc), creation_time, 0, 0, 0);
    descriptor = w_desc;

    // Store the master private key and descriptor
    WalletBatch batch(*m_database);
    if (!AddDescriptorKeyWithDB(batch, master_key.key, master_key.key.GetPubKey())) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor private key failed");
    }
    if (!batch.WriteDescriptor(GetID(), descriptor)) {
        throw std::runtime_error(std::string(__func__) + ": writing descriptor failed");
    }

    // TopUp
    TopUp();

    UnsetWalletFlagWithDB(batch, WALLET_FLAG_BLANK_WALLET);
    return true;
}

bool DescriptorScriptPubKeyMan::IsHDEnabled() const
{
    return descriptor.descriptor->IsRange();
}

bool DescriptorScriptPubKeyMan::CanGetAddresses(bool internal)
{
    return HavePrivateKeys() || descriptor.next_index < descriptor.range_end;
}

bool DescriptorScriptPubKeyMan::Upgrade(int prev_version, int new_version)
{
    return false;
}

bool DescriptorScriptPubKeyMan::HavePrivateKeys() const
{
    LOCK(cs_desc_man);
    return m_map_keys.size() > 0 || m_map_crypted_keys.size() > 0;
}

void DescriptorScriptPubKeyMan::RewriteDB() {}

int64_t DescriptorScriptPubKeyMan::GetOldestKeyPoolTime()
{
    return GetTime();
}

size_t DescriptorScriptPubKeyMan::KeypoolCountExternalKeys()
{
    if (internal) {
        return 0;
    }
    return descriptor.range_end - descriptor.next_index;
}

unsigned int DescriptorScriptPubKeyMan::GetKeypoolSize() const
{
    return descriptor.range_end - descriptor.next_index;
}

int64_t DescriptorScriptPubKeyMan::GetTimeFirstKey() const
{
    return descriptor.creation_time;
}

std::unique_ptr<SigningProvider> DescriptorScriptPubKeyMan::GetSigningProvider(const CScript& script) const
{
    return nullptr;
}

bool DescriptorScriptPubKeyMan::CanProvide(const CScript& script, SignatureData& sigdata)
{
    return IsMine(script);
}

const CKeyMetadata* DescriptorScriptPubKeyMan::GetMetadata(uint160 id) const
{
    return nullptr;
}

uint256 DescriptorScriptPubKeyMan::GetID() const
{
    std::string desc_str = descriptor.descriptor->ToString();
    uint256 id;
    CSHA256().Write((unsigned char*)desc_str.data(), desc_str.size()).Finalize(id.begin());
    return id;
}

void DescriptorScriptPubKeyMan::SetType(OutputType type, bool internal)
{
    this->address_type = type;
    this->internal = internal;
}

void DescriptorScriptPubKeyMan::SetCache(std::vector<std::vector<unsigned char>> cache)
{
    LOCK(cs_desc_man);
    descriptor.cache = cache;
    for (int32_t i = descriptor.range_start; i < descriptor.range_end; ++i) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts_temp;
        descriptor.descriptor->ExpandFromCache(i, descriptor.cache[i - descriptor.range_start], scripts_temp, out_keys);
        // Add all of the scriptPubKeys to the scriptPubKey set
        for (const CScript& script : scripts_temp) {
            m_map_script_pub_keys[script] = i;
        }
    }
}

bool DescriptorScriptPubKeyMan::AddKey(const CKeyID& key_id, const CKey& key)
{
    LOCK(cs_desc_man);
    m_map_keys[key_id] = key;
    return true;
}

bool DescriptorScriptPubKeyMan::SetCrypted()
{
    LOCK(cs_desc_man);
    if (m_use_crypto)
        return true;
    if (!m_map_keys.empty())
        return false;
    m_use_crypto = true;
    return true;
}

bool DescriptorScriptPubKeyMan::AddCryptedKey(const CKeyID& key_id, const CPubKey& pubkey, const std::vector<unsigned char>& crypted_key)
{
    LOCK(cs_desc_man);
    if (!SetCrypted()) {
        return false;
    }

    m_map_crypted_keys[key_id] = make_pair(pubkey, crypted_key);
    return true;
}
