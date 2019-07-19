// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
#define BITCOIN_WALLET_SCRIPTPUBKEYMAN_H

#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <script/standard.h>
#include <wallet/crypter.h>
#include <wallet/ismine.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>

#include <functional>

#include <boost/signals2/signal.hpp>

enum class OutputType;

//! Default for -keypool
static const unsigned int DEFAULT_KEYPOOL_SIZE = 1000;

std::vector<CKeyID> GetAffectedKeys(const CScript& spk, const SigningProvider& provider);

/** A key from a CWallet's keypool
 *
 * The wallet holds one (for pre HD-split wallets) or several keypools. These
 * are sets of keys that have not yet been used to provide addresses or receive
 * change.
 *
 * The Bitcoin Core wallet was originally a collection of unrelated private
 * keys with their associated addresses. If a non-HD wallet generated a
 * key/address, gave that address out and then restored a backup from before
 * that key's generation, then any funds sent to that address would be
 * lost definitively.
 *
 * The keypool was implemented to avoid this scenario (commit: 10384941). The
 * wallet would generate a set of keys (100 by default). When a new public key
 * was required, either to give out as an address or to use in a change output,
 * it would be drawn from the keypool. The keypool would then be topped up to
 * maintain 100 keys. This ensured that as long as the wallet hadn't used more
 * than 100 keys since the previous backup, all funds would be safe, since a
 * restored wallet would be able to scan for all owned addresses.
 *
 * A keypool also allowed encrypted wallets to give out addresses without
 * having to be decrypted to generate a new private key.
 *
 * With the introduction of HD wallets (commit: f1902510), the keypool
 * essentially became an address look-ahead pool. Restoring old backups can no
 * longer definitively lose funds as long as the addresses used were from the
 * wallet's HD seed (since all private keys can be rederived from the seed).
 * However, if many addresses were used since the backup, then the wallet may
 * not know how far ahead in the HD chain to look for its addresses. The
 * keypool is used to implement a 'gap limit'. The keypool maintains a set of
 * keys (by default 1000) ahead of the last used key and scans for the
 * addresses of those keys.  This avoids the risk of not seeing transactions
 * involving the wallet's addresses, or of re-using the same address.
 *
 * The HD-split wallet feature added a second keypool (commit: 02592f4c). There
 * is an external keypool (for addresses to hand out) and an internal keypool
 * (for change addresses).
 *
 * Keypool keys are stored in the wallet/keystore's keymap. The keypool data is
 * stored as sets of indexes in the wallet (setInternalKeyPool,
 * setExternalKeyPool and set_pre_split_keypool), and a map from the key to the
 * index (m_pool_key_to_index). The CKeyPool object is used to
 * serialize/deserialize the pool data to/from the database.
 */
class CKeyPool
{
public:
    //! The time at which the key was generated. Set in AddKeypoolPubKeyWithDB
    int64_t nTime;
    //! The public key
    CPubKey vchPubKey;
    //! Whether this keypool entry is in the internal keypool (for change outputs)
    bool fInternal;
    //! Whether this key was generated for a keypool before the wallet was upgraded to HD-split
    bool m_pre_split;

    CKeyPool();
    CKeyPool(const CPubKey& vchPubKeyIn, bool internalIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
        if (ser_action.ForRead()) {
            try {
                READWRITE(fInternal);
            }
            catch (std::ios_base::failure&) {
                /* flag as external address if we can't read the internal boolean
                   (this will be the case for any wallet before the HD chain split version) */
                fInternal = false;
            }
            try {
                READWRITE(m_pre_split);
            }
            catch (std::ios_base::failure&) {
                /* flag as postsplit address if we can't read the m_pre_split boolean
                   (this will be the case for any wallet that upgrades to HD chain split)*/
                m_pre_split = false;
            }
        }
        else {
            READWRITE(fInternal);
            READWRITE(m_pre_split);
        }
    }
};

typedef std::function<void(uint64_t)> FlagFunc;
typedef std::function<void(WalletBatch&, uint64_t)> FlagFuncWithDB;
typedef std::function<bool(uint64_t)> FlagSetFunc;
typedef std::function<bool(enum WalletFeature)> VersionFunc;
typedef std::function<std::string()> NameFunc;
typedef std::function<void(enum WalletFeature, WalletBatch*, bool)> SetVersionFunc;

class ScriptPubKeyMan
{
protected:
    FlagSetFunc IsWalletFlagSet; // Function pointer to function that determines if a wallet flag is set
    FlagFunc SetWalletFlag; // Function pointer to function to set wallet flags
    FlagFuncWithDB UnsetWalletFlagWithDB; // Function pointer to function to unset wallet flags
    VersionFunc CanSupportFeature; // Function pointer to function that indicates whether the feature is supported
    NameFunc GetDisplayName; // Function pointer to GetDisplayName to get the name of a wallet for WalletLogPrintf
    SetVersionFunc SetMinVersion; // Function pointer to SetMinVersion in the wallet

    /** Internal database handle. */
    std::shared_ptr<WalletDatabase> m_database;

public:
    ScriptPubKeyMan(FlagSetFunc is_set_func, FlagFunc set_flag_func, FlagFuncWithDB unset_flag_func, VersionFunc feature_sup_func, NameFunc wallet_name_func, SetVersionFunc set_version_func, std::shared_ptr<WalletDatabase> database)
        :   IsWalletFlagSet(is_set_func),
            SetWalletFlag(set_flag_func),
            UnsetWalletFlagWithDB(unset_flag_func),
            CanSupportFeature(feature_sup_func),
            GetDisplayName(wallet_name_func),
            SetMinVersion(set_version_func),
            m_database(database)
        {}

    virtual ~ScriptPubKeyMan() {};
    virtual bool GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error) { return false; }
    virtual isminetype IsMine(const CScript& script) const { return ISMINE_NO; }

    virtual bool IsCrypted() const { return false; }
    virtual bool IsLocked() const { return false; }
    virtual bool Lock() { return false; }

    virtual bool Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys = false) { return false; }
    virtual bool Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch) { return false; }

    virtual bool GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool) { return false; }
    virtual void KeepDestination(int64_t index) {}
    virtual void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) {}

    virtual bool TopUp(unsigned int size = 0) { return false; }

    //! Mark unused addresses as being used
    virtual void MarkUnusedAddresses(const CScript& script) {}

    //! Upgrade stored CKeyMetadata objects to store key origin info as KeyOriginInfo
    virtual void UpgradeKeyMetadata() {}

    /** Sets up the key generation stuff.
      * Returns false if already setup or setup fails, true if setup is successful
      * Set force=true to make it re-setup if already setup, used for upgrades
      */
    virtual bool SetupGeneration(bool force = false) { return false; }

    /* Returns true if HD is enabled */
    virtual bool IsHDEnabled() const { return false; }

    /* Returns true if the wallet can give out new addresses. This means it has keys in the keypool or can generate new keys */
    virtual bool CanGetAddresses(bool internal = false) { return false; }

    /** Upgrades the wallet to the specified version */
    virtual bool Upgrade(int prev_version, int new_version) { return false; }

    virtual bool HavePrivateKeys() const { return false; }

    //! The action to do when the DB needs rewrite
    virtual void RewriteDB() {}

    virtual int64_t GetOldestKeyPoolTime() { return GetTime(); }

    virtual size_t KeypoolCountExternalKeys() { return 0; }
    virtual unsigned int GetKeypoolSize() const { return 0; }

    virtual int64_t GetTimeFirstKey() const { return 0; }

    virtual const CKeyMetadata* GetMetadata(uint160 id) const { return nullptr; }

    virtual std::unique_ptr<SigningProvider> GetSigningProvider(const CScript& script) const { return nullptr; }
    virtual bool CanProvide(const CScript& script, SignatureData& sigdata) { return false; }

    virtual uint256 GetID() const { return uint256(); }

    virtual void SetType(OutputType type, bool internal) {}

    /** Prepends the wallet name in logging output to ease debugging in multi-wallet use cases */
    template<typename... Params>
    void WalletLogPrintf(std::string fmt, Params... parameters) const {
        LogPrintf(("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    };

    /** Watch-only address added */
    boost::signals2::signal<void (bool fHaveWatchOnly)> NotifyWatchonlyChanged;

    /** Keypool has new keys */
    boost::signals2::signal<void ()> NotifyCanGetAddressesChanged;

    virtual bool HasWalletDescriptor(const WalletDescriptor& desc) const { return false; }
};

class LegacyScriptPubKeyMan : public ScriptPubKeyMan, public FillableSigningProvider
{
private:
    //! if fUseCrypto is true, mapKeys must be empty
    //! if fUseCrypto is false, vMasterKey must be empty
    std::atomic<bool> fUseCrypto;

    bool SetCrypted();

    //! keeps track of whether Unlock has run a thorough check before
    bool fDecryptionThoroughlyChecked;

    CKeyingMaterial vMasterKey GUARDED_BY(cs_KeyStore);
    using WatchOnlySet = std::set<CScript>;
    using WatchKeyMap = std::map<CKeyID, CPubKey>;

    WalletBatch *encrypted_batch GUARDED_BY(cs_KeyStore) = nullptr;

    using CryptedKeyMap = std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char>>>;

    CryptedKeyMap mapCryptedKeys GUARDED_BY(cs_KeyStore);
    WatchOnlySet setWatchOnly GUARDED_BY(cs_KeyStore);
    WatchKeyMap mapWatchKeys GUARDED_BY(cs_KeyStore);

    int64_t nTimeFirstKey GUARDED_BY(cs_KeyStore) = 0;

    bool AddKeyPubKeyInner(const CKey& key, const CPubKey &pubkey);
    bool AddCryptedKeyInner(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);

    /**
     * Private version of AddWatchOnly method which does not accept a
     * timestamp, and which will reset the wallet's nTimeFirstKey value to 1 if
     * the watch key did not previously have a timestamp associated with it.
     * Because this is an inherited virtual method, it is accessible despite
     * being marked private, but it is marked private anyway to encourage use
     * of the other AddWatchOnly which accepts a timestamp and sets
     * nTimeFirstKey more intelligently for more efficient rescans.
     */
    bool AddWatchOnly(const CScript& dest) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    bool AddWatchOnlyWithDB(WalletBatch &batch, const CScript& dest) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    bool AddWatchOnlyInMem(const CScript &dest);
    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnlyWithDB(WalletBatch &batch, const CScript& dest, int64_t create_time) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKeyWithDB(WalletBatch &batch,const CKey& key, const CPubKey &pubkey) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    void AddKeypoolPubkeyWithDB(const CPubKey& pubkey, const bool internal, WalletBatch& batch);

    //! Adds a script to the store and saves it to disk
    bool AddCScriptWithDB(WalletBatch& batch, const CScript& script);

    /** Add a KeyOriginInfo to the wallet */
    bool AddKeyOriginWithDB(WalletBatch& batch, const CPubKey& pubkey, const KeyOriginInfo& info);

    /* the HD chain data model (external chain counters) */
    CHDChain hdChain;

    /* HD derive new child key (on internal or external chain) */
    void DeriveNewChildKey(WalletBatch& batch, CKeyMetadata& metadata, CKey& secret, bool internal = false) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    std::set<int64_t> setInternalKeyPool GUARDED_BY(cs_KeyStore);
    std::set<int64_t> setExternalKeyPool GUARDED_BY(cs_KeyStore);
    std::set<int64_t> set_pre_split_keypool GUARDED_BY(cs_KeyStore);
    int64_t m_max_keypool_index GUARDED_BY(cs_KeyStore) = 0;
    std::map<CKeyID, int64_t> m_pool_key_to_index;
    std::map<int64_t, CKeyID> m_reserved_key_to_index;

    //! Fetches a key from the keypool
    bool GetKeyFromPool(CPubKey &key, bool internal = false);

    /**
     * Reserves a key from the keypool and sets nIndex to its index
     *
     * @param[out] nIndex the index of the key in keypool
     * @param[out] keypool the keypool the key was drawn from, which could be the
     *     the pre-split pool if present, or the internal or external pool
     * @param fRequestedInternal true if the caller would like the key drawn
     *     from the internal keypool, false if external is preferred
     *
     * @return true if succeeded, false if failed due to empty keypool
     * @throws std::runtime_error if keypool read failed, key was invalid,
     *     was not found in the wallet, or was misclassified in the internal
     *     or external keypool
     */
    bool ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fRequestedInternal);

    void KeepKey(int64_t nIndex);
    void ReturnKey(int64_t nIndex, bool fInternal, const CKeyID& pubkey_id);

public:
    LegacyScriptPubKeyMan(FlagSetFunc is_set_func, FlagFunc set_flag_func, FlagFuncWithDB unset_flag_func, VersionFunc feature_sup_func, NameFunc wallet_name_func, SetVersionFunc set_version_func, std::shared_ptr<WalletDatabase> database)
        :   ScriptPubKeyMan(is_set_func, set_flag_func, unset_flag_func, feature_sup_func, wallet_name_func, set_version_func, database),
            fUseCrypto(false),
            fDecryptionThoroughlyChecked(false)
        {}

    bool GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error) override EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    isminetype IsMine(const CScript& script) const override;

    bool IsCrypted() const override;
    bool IsLocked() const override;
    bool Lock() override;

    bool Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys = false) override;
    bool Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch) override;

    bool GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool) override;
    void KeepDestination(int64_t index) override;
    void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) override;

    bool TopUp(unsigned int size = 0) override;

    void MarkUnusedAddresses(const CScript& script) override;

    void UpgradeKeyMetadata() override;

    bool IsHDEnabled() const override;

    bool SetupGeneration(bool force = false) override;

    bool Upgrade(int prev_version, int new_version) override;

    bool HavePrivateKeys() const override;

    void RewriteDB() override;

    int64_t GetOldestKeyPoolTime() override;
    size_t KeypoolCountExternalKeys() override;
    unsigned int GetKeypoolSize() const override;

    int64_t GetTimeFirstKey() const override;

    const CKeyMetadata* GetMetadata(uint160 id) const override;

    bool CanGetAddresses(bool internal = false) override;

    std::unique_ptr<SigningProvider> GetSigningProvider(const CScript& script) const override;

    bool CanProvide(const CScript& script, SignatureData& sigdata) override;

    uint256 GetID() const override;

    void SetType(OutputType type, bool internal) override;

    // Map from Key ID to key metadata.
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata GUARDED_BY(cs_KeyStore);

    // Map from Script ID to key metadata (for watch-only keys).
    std::map<CScriptID, CKeyMetadata> m_script_metadata GUARDED_BY(cs_KeyStore);

    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey &pubkey) override EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey& key, const CPubKey &pubkey);
    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    void UpdateTimeFirstKey(int64_t nCreateTime) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    //! Adds a CScript to the store
    bool LoadCScript(const CScript& redeemScript);
    //! Load metadata (used by LoadWallet)
    void LoadKeyMetadata(const CKeyID& keyID, const CKeyMetadata &metadata);
    void LoadScriptMetadata(const CScriptID& script_id, const CKeyMetadata &metadata);
    //! Generate a new key
    CPubKey GenerateNewKey(WalletBatch& batch, bool internal = false) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    /* Set the HD chain model (chain child index counters) */
    void SetHDChain(const CHDChain& chain, bool memonly);
    const CHDChain& GetHDChain() const { return hdChain; }

    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)
    bool LoadWatchOnly(const CScript &dest);
    //! Returns whether the watch-only script is in the wallet
    bool HaveWatchOnly(const CScript &dest) const;
    //! Returns whether there are any watch-only things in the wallet
    bool HaveWatchOnly() const;
    //! Remove a watch only script from the keystore
    bool RemoveWatchOnly(const CScript &dest);
    bool AddWatchOnly(const CScript& dest, int64_t nCreateTime) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    //! Fetches a pubkey from mapWatchKeys if it exists there
    bool GetWatchPubKey(const CKeyID &address, CPubKey &pubkey_out) const;

    /* SigningProvider overrides */
    bool HaveKey(const CKeyID &address) const override;
    bool GetKey(const CKeyID &address, CKey& keyOut) const override;
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const override;
    bool AddCScript(const CScript& redeemScript) override;
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override;

    //! Load a keypool entry
    void LoadKeyPool(int64_t nIndex, const CKeyPool &keypool);
    bool TopUpKeyPool(unsigned int kpSize = 0);
    bool NewKeyPool();
    void MarkPreSplitKeys() EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    bool ImportScripts(const std::set<CScript> scripts, int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    bool ImportPrivKeys(const std::map<CKeyID, CKey>& privkey_map, const int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    bool ImportPubKeys(const std::vector<CKeyID>& ordered_pubkeys, const std::map<CKeyID, CPubKey>& pubkey_map, const std::map<CKeyID, std::pair<CPubKey, KeyOriginInfo>>& key_origins, const bool add_keypool, const bool internal, const int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    bool ImportScriptPubKeys(const std::set<CScript>& script_pub_keys, const bool have_solving_data, const int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);

    /* Returns true if the wallet can generate new keys */
    bool CanGenerateKeys();

    /* Generates a new HD seed (will not be activated) */
    CPubKey GenerateNewSeed();

    /* Derives a new HD seed (will not be activated) */
    CPubKey DeriveNewSeed(const CKey& key);

    /* Set the current HD seed (will reset the chain child index counters)
       Sets the seed's version based on the current wallet version (so the
       caller must ensure the current wallet version is correct before calling
       this function). */
    void SetHDSeed(const CPubKey& key);

    /**
     * Explicitly make the wallet learn the related scripts for outputs to the
     * given key. This is purely to make the wallet file compatible with older
     * software, as FillableSigningProvider automatically does this implicitly for all
     * keys now.
     */
    void LearnRelatedScripts(const CPubKey& key, OutputType);

    /**
     * Same as LearnRelatedScripts, but when the OutputType is not known (and could
     * be anything).
     */
    void LearnAllRelatedScripts(const CPubKey& key);

    /**
     * Marks all keys in the keypool up to and including reserve_key as used.
     */
    void MarkReserveKeysAsUsed(int64_t keypool_id) EXCLUSIVE_LOCKS_REQUIRED(cs_KeyStore);
    const std::map<CKeyID, int64_t>& GetAllReserveKeys() const { return m_pool_key_to_index; }
};

/** Wraps a LegacyScriptPubKeyMan so that it can be returned in a new unique_ptr */
class LegacySigningProvider : public SigningProvider
{
private:
    const LegacyScriptPubKeyMan* spk_man;
public:
    LegacySigningProvider(const LegacyScriptPubKeyMan* spk_man) : spk_man(spk_man) {}

    bool GetCScript(const CScriptID &scriptid, CScript& script) const override { return spk_man->GetCScript(scriptid, script); }
    bool HaveCScript(const CScriptID &scriptid) const override { return spk_man->HaveCScript(scriptid); }
    bool GetPubKey(const CKeyID &address, CPubKey& pubkey) const override { return spk_man->GetPubKey(address, pubkey); }
    bool GetKey(const CKeyID &address, CKey& key) const override { return spk_man->GetKey(address, key); }
    bool HaveKey(const CKeyID &address) const override { return spk_man->HaveKey(address); }
    bool GetKeyOrigin(const CKeyID& keyid, KeyOriginInfo& info) const override { return spk_man->GetKeyOrigin(keyid, info); }
};

class DescriptorScriptPubKeyMan : public ScriptPubKeyMan
{
private:
    mutable CCriticalSection cs_desc_man;

    WalletDescriptor descriptor;

    using ScriptPubKeyMap = std::map<CScript, int32_t>; // Map of scripts to descriptor range index
    using CryptedKeyMap = std::map<CKeyID, std::pair<CPubKey, std::vector<unsigned char>>>;
    using KeyMap = std::map<CKeyID, CKey>;

    ScriptPubKeyMap m_map_script_pub_keys GUARDED_BY(cs_desc_man);

    OutputType address_type;
    bool internal;

    KeyMap m_map_keys GUARDED_BY(cs_desc_man);
    CryptedKeyMap m_map_crypted_keys GUARDED_BY(cs_desc_man);

    //! if m_use_crypto is true, m_map_keys must be empty
    //! if m_use_crypto is false, m_master_key must be empty
    std::atomic<bool> m_use_crypto;

    bool SetCrypted();

    //! keeps track of whether Unlock has run a thorough check before
    bool m_decryption_thoroughly_checked;

    CKeyingMaterial m_master_key GUARDED_BY(cs_desc_man);

    bool AddDescriptorKeyWithDB(WalletBatch& batch, const CKey& key, const CPubKey &pubkey);

    KeyMap GetKeys() const EXCLUSIVE_LOCKS_REQUIRED(cs_desc_man);
public:
    DescriptorScriptPubKeyMan(FlagSetFunc is_set_func, FlagFunc set_flag_func, FlagFuncWithDB unset_flag_func, VersionFunc feature_sup_func, NameFunc wallet_name_func, SetVersionFunc set_version_func, std::shared_ptr<WalletDatabase> database, WalletDescriptor& descriptor)
        :   ScriptPubKeyMan(is_set_func, set_flag_func, unset_flag_func, feature_sup_func, wallet_name_func, set_version_func, database),
            descriptor(descriptor),
            m_use_crypto(false), m_decryption_thoroughly_checked(false)
        {}
    DescriptorScriptPubKeyMan(FlagSetFunc is_set_func, FlagFunc set_flag_func, FlagFuncWithDB unset_flag_func, VersionFunc feature_sup_func, NameFunc wallet_name_func, SetVersionFunc set_version_func, std::shared_ptr<WalletDatabase> database, OutputType address_type, bool internal)
        :   ScriptPubKeyMan(is_set_func, set_flag_func, unset_flag_func, feature_sup_func, wallet_name_func, set_version_func, database),
            address_type(address_type), internal(internal),
            m_use_crypto(false), m_decryption_thoroughly_checked(false)
        {}

    bool GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error) override;
    isminetype IsMine(const CScript& script) const override;

    bool IsCrypted() const override;
    bool IsLocked() const override;
    bool Lock() override;

    bool Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys = false) override;
    bool Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch) override;

    bool GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool) override;
    void KeepDestination(int64_t index) override;
    void ReturnDestination(int64_t index, bool internal, const CTxDestination& addr) override;

    bool TopUp(unsigned int size = 0) override;

    void MarkUnusedAddresses(const CScript& script) override;

    void UpgradeKeyMetadata() override;

    bool IsHDEnabled() const override;

    bool SetupGeneration(bool force = false) override;

    bool Upgrade(int prev_version, int new_version) override;

    bool HavePrivateKeys() const override;

    void RewriteDB() override;

    int64_t GetOldestKeyPoolTime() override;
    size_t KeypoolCountExternalKeys() override;
    unsigned int GetKeypoolSize() const override;

    int64_t GetTimeFirstKey() const override;

    const CKeyMetadata* GetMetadata(uint160 id) const override;

    bool CanGetAddresses(bool internal = false) override;

    std::unique_ptr<SigningProvider> GetSigningProvider(const CScript& script) const override;

    bool CanProvide(const CScript& script, SignatureData& sigdata) override;

    uint256 GetID() const override;

    void SetType(OutputType type, bool internal) override;

    bool HasWalletDescriptor(const WalletDescriptor& desc) const override;

    void SetCache(std::vector<std::vector<unsigned char>> cache);

    bool AddKey(const CKeyID& key_id, const CKey& key);
    bool AddCryptedKey(const CKeyID& key_id, const CPubKey& pubkey, const std::vector<unsigned char>& crypted_key);

    void AddDescriptorKeyWithDB(const CKey& key, const CPubKey &pubkey);
    void WriteDescriptor();

    const std::vector<CScript> GetScriptPubKeys() const;
};

#endif // BITCOIN_WALLET_SCRIPTPUBKEYMAN_H
