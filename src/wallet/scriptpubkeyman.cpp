// Copyright (c) 2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/scriptpubkeyman.h>

bool LegacyScriptPubKeyMan::GetNewDestination(const OutputType type, CTxDestination& dest, std::string& error)
{
    return false;
}

isminetype LegacyScriptPubKeyMan::IsMine(const CScript& script) const
{
    return ISMINE_NO;
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
    return false;
}

bool LegacyScriptPubKeyMan::Unlock(const CKeyingMaterial& vMasterKeyIn, bool accept_no_keys)
{
    return false;
}

bool LegacyScriptPubKeyMan::Encrypt(CKeyingMaterial& vMasterKeyIn, WalletBatch* batch)
{
    return false;
}

bool LegacyScriptPubKeyMan::GetReservedDestination(const OutputType type, bool internal, CTxDestination& address, int64_t& index, CKeyPool& keypool)
{
    return false;
}

void LegacyScriptPubKeyMan::KeepDestination(int64_t index)
{
}

void LegacyScriptPubKeyMan::ReturnDestination(int64_t index, bool internal, const CTxDestination& addr)
{
}

bool LegacyScriptPubKeyMan::TopUp(unsigned int size)
{
    return false;
}

void LegacyScriptPubKeyMan::MarkUnusedAddresses(const CScript& script)
{
}

void LegacyScriptPubKeyMan::UpgradeKeyMetadata()
{
}

bool LegacyScriptPubKeyMan::SetupGeneration(bool force)
{
    return false;
}

bool LegacyScriptPubKeyMan::IsHDEnabled() const
{
    return false;
}

bool LegacyScriptPubKeyMan::CanGetAddresses(bool internal)
{
    return false;
}

bool LegacyScriptPubKeyMan::Upgrade(int prev_version, int new_version)
{
    return false;
}

bool LegacyScriptPubKeyMan::HavePrivateKeys() const
{
    return false;
}

void LegacyScriptPubKeyMan::RewriteDB()
{
}

int64_t LegacyScriptPubKeyMan::GetOldestKeyPoolTime()
{
    return GetTime();
}

size_t LegacyScriptPubKeyMan::KeypoolCountExternalKeys()
{
    return 0;
}

unsigned int LegacyScriptPubKeyMan::GetKeypoolSize() const
{
    return 0;
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
    return false;
}

const CKeyMetadata* LegacyScriptPubKeyMan::GetMetadata(uint160 id) const
{
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
