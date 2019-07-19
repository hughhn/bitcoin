#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test descriptor wallet function."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error
)


class WalletDescriptorTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [['-keypool=100']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        # Make a descriptor wallet
        self.log.info("Making a descriptor wallet")
        self.nodes[0].createwallet(wallet_name="desc1", descriptors=True)
        self.nodes[0].unloadwallet("")

        # A descriptor wallet should have 100 addresses * 3 types = 300 keys
        self.log.info("Checking wallet info")
        wallet_info = self.nodes[0].getwalletinfo()
        assert_equal(wallet_info['keypoolsize'], 300)
        assert_equal(wallet_info['keypoolsize_hd_internal'], 300)

        # Check that getnewaddress works
        self.log.info("Test that getnewaddress and getrawchangeaddress work")
        addr = self.nodes[0].getnewaddress("", "legacy")
        addr_info = self.nodes[0].getaddressinfo(addr)
        assert_equal(addr_info['hdkeypath'], 'm/44\'/0\'/0\'')

        addr = self.nodes[0].getnewaddress("", "p2sh-segwit")
        addr_info = self.nodes[0].getaddressinfo(addr)
        assert_equal(addr_info['hdkeypath'], 'm/49\'/0\'/0\'')

        addr = self.nodes[0].getnewaddress("", "bech32")
        addr_info = self.nodes[0].getaddressinfo(addr)
        assert_equal(addr_info['hdkeypath'], 'm/84\'/0\'/0\'')

        # Check that getrawchangeaddress works
        addr = self.nodes[0].getrawchangeaddress("legacy")
        addr_info = self.nodes[0].getaddressinfo(addr)
        assert_equal(addr_info['hdkeypath'], 'm/44\'/1\'/0\'')

        addr = self.nodes[0].getrawchangeaddress("p2sh-segwit")
        addr_info = self.nodes[0].getaddressinfo(addr)
        assert_equal(addr_info['hdkeypath'], 'm/49\'/1\'/0\'')

        addr = self.nodes[0].getrawchangeaddress("bech32")
        addr_info = self.nodes[0].getaddressinfo(addr)
        assert_equal(addr_info['hdkeypath'], 'm/84\'/1\'/0\'')

        # Make a wallet to receive coins at
        self.nodes[0].createwallet(wallet_name="desc2", descriptors=True)
        recv_wrpc = self.nodes[0].get_wallet_rpc("desc2")
        send_wrpc = self.nodes[0].get_wallet_rpc("desc1")

        # Generate some coins
        send_wrpc.generatetoaddress(101, send_wrpc.getnewaddress())

        # Make transactions
        self.log.info("Test sending and receiving")
        addr = recv_wrpc.getnewaddress()
        send_wrpc.sendtoaddress(addr, 10)

        # Make sure things are disabled
        self.log.info("Test disabled RPCs")
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.importprivkey, "cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW")
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.importpubkey, send_wrpc.getaddressinfo(send_wrpc.getnewaddress()))
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.importaddress, recv_wrpc.getnewaddress())
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.importmulti, [])
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.addmultisigaddress, 1, [recv_wrpc.getnewaddress()])
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.dumpprivkey, recv_wrpc.getnewaddress())
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.dumpwallet, 'wallet.dump')
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.importwallet, 'wallet.dump')
        assert_raises_rpc_error(-4, "This type of wallet does not support this command", recv_wrpc.sethdseed)

        self.log.info("Test encryption")
        # Get the master fingerprint before encrypt
        info1 = send_wrpc.getaddressinfo(send_wrpc.getnewaddress())

        # Encrypt wallet 0
        send_wrpc.encryptwallet('pass')
        send_wrpc.walletpassphrase('pass', 10)
        info2 = send_wrpc.getaddressinfo(send_wrpc.getnewaddress())
        assert info1['hdmasterfingerprint'] != info2['hdmasterfingerprint']
        send_wrpc.walletlock()
        assert 'hdmasterfingerprint' in send_wrpc.getaddressinfo(send_wrpc.getnewaddress())

        self.log.info("Test born encrypted wallets")
        self.nodes[0].createwallet('desc_enc', False, False, 'pass', False, True)
        enc_rpc = self.nodes[0].get_wallet_rpc('desc_enc')
        enc_rpc.getnewaddress() # Makes sure that we can get a new address from a born encrypted wallet

        self.log.info("Test blank descriptor wallets")
        self.nodes[0].createwallet(wallet_name='desc_blank', blank=True, descriptors=True)
        blank_rpc = self.nodes[0].get_wallet_rpc('desc_blank')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', blank_rpc.getnewaddress)

        self.log.info("Test descriptor wallet with disabled private keys")
        self.nodes[0].createwallet(wallet_name='desc_no_priv', disable_private_keys=True, descriptors=True)
        nopriv_rpc = self.nodes[0].get_wallet_rpc('desc_no_priv')
        assert_raises_rpc_error(-4, 'This wallet has no available keys', nopriv_rpc.getnewaddress)

if __name__ == '__main__':
    WalletDescriptorTest().main ()
