#!/usr/bin/env python3
# Copyright (c) 2017-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""That coin selection does sane things under various multi-asset scenarios

## Exmalpe Test destripotn

Test that the nodes generate the correct change address type:
    - node0 always uses a legacy change address.
    - node1 uses a bech32 addresses for change if any destination address is bech32.
    - node2 always uses a bech32 address for change
    - node3 always uses a bech32 address for change
    - node4 always uses p2sh/segwit output for change.
"""

from decimal import Decimal
import random

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
)

class WalletCtTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def generate_dest_addrs(self, n_explicit, n_blinded):
        dest_addrs = \
            [ self.nodes[0].getnewaddress() for x in range(n_blinded) ] \
            + [ self.nodes[0].validateaddress(self.nodes[0].getnewaddress())["unconfidential"] for x in range(n_explicit) ]
        random.shuffle(dest_addrs)
        return dest_addrs

    def check_tx(self, txid, n_outputs):
        data = self.nodes[0].getrawtransaction(txid, 1)
        assert_equal(len(data['vout']), n_outputs)
        assert_equal(len(data['fee']), 1)
        feerate = 1000 * data['fee'][self.nodes[0].dumpassetlabels()['bitcoin']] / data['vsize']
        # FIXME assert something here
        print(feerate)
        print(data['fee'][self.nodes[0].dumpassetlabels()['bitcoin']])

    def run_test(self):
        # Mine 101 blocks to get the initial coins out of IBD
        self.nodes[0].generate(COINBASE_MATURITY + 1)
        self.nodes[0].syncwithvalidationinterfacequeue()

        self.log.info(f"Starting with balance {self.nodes[0].getbalance()}")
        # Burn all but 0.25 coin, which we split into 250 explicit outputs, with the
        # goal of noticing disparities between our fee estimate during coin selection
        # and the actual needed fee. (If we left all the money in one big output,
        # coin selection could be wildly wrong and the tx would still be okay, since
        # the final step in tx construction is to compute the actual required fee and
        # subtract this from the change output. To notice errors we want to start
        # with as small a change output as possible.)
        dest_addrs = self.generate_dest_addrs(250, 0)
        tx_hex = self.nodes[0].createrawtransaction(outputs = [{"burn": self.nodes[0].getbalance()['bitcoin'] - Decimal(0.25) }] \
            + [{ dest_addr: 0.001} for dest_addr in dest_addrs ])
        tx_hex = self.nodes[0].fundrawtransaction(hexstring=tx_hex, options={"subtract_fee_from_outputs": [i for i in range(len(dest_addrs))]})['hex']
        tx_hex = self.nodes[0].signrawtransactionwithwallet(tx_hex)['hex']
        self.nodes[0].sendrawtransaction(tx_hex)

        # Create a big pile of distinct assets
        self.log.info("Funding wallet with several assets")
        explicit_issuances = [ self.nodes[0].issueasset(10000, 100, False) for i in range(10) ]
        blind_issuances = [ self.nodes[0].issueasset(10000, 100, True) for i in range(10) ]
        # Check that listissuances return all issuances
        self.nodes[0].generate(2)
        issuances = self.nodes[0].listissuances()
        assert_equal(len(issuances), len(explicit_issuances) + len(blind_issuances))

        # Try to send all explicit assets to self, in full
        self.log.info("Sending all explicit assets to self")
        dest_addrs = self.generate_dest_addrs(len(explicit_issuances), 0)
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 10000 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, explicit_issuances) },
        )
        self.check_tx(txid, len(explicit_issuances) + 2)
        dest_addrs = self.generate_dest_addrs(0, len(explicit_issuances))
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 10000 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, explicit_issuances) },
        )
        self.check_tx(txid, len(explicit_issuances) + 2)
        dest_addrs = self.generate_dest_addrs(len(explicit_issuances), 0)
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 10000 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, explicit_issuances) },
        )
        self.check_tx(txid, len(explicit_issuances) + 2)
        self.nodes[0].generate(2)

        # Try to send all confidential assets to self
        self.log.info("Sending all confidential assets to self")
        dest_addrs = self.generate_dest_addrs(0, len(blind_issuances))
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 10000 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, blind_issuances) },
        )
        self.check_tx(txid, len(blind_issuances) + 2)
        dest_addrs = self.generate_dest_addrs(len(blind_issuances), 0)
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 10000 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, blind_issuances) },
        )
        self.check_tx(txid, len(blind_issuances) + 2)
        dest_addrs = self.generate_dest_addrs(0, len(blind_issuances))
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 10000 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, blind_issuances) },
        )
        self.check_tx(txid, len(blind_issuances) + 2)
        self.nodes[0].generate(2)

        # Send 1 unit of everything to self, forcing change on every output (mixed confidential/explicit outputs)
        self.log.info("Creating many change outputs")
        all_issuances = blind_issuances + explicit_issuances
        random.shuffle(all_issuances)
        dest_addrs = self.generate_dest_addrs(len(explicit_issuances), len(blind_issuances))
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 1 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, all_issuances) },
        )
        self.check_tx(txid, 2 * len(all_issuances) + 2)
        self.nodes[0].generate(2)

        # Send many units of everything to self, forcing "1 satoshi" change on every output (all explicit outputs)
        all_issuances = blind_issuances + explicit_issuances
        random.shuffle(all_issuances)
        dest_addrs = self.generate_dest_addrs(len(explicit_issuances) + len(blind_issuances), 0)
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 9999.99999999 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, all_issuances) },
        )
        self.check_tx(txid, 2 * len(all_issuances) + 2)
        self.nodes[0].generate(2)

        # Reconsolidate everything
        all_issuances = blind_issuances + explicit_issuances
        random.shuffle(all_issuances)
        dest_addrs = self.generate_dest_addrs(len(explicit_issuances), len(blind_issuances))
        txid = self.nodes[0].sendmany(
            dummy="",
            amounts={ dest_addr: 10000 for dest_addr in dest_addrs },
            output_assets={ dest_addr: dest_asset["asset"] for dest_addr, dest_asset in zip(dest_addrs, all_issuances) },
        )
        self.check_tx(txid, len(all_issuances) + 2)
        self.nodes[0].generate(2)

if __name__ == '__main__':
    WalletCtTest().main()

