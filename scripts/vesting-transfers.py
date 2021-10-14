#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Sep 16 20:41:13 2021

@author: brenzi
"""

from substrateinterface import SubstrateInterface, Keypair
from substrateinterface.utils.ss58 import ss58_encode

def get_balance(who):
    return substrate.query('System', 'Account', params=[who]).value['data']['free']
def float_balance(val):
    return float(val) / pow(10.0,12.0)

substrate = SubstrateInterface(
        url="wss://api.solo.integritee.io:443",
        type_registry_preset='kusama'
    )
treasury = ss58_encode('0x' + b'modlpy/trsry'.hex() + '0000000000000000000000000000000000000000', ss58_format=13)

anonproxy = '2KF2YRZbMVmDTCEhw5Bjz7Na5dG7fCCtUcd9KccUBaRngUW9'
#beneficiary = '2PaWxAa4RKMY2HrHwy4aAWF1KiGbv7haDasF34PwZLaMvBvb'
beneficiary='2PuNvnHydtgtS4Adpmj4NGn6qsGd3xJmsEdEhn1gjABcpLYo'

print(f"treasury {treasury} balance is {float_balance(get_balance(treasury))}")
print(f"anon proxy {anonproxy} balance is {float_balance(get_balance(anonproxy))}")

signer = Keypair.create_from_uri('//SomeTemporaryCustodian', ss58_format=13)
print(f"temporary account: {signer.ss58_address}")


block_number_now = substrate.get_block_number(substrate.get_chain_head())
print(f"current block number: {block_number_now}")

call = substrate.compose_call(
    call_module='Vesting',
    call_function='vested_transfer',
    call_params={
        'target': beneficiary,
        'schedule' : {
                'locked':  1000000000000,
                'per_block': 10000000000,
                'starting_block': block_number_now + 10
        }
    }
)

extrinsic = substrate.create_signed_extrinsic(
    call=call,
    keypair=signer,
    era={'period': 64}
)
receipt = substrate.submit_extrinsic(extrinsic, wait_for_inclusion=True)
print('extrinsic sent')
print(f"beneficiary balance: {float_balance(get_balance(beneficiary))}")
