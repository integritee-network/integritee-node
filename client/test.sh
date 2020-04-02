#!/bin/bash
CLIENT="../target/release/encointer-client 127.0.0.1:9979 "

# generate and pre-fund accounts
account1=$($CLIENT new_account)
echo $account1
$CLIENT fund_account $account1

account2=$($CLIENT new_account)
echo $account2
$CLIENT fund_account $account2

account3=$($CLIENT new_account)
echo $account3
$CLIENT fund_account $account3

phase=$($CLIENT get_phase)
echo $phase
if ["$phase" == "REGISTERING\n"]; then
   echo "phase is REGISTERING"
fi

# assuming we are in "REGISTERING" phase
$CLIENT register_participant $account1
$CLIENT register_participant $account2
$CLIENT register_participant $account3

# list registry
$CLIENT list_participant_registry

$CLIENT next_phase

$CLIENT list_meetup_registry


