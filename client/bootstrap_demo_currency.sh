#!/bin/bash
CLIENT="../target/release/encointer-client 127.0.0.1:9979 "

# register new currency
cid=$($CLIENT new_currency test-locations-mediterranean.json //Alice)
echo $cid

# list currenies
$CLIENT list_currencies

# bootstrap currency with well-known keys
phase=$($CLIENT get_phase)
echo "phase is $phase"
if [ "$phase" == "REGISTERING" ]; then
   echo "that's fine"
elif [ "$phase" == "ASSIGNING" ]; then
   echo "need to advance"
   $CLIENT next_phase   
   $CLIENT next_phase
elif [ "$phase" == "ATTESTING" ]; then
   echo "need to advance"
   $CLIENT next_phase   
fi
phase=$($CLIENT get_phase)
echo "phase is now: $phase"

account1=//Alice
account2=//Bob
account3=//Charlie

# charlie has no genesis funds
$CLIENT fund_account $account3

$CLIENT --cid $cid register_participant $account1
$CLIENT --cid $cid register_participant $account2
$CLIENT --cid $cid register_participant $account3

# list registry
$CLIENT --cid $cid list_participant_registry

$CLIENT next_phase
# should now be ASSIGNING

$CLIENT --cid $cid list_meetup_registry

$CLIENT next_phase
# should now be ATTESTING

echo "*** start meetup"
claim1=$($CLIENT --cid $cid new_claim $account1 3)
claim2=$($CLIENT --cid $cid new_claim $account2 3)
claim3=$($CLIENT --cid $cid new_claim $account3 3)

echo "*** sign each others claims"
witness1_2=$($CLIENT sign_claim $account1 $claim2)
witness1_3=$($CLIENT sign_claim $account1 $claim3)

witness2_1=$($CLIENT sign_claim $account2 $claim1)
witness2_3=$($CLIENT sign_claim $account2 $claim3)

witness3_1=$($CLIENT sign_claim $account3 $claim1)
witness3_2=$($CLIENT sign_claim $account3 $claim2)

echo "*** send witnesses to chain"
$CLIENT register_attestations $account1 $witness2_1 $witness3_1
$CLIENT register_attestations $account2 $witness1_2 $witness3_2
$CLIENT register_attestations $account3 $witness1_3 $witness2_3

$CLIENT --cid $cid list_attestations_registry

$CLIENT next_phase
# should now be REGISTERING

echo "account balances for new currency with cid $cid"
$CLIENT --cid $cid get_balance //Alice
$CLIENT --cid $cid get_balance //Bob
$CLIENT --cid $cid get_balance //Charlie