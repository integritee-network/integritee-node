#!/bin/bash
CLIENT="../target/release/encointer-client ws://127.0.0.1:9979 "

#./bootstrap_demo_currency.sh
cid=3LjCHdiNbNLKEtwGtBf6qHGZnfKFyjLu9v3uxVgDL35C

# generate and pre-fund accounts
account1=$($CLIENT new-account)
echo $account1
$CLIENT fund-account $account1

account2=$($CLIENT new-account)
echo $account2
$CLIENT fund-account $account2

account3=$($CLIENT new-account)
echo $account3
$CLIENT fund-account $account3

phase=$($CLIENT get-phase)
echo "phase is $phase"
if [ "$phase" == "REGISTERING" ]; then
   echo "that's fine"
elif [ "$phase" == "ASSIGNING" ]; then
   echo "need to advance"
   $CLIENT next-phase   
   $CLIENT next-phase
elif [ "$phase" == "ATTESTING" ]; then
   echo "need to advance"
   $CLIENT next-phase   
fi
phase=$($CLIENT get-phase)
echo "phase is now: $phase"

# master of ceremony fakes reputation
$CLIENT --cid $cid grant-reputation $account1
$CLIENT --cid $cid grant-reputation $account2
$CLIENT --cid $cid grant-reputation $account3

echo "*** registering new accounts for meetup"
# assuming we are in "REGISTERING" phase
$CLIENT --cid $cid register-participant $account1 --proof
$CLIENT --cid $cid register-participant $account2 --proof
$CLIENT --cid $cid register-participant $account3 --proof

# list registry
$CLIENT --cid $cid list-participant-registry

$CLIENT next-phase
# should now be ASSIGNING

$CLIENT --cid $cid list-meetup-registry

$CLIENT next-phase
# should now be WITNESSING

echo "*** start meetup"
claim1=$($CLIENT --cid $cid new-claim $account1 3)
claim2=$($CLIENT --cid $cid new-claim $account2 3)
claim3=$($CLIENT --cid $cid new-claim $account3 3)

echo "*** sign each others claims"
witness1_2=$($CLIENT sign-claim $account1 $claim2)
witness1_3=$($CLIENT sign-claim $account1 $claim3)

witness2_1=$($CLIENT sign-claim $account2 $claim1)
witness2_3=$($CLIENT sign-claim $account2 $claim3)

witness3_1=$($CLIENT sign-claim $account3 $claim1)
witness3_2=$($CLIENT sign-claim $account3 $claim2)

echo "*** send witnesses to chain"
$CLIENT register-attestations $account1 $witness2_1 $witness3_1
$CLIENT register-attestations $account2 $witness1_2 $witness3_2
$CLIENT register-attestations $account3 $witness1_3 $witness2_3

$CLIENT --cid $cid list-attestations-registry

echo "*** balances before reward round"
$CLIENT --cid $cid get-balance $account1
$CLIENT --cid $cid get-balance $account2
$CLIENT --cid $cid get-balance $account3
echo "*** move phase to issue rewards"
$CLIENT next-phase
# should now be REGISTERING
echo "*** balances after reward round"
$CLIENT --cid $cid get-balance $account1
$CLIENT --cid $cid get-balance $account2
$CLIENT --cid $cid get-balance $account3
