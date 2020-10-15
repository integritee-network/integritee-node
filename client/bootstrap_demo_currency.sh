#!/bin/bash
CLIENT="../target/release/encointer-client-notee"

# register new currency
echo "registering demo currency with cid:"
cid=$($CLIENT new-currency test-locations-mediterranean.json //Alice)
echo $cid

# list currenies
$CLIENT list-currencies

# bootstrap currency with well-known keys
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

account1=//Alice
account2=//Bob
account3=//Charlie

# charlie has no genesis funds
$CLIENT faucet $account3

# await next block
$CLIENT listen -b 1

$CLIENT --cid $cid register-participant $account1
$CLIENT --cid $cid register-participant $account2
$CLIENT --cid $cid register-participant $account3

# await next block
$CLIENT listen -b 1

# list registry
$CLIENT --cid $cid list-participants

$CLIENT next-phase
# should now be ASSIGNING

$CLIENT --cid $cid list-meetups

$CLIENT next-phase
# should now be ATTESTING

echo "*** start meetup"
claim1=$($CLIENT --cid $cid new-claim $account1 3)
echo "claim for $account1 is $claim1"
claim2=$($CLIENT --cid $cid new-claim $account2 3)
claim3=$($CLIENT --cid $cid new-claim $account3 3)

echo "*** sign each others claims"
witness1_2=$($CLIENT sign-claim $account1 $claim2)
witness1_3=$($CLIENT sign-claim $account1 $claim3)

witness2_1=$($CLIENT sign-claim $account2 $claim1)
echo "attestation for $account1 by $account2 is $witness2_1"
witness2_3=$($CLIENT sign-claim $account2 $claim3)

witness3_1=$($CLIENT sign-claim $account3 $claim1)
witness3_2=$($CLIENT sign-claim $account3 $claim2)

echo "*** send witnesses to chain"
$CLIENT register-attestations $account1 $witness2_1 $witness3_1
$CLIENT register-attestations $account2 $witness1_2 $witness3_2
$CLIENT register-attestations $account3 $witness1_3 $witness2_3

# await next block
$CLIENT listen -b 1

$CLIENT --cid $cid list-attestations

$CLIENT next-phase
# should now be REGISTERING

echo "account balances for new currency with cid $cid"
$CLIENT --cid $cid balance //Alice
$CLIENT --cid $cid balance //Bob
$CLIENT --cid $cid balance //Charlie