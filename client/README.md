# encointer CLI client
Interact with the encointer chain from the command line

Includes
* keystore (incompatible with polkadot js app json)
* basic balancce transfer
* all encointer-specific calls

## examples
```
> encointer-client new_account
> encointer-client 127.0.0.1 transfer 5GpuFm6t1AU9xpTAnQnHXakTGA9rSHz8xNkEvx7RVQz2BVpd 5FkGDttiYa9ZoDAuNxzwEdLzkgt6ngWykSBhobGvoFUcUo8B 12345
> encointer-client 127.0.0.1:9979 register_participant 5FkGDttiYa9ZoDAuNxzwEdLzkgt6ngWykSBhobGvoFUcUo8B
> encointer-client 127.0.0.1:9979 list_participant_registry
> encointer-client 127.0.0.1:9979 get_phase
> encointer-client 127.0.0.1:9979 new_claim 5EqvwjCA8mH6x9gWbSmcQhxDkYHJcUfwjaHHn9q1hBrKLL65 3
> encointer-client 127.0.0.1:9979 sign_claim 5EqvwjCA8mH6x9gWbSmcQhxDkYHJcUfwjaHHn9q1hBrKLL65 7af690ced4cd1e84a857d047b4fc93f3b4801f9a94c9a4d568a01bc435f5bae903000000000000000000000003000000
```

Find a full ceremony cycle demo [here](./demo_poc1.sh)
