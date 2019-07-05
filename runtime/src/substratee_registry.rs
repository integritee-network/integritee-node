/*
	Copyright 2019 Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

use parity_codec::{Decode, Encode};
use rstd::prelude::*;
use rstd::str;
use support::{decl_event, decl_module,
              decl_storage, dispatch::Result, ensure, EnumerableStorageMap, StorageMap, StorageValue};
use system::ensure_signed;

use runtime_io::{verify_ra_report, print};

pub trait Trait: balances::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}


#[derive(Encode, Decode, Default, Copy, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Enclave<PubKey, Url> {
    pubkey: PubKey,
    // utf8 encoded url
    url: Url,
}

decl_event!(
	pub enum Event<T>
	where
		<T as system::Trait>::AccountId,
	{
		AddedEnclave(AccountId, Vec<u8>),
		RemovedEnclave(AccountId),
		UpdatedIPFSHash(Vec<u8>),
		Forwarded(AccountId, Vec<u8>),
		CallConfirmed(AccountId, Vec<u8>),
	}
);

decl_storage! {
	trait Store for Module<T: Trait> as substraTEERegistry {
	    // Simple lists are not supported in runtime modules as theoretically O(n)
	    // operations can be executed while only being charged O(1), see substrate
	    // Kitties tutorial Chapter 2, Tracking all Kitties.
        pub EnclaveRegistry get(enclave): linked_map u64 => Enclave<T::AccountId, Vec<u8>>;
	    pub EnclaveCount get(num_enclaves): u64;
	    pub EnclaveIndex: map T::AccountId => u64;
	    pub LatestIPFSHash get(ipfs_hash) : Vec<u8>;
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

 		fn deposit_event<T>() = default;

		// the substraTEE-worker wants to register his enclave
 		pub fn register_enclave(origin, ra_report: Vec<u8>, worker_url: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;

            verify_ra_report(&ra_report)?;
            Self::add_enclave(&sender, &worker_url)?;
            Self::deposit_event(RawEvent::AddedEnclave(sender, worker_url));
 			Ok(())
		}

		pub fn unregister_enclave(origin) -> Result {
		    let sender = ensure_signed(origin)?;

            Self::remove_enclave(&sender)?;
            Self::deposit_event(RawEvent::RemovedEnclave(sender));
            Ok(())
		}

		pub fn update_ipfs_hash(origin, hash: Vec<u8>) -> Result {
		    let sender = ensure_signed(origin)?;
		    ensure!(<EnclaveIndex<T>>::exists(sender),
		    "[SubstraTEERegistry]: IPFS state update requested by enclave that is not registered");

		    <LatestIPFSHash<T>>::put(hash.clone());
            Self::deposit_event(RawEvent::UpdatedIPFSHash(hash));
            Ok(())
		}

		pub fn call_worker(origin, payload: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;

 			Self::deposit_event(RawEvent::Forwarded(sender, payload));

 			Ok(())
		}

		// the substraTEE-worker calls this function for every processed call to confirm a state update
 		pub fn confirm_call(origin, payload: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;
			//FIXME: only enclave is allowed to call this. But we'll need an enclave registry first. right now, people have to manually check AccountID
 			Self::deposit_event(RawEvent::CallConfirmed(sender, payload));

 			Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
    fn add_enclave(sender: &T::AccountId, url: &[u8]) -> Result {
        if <EnclaveIndex<T>>::exists(sender) {
            print("Updating already registered enclave");
            return Self::update_enclave(sender, url)
        }
        let enclaves_count = Self::num_enclaves();
        let new_enclaves_count = enclaves_count.checked_add(1).
            ok_or("[SubstraTEERegistry]: Overflow adding new enclave to registry")?;

        let new_enclave = Enclave {
            pubkey: sender.clone(),
            url: url.to_vec(),
        };

        <EnclaveRegistry<T>>::insert(enclaves_count, &new_enclave);
        <EnclaveCount<T>>::put(new_enclaves_count);
        <EnclaveIndex<T>>::insert(sender, enclaves_count);

        Ok(())
    }

    fn remove_enclave(sender: &T::AccountId) -> Result {
        ensure!(<EnclaveIndex<T>>::exists(sender), "[SubstraTEERegistry]: Trying to remove an enclave that doesn't exist.");
        let index_to_remove = <EnclaveIndex<T>>::take(sender);

        let enclaves_count = Self::num_enclaves();
        let new_enclaves_count = enclaves_count.checked_sub(1).
            ok_or("[SubstraTEERegistry]: Underflow removing an enclave from the registry")?;

        Self::swap_and_pop(index_to_remove, new_enclaves_count)?;
        <EnclaveCount<T>>::put(new_enclaves_count);

        Ok(())
    }

    fn update_enclave(sender: &T::AccountId, url: &[u8]) -> Result {
        let key = <EnclaveIndex<T>>::get(sender);
        let mut enc = <EnclaveRegistry<T>>::get(key);
        enc.url = url.to_vec();
        <EnclaveRegistry<T>>::insert(key, enc);

        Ok(())
    }

    pub fn list_enclaves() -> Vec<(u64, Enclave<T::AccountId, Vec<u8>>)> {
        <EnclaveRegistry<T>>::enumerate().collect::<Vec<(u64, Enclave<T::AccountId, Vec<u8>>)>>()
    }


    /// Our list implementation would introduce holes in out list if if we try to remove elements from the middle.
    /// As the order of the enclave entries is not important, we use the swap an pop method to remove elements from
    /// the registry.
    fn swap_and_pop(index_to_remove: u64, new_enclaves_count: u64) -> Result {
        if index_to_remove != new_enclaves_count {
            let last_enclave = <EnclaveRegistry<T>>::get(&new_enclaves_count);
            <EnclaveRegistry<T>>::insert(index_to_remove, &last_enclave);
            <EnclaveIndex<T>>::insert(last_enclave.pubkey, index_to_remove);
        }

        <EnclaveRegistry<T>>::remove(new_enclaves_count);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use primitives::{Blake2Hasher, H256};
    use runtime_primitives::{
        BuildStorage, testing::{Digest, DigestItem, Header},
        traits::{BlakeTwo256, IdentityLookup}
    };
    use support::{assert_ok, impl_outer_origin};

    use runtime_io::{TestExternalities, with_externalities};

    use super::*;

    //    const WASM_CODE: &'static [u8] = include_bytes!("../wasm/target/wasm32-unknown-unknown/release/substratee_node_runtime_wasm.compact.wasm");
    const CERT: &[u8] = b"0\x82\x0c\x8c0\x82\x0c2\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r190617124609Z\x17\r190915124609Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04RT\x16\x16 \xef_\xd8\xe7\xc3\xb7\x03\x1d\xd6:\x1fF\xe3\xf2b!\xa9/\x8b\xd4\x82\x8f\xd1\xff[\x9c\x97\xbc\xf27\xb8,L\x8a\x01\xb0r;;\xa9\x83\xdc\x86\x9f\x1d%y\xf4;I\xe4Y\xc80'$K[\xd6\xa3\x82\x0bw0\x82\x0bs0\x82\x0bo\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0b`{\"id\":\"117077750682263877593646412006783680848\",\"timestamp\":\"2019-06-17T12:46:04.002066\",\"version\":3,\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000900000909020401800000000000000000000008000009000000020000000000000B401A355B313FC939B4F48A54349C914A32A3AE2C4871BFABF22E960C55635869FC66293A3D9B2D58ED96CA620B65D669A444C80291314EF691E896F664317CF80C\",\"isvEnclaveQuoteBody\":\"AgAAAEALAAAIAAcAAAAAAOE6wgoHKsZsnVWSrsWX9kky0kWt9K4xcan0fQ996Ct+CAj//wGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFJJYIbPVot9NzRCjW2z9+k+9K8BsHQKzVMEHOR14hNbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSVBYWIO9f2OfDtwMd1jofRuPyYiGpL4vUgo/R/1ucl7zyN7gsTIoBsHI7O6mD3IafHSV59DtJ5FnIMCckS1vW\"}|EbPFH/ThUaS/dMZoDKC5EgmdUXUORFtQzF49Umi1P55oeESreJaUvmA0sg/ATSTn5t2e+e6ZoBQIUbLHjcWLMLzK4pJJUeHhok7EfVgoQ378i+eGR9v7ICNDGX7a1rroOe0s1OKxwo/0hid2KWvtAUBvf1BDkqlHy025IOiXWhXFLkb/qQwUZDWzrV4dooMfX5hfqJPi1q9s18SsdLPmhrGBheh9keazeCR9hiLhRO9TbnVgR9zJk43SPXW+pHkbNigW+2STpVAi5ugWaSwBOdK11ZjaEU1paVIpxQnlW1D6dj1Zc3LibMH+ly9ZGrbYtuJks4eRnjPhroPXxlJWpQ==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\xae6\x06\t@Sy\x8f\x8ec\x9d\xdci^Ex*\x92}\xdcG\x15A\x97\xd7\xd7\xd1\xccx\xe0\x1e\x08\x02 \x15Q\xa0BT\xde'~\xec\xbd\x027\xd3\xd8\x83\xf7\xe6Z\xc5H\xb4D\xf7\xe2\r\xa7\xe4^f\x10\x85p";
    const URL: &[u8] = &[119, 115, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 57, 57, 57, 49];

    #[derive(Clone, Eq, PartialEq)]
    pub struct RegistryTest;

    impl_outer_origin! {
    pub enum Origin for RegistryTest {}
    }

    // Implement the system module traits
    impl system::Trait for RegistryTest {
        type Origin = Origin;
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type Digest = Digest;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type Log = DigestItem;
    }

    // Implement the balances module traits
    impl balances::Trait for RegistryTest {
        type Balance = u64;
        type OnFreeBalanceZero = ();
        type OnNewAccount = ();
        type TransactionPayment = ();
        type TransferPayment = ();
        type DustRemoval = ();
        type Event = ();
    }

    // Implement the trait for our own module, `super::Trait`
    impl super::Trait for RegistryTest { type Event = (); }

    // Easy access alias
    type Registry = super::Module<RegistryTest>;

//    Fixme:    Was not able to use these statics for the tests, always threw cannot move out of
//              dereference of raw pointer. As copy trait not implemented for whatever reason.
//    lazy_static! {
//        #[derive(Clone, Copy, Encode, Decode, Default, PartialEq)]
//        static ref ENC_1: Enclave<u64, Vec<u8>> = Enclave { pubkey: 10, url: URL.to_vec() };
//        #[derive(Encode, Decode, Default, Clone, Copy, PartialEq)]
//        static ref ENC_2: Enclave<u64, Vec<u8>> = Enclave { pubkey: 20, url: URL.to_vec() };
//        #[derive(Encode, Decode, Default, Clone, Copy, PartialEq)]
//        static ref ENC_3: Enclave<u64, Vec<u8>> = Enclave { pubkey: 30, url: URL.to_vec() };
//    }

    fn build_ext() -> TestExternalities<Blake2Hasher> {
        let mut t = system::GenesisConfig::<RegistryTest>::default().build_storage().unwrap().0;
        t.extend(balances::GenesisConfig::<RegistryTest>::default().build_storage().unwrap().0);
        // t.extend(GenesisConfig::<RegistryTest>::default().build_ext().unwrap().0);
        t.into()
    }

    #[test]
    fn add_enclave_works() {
        with_externalities(&mut build_ext(), || {
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec(), URL.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
        })
    }

    #[test]
    fn add_and_remove_enclave_works() {
        with_externalities(&mut build_ext(), || {
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec(), URL.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_ok!(Registry::unregister_enclave(Origin::signed(10)));
            assert_eq!(Registry::num_enclaves(), 0);
            assert_eq!(Registry::list_enclaves(), vec![])
        })
    }

    #[test]
    fn list_enclaves_works() {
        with_externalities(&mut build_ext(), || {
            let e_1: Enclave<u64, Vec<u8>> = Enclave { pubkey: 10, url: URL.to_vec() };
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec(), URL.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_eq!(Registry::list_enclaves(), vec![(0, e_1)])
        })
    }

    #[test]
    fn remove_middle_enclave_works() {
        with_externalities(&mut build_ext(), || {
            // add enclave 1
            let e_1: Enclave<u64, Vec<u8>> = Enclave { pubkey: 10, url: URL.to_vec() };
            let e_2: Enclave<u64, Vec<u8>> = Enclave { pubkey: 20, url: URL.to_vec() };
            let e_3: Enclave<u64, Vec<u8>> = Enclave { pubkey: 30, url: URL.to_vec() };

            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec(), URL.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_eq!(Registry::list_enclaves(), vec![(0, e_1.clone())]);

            // add enclave 2
            assert_ok!(Registry::register_enclave(Origin::signed(20), CERT.to_vec(), URL.to_vec()));
            assert_eq!(Registry::num_enclaves(), 2);
            assert_eq!(Registry::list_enclaves(), vec![(1, e_2.clone()), (0, e_1.clone())]);

            // add enclave 3
            assert_ok!(Registry::register_enclave(Origin::signed(30), CERT.to_vec(), URL.to_vec()));
            assert_eq!(Registry::num_enclaves(), 3);
            assert_eq!(Registry::list_enclaves(), vec![(2, e_3.clone()), (1, e_2.clone()), (0, e_1.clone())]);

            // remove enclave 2
            assert_ok!(Registry::unregister_enclave(Origin::signed(20)));
            assert_eq!(Registry::num_enclaves(), 2);
            assert_eq!(Registry::list_enclaves(), vec![(1, e_3.clone()), (0, e_1.clone())]);
        })
    }

    #[test]
    fn register_invalid_enclave_fails() {
        assert!(Registry::register_enclave(Origin::signed(10), Vec::new(), URL.to_vec()).is_err(), URL.to_vec());
    }

    #[test]
    fn update_enclave_url_works() {
        with_externalities(&mut build_ext(), || {
            let url2 = "my fancy url".as_bytes();
            let e_1: Enclave<u64, Vec<u8>> = Enclave { pubkey: 10, url: url2.to_vec() };

            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec(), URL.to_vec()));
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec(), url2.to_vec()));
            assert_eq!(Registry::enclave(0).url, url2.to_vec());
            assert_eq!(Registry::list_enclaves(), vec![(0, e_1)]);

        })
    }

    #[test]
    fn update_ipfs_hash_works() {
        with_externalities(&mut build_ext(), || {
            let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec(), URL.to_vec()));
            assert_ok!(Registry::update_ipfs_hash(Origin::signed(10), ipfs_hash.as_bytes().to_vec()));
            assert_eq!(str::from_utf8(&Registry::ipfs_hash()).unwrap(), ipfs_hash);
        })
    }

    #[test]
    fn ipfs_update_from_unregistered_enclave_fails() {
        with_externalities(&mut build_ext(), || {
            let ipfs_hash = "QmYY9U7sQzBYe79tVfiMyJ4prEJoJRWCD8t85j9qjssS9y";
            assert!(Registry::update_ipfs_hash(Origin::signed(10), ipfs_hash.as_bytes().to_vec()).is_err());
        })
    }
}

