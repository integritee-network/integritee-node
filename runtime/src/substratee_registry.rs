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
use parity_codec::{Encode, Decode};

pub trait Trait: balances::Trait {
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}


decl_event!(
	pub enum Event<T>
	where
		<T as system::Trait>::AccountId,
	{
		AddedEnclave(AccountId),
		RemovedEnclave(AccountId),
	}
);

#[derive(Encode, Decode, Default, Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Enclave <PubKey, Url> {
    pubkey: PubKey,
    // utf8 encoded url
    url: Url,
}

decl_storage! {
	trait Store for Module<T: Trait> as substraTEERegistry {
	    // Simple lists are not supported in runtime modules as theoretically O(n)
	    // operations can be executed while only being charged O(1), see substrate
	    // Kitties tutorial Chapter 2, Tracking all Kitties.
        EnclaveRegistry get(enclave): linked_map u64 => Enclave<T::AccountId, Vec<u8>>;
	    EnclaveCount get(num_enclaves): u64;
	    EnclaveIndex: map T::AccountId => u64
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
            Self::deposit_event(RawEvent::AddedEnclave(sender));
 			Ok(())
		}

		pub fn unregister_enclave(origin) -> Result {
		    let sender = ensure_signed(origin)?;

            Self::remove_enclave(&sender)?;
            Self::deposit_event(RawEvent::RemovedEnclave(sender));
            Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
    fn add_enclave(sender: &T::AccountId, url: &[u8]) -> Result {
        let enclaves_count = Self::num_enclaves();
        let new_enclaves_count = enclaves_count.checked_add(1).
            ok_or("[SubstraTEERegistry]: Overflow adding new enclave to registry")?;

        let new_enclave = Enclave {
            pubkey: sender.clone(),
            url:url.to_vec(),
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

//    pub fn list_enclaves() -> Vec<(u64, T::AccountId)> {
//        <EnclaveRegistry<T>>::enumerate().collect::<Vec<(u64, T::AccountId)>>()
//    }


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

