use rstd::prelude::*;
use support::{decl_event, decl_module,
              decl_storage, dispatch::Result, ensure, EnumerableStorageMap, StorageMap, StorageValue};
use system::ensure_signed;

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


decl_storage! {
	trait Store for Module<T: Trait> as substraTEERegistry {
	    // Simple lists are not supported in runtime modules as theoretically O(n)
	    // operations can be executed while only being charged O(1), see substrate
	    // Kitties tutorial Chapter 2, Tracking all Kitties.
	    EnclaveRegistry get(enclave): linked_map u64 => T::AccountId;
	    EnclaveCount get(num_enclaves): u64;
	    EnclaveIndex: map T::AccountId => u64
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

 		fn deposit_event<T>() = default;

		// the substraTEE-worker wants to register his enclave
 		pub fn register_enclave(origin, ra_report: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;

            // Fixme: Check enclave report
            Self::verify_ra_report(ra_report);

            if let Err(x) = Self::add_enclave(&sender) {
                return Err(x);
            }
            Self::deposit_event(RawEvent::AddedEnclave(sender));

 			Ok(())
		}

		pub fn unregister_enclave(origin) -> Result {
		    let sender = ensure_signed(origin)?;

            if let Err(x) = Self::remove_enclave(&sender) {
                return Err(x);
            }

            Self::deposit_event(RawEvent::RemovedEnclave(sender));

            Ok(())
		}
	}
}

impl<T: Trait> Module<T> {
    fn add_enclave(sender: &T::AccountId) -> Result {
        let enclaves_count = Self::num_enclaves();
        let new_enclaves_count = enclaves_count.checked_add(1).
            ok_or("[SubstraTEERegistry]: Overflow adding new enclave to registry")?;


        <EnclaveRegistry<T>>::insert(enclaves_count, sender);
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

        if let Err(x) = Self::swap_and_pop(index_to_remove, new_enclaves_count) {
            return Err(x);
        }

        <EnclaveCount<T>>::put(new_enclaves_count);

        Ok(())
    }

    pub fn list_enclaves() -> Vec<(u64, T::AccountId)> {
        <EnclaveRegistry<T>>::enumerate().collect::<Vec<(u64, T::AccountId)>>()
    }

    fn verify_ra_report(report: Vec<u8>) -> Result {
        // Todo: Fill body
        Ok(())
    }


    /// Our list implementation would introduce holes in out list if if we try to remove elements from the middle.
    /// As the order of the enclave entries is not important, we use the swap an pop method to remove elements from
    /// the registry.
    fn swap_and_pop(index_to_remove: u64, new_enclaves_count: u64) -> Result {
        if index_to_remove != new_enclaves_count {
            let last_enclave = <EnclaveRegistry<T>>::get(&new_enclaves_count);
            <EnclaveRegistry<T>>::insert(index_to_remove, &last_enclave);
            <EnclaveIndex<T>>::insert(&last_enclave, index_to_remove);
        }

        <EnclaveRegistry<T>>::remove(new_enclaves_count);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use primitives::{Blake2Hasher, H256};
    use runtime_io::{TestExternalities, with_externalities};
    use runtime_primitives::{
        BuildStorage, testing::{Digest, DigestItem, Header},
        traits::{BlakeTwo256, IdentityLookup}
    };
    use support::{assert_ok, impl_outer_origin};

    use super::*;

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

    fn build_ext() -> TestExternalities<Blake2Hasher> {
        let mut t = system::GenesisConfig::<RegistryTest>::default().build_storage().unwrap().0;
        t.extend(balances::GenesisConfig::<RegistryTest>::default().build_storage().unwrap().0);
        // t.extend(GenesisConfig::<RegistryTest>::default().build_ext().unwrap().0);
        t.into()
    }

    #[test]
    fn should_add_enclave() {
        with_externalities(&mut build_ext(), || {
            assert_ok!(Registry::register_enclave(Origin::signed(10), Vec::new()));
            assert_eq!(Registry::num_enclaves(), 1);
        })
    }

    #[test]
    fn should_add_and_remove_enclave() {
        with_externalities(&mut build_ext(), || {
            assert_ok!(Registry::register_enclave(Origin::signed(10), Vec::new()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_ok!(Registry::unregister_enclave(Origin::signed(10)));
            assert_eq!(Registry::num_enclaves(), 0);
            assert_eq!(Registry::list_enclaves(), vec![])
        })
    }

    #[test]
    fn should_list_enclaves() {
        with_externalities(&mut build_ext(), || {
            assert_ok!(Registry::register_enclave(Origin::signed(10), Vec::new()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_eq!(Registry::list_enclaves(), vec![(0, 10)])
        })
    }

    #[test]
    fn remove_middle_enclave() {
        with_externalities(&mut build_ext(), || {
            // add enclave 1
            assert_ok!(Registry::register_enclave(Origin::signed(10), Vec::new()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_eq!(Registry::list_enclaves(), vec![(0, 10)]);

            // add enclave 2
            assert_ok!(Registry::register_enclave(Origin::signed(20), Vec::new()));
            assert_eq!(Registry::num_enclaves(), 2);
            assert_eq!(Registry::list_enclaves(), vec![(1, 20), (0, 10)]);

            // add enclave 3
            assert_ok!(Registry::register_enclave(Origin::signed(30), Vec::new()));
            assert_eq!(Registry::num_enclaves(), 3);
            assert_eq!(Registry::list_enclaves(), vec![(2, 30), (1, 20), (0, 10)]);

            // remove enclave 2
            assert_ok!(Registry::unregister_enclave(Origin::signed(20)));
            assert_eq!(Registry::num_enclaves(), 2);
            assert_eq!(Registry::list_enclaves(), vec![(1, 30), (0, 10)]);
        })
    }
}

