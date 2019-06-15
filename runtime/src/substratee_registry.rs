use rstd::prelude::*;
use support::{decl_event, decl_module,
              decl_storage, dispatch::Result, StorageMap, StorageValue};
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
	}
);


decl_storage! {
	trait Store for Module<T: Trait> as substraTEERegistry {
	    EnclaveRegistry get(enclave): map u64 => T::AccountId;
	    EnclaveCount get(num_enclaves): u64;
	    EnclaveIndex: map T::AccountId => u64
	}
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

 		fn deposit_event<T>() = default;

		// the substraTEE-worker wants to register his enclave
 		pub fn register_enclave(origin, _ra_report: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;

			// Fixme: Check enclave report

            if let Err(x) = Self::add_enclave(&sender) {
                return Err(x);
            }
            Self::deposit_event(RawEvent::AddedEnclave(sender));

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
}

