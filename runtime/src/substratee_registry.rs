use rstd::prelude::*;
use support::{decl_event, decl_module,
              decl_storage, dispatch::Result, ensure, EnumerableStorageMap, StorageMap, StorageValue};
use system::ensure_signed;

use runtime_io::verify_ra_report;

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

            verify_ra_report(&ra_report)?;
            Self::add_enclave(&sender)?;
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

        Self::swap_and_pop(index_to_remove, new_enclaves_count)?;
        <EnclaveCount<T>>::put(new_enclaves_count);

        Ok(())
    }

    pub fn list_enclaves() -> Vec<(u64, T::AccountId)> {
        <EnclaveRegistry<T>>::enumerate().collect::<Vec<(u64, T::AccountId)>>()
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
    use runtime_primitives::{
        BuildStorage, testing::{Digest, DigestItem, Header},
        traits::{BlakeTwo256, IdentityLookup}
    };
    use support::{assert_ok, impl_outer_origin};
    use runtime_io::{TestExternalities, verify_ra_report, with_externalities};
    use substrate_executor::{Externalities, WasmExecutor};

    use super::*;

    const WASM_CODE: &'static [u8] = include_bytes!("../wasm/target/wasm32-unknown-unknown/release/substratee_node_runtime_wasm.compact.wasm");
    const CERT: &[u8] = b"0\x82\x0c\x8c0\x82\x0c2\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0\x1e\x17\r190617124609Z\x17\r190915124609Z0\x121\x100\x0e\x06\x03U\x04\x03\x0c\x07MesaTEE0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04RT\x16\x16 \xef_\xd8\xe7\xc3\xb7\x03\x1d\xd6:\x1fF\xe3\xf2b!\xa9/\x8b\xd4\x82\x8f\xd1\xff[\x9c\x97\xbc\xf27\xb8,L\x8a\x01\xb0r;;\xa9\x83\xdc\x86\x9f\x1d%y\xf4;I\xe4Y\xc80'$K[\xd6\xa3\x82\x0bw0\x82\x0bs0\x82\x0bo\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0b`{\"id\":\"117077750682263877593646412006783680848\",\"timestamp\":\"2019-06-17T12:46:04.002066\",\"version\":3,\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"1502006504000900000909020401800000000000000000000008000009000000020000000000000B401A355B313FC939B4F48A54349C914A32A3AE2C4871BFABF22E960C55635869FC66293A3D9B2D58ED96CA620B65D669A444C80291314EF691E896F664317CF80C\",\"isvEnclaveQuoteBody\":\"AgAAAEALAAAIAAcAAAAAAOE6wgoHKsZsnVWSrsWX9kky0kWt9K4xcan0fQ996Ct+CAj//wGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAFJJYIbPVot9NzRCjW2z9+k+9K8BsHQKzVMEHOR14hNbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSVBYWIO9f2OfDtwMd1jofRuPyYiGpL4vUgo/R/1ucl7zyN7gsTIoBsHI7O6mD3IafHSV59DtJ5FnIMCckS1vW\"}|EbPFH/ThUaS/dMZoDKC5EgmdUXUORFtQzF49Umi1P55oeESreJaUvmA0sg/ATSTn5t2e+e6ZoBQIUbLHjcWLMLzK4pJJUeHhok7EfVgoQ378i+eGR9v7ICNDGX7a1rroOe0s1OKxwo/0hid2KWvtAUBvf1BDkqlHy025IOiXWhXFLkb/qQwUZDWzrV4dooMfX5hfqJPi1q9s18SsdLPmhrGBheh9keazeCR9hiLhRO9TbnVgR9zJk43SPXW+pHkbNigW+2STpVAi5ugWaSwBOdK11ZjaEU1paVIpxQnlW1D6dj1Zc3LibMH+ly9ZGrbYtuJks4eRnjPhroPXxlJWpQ==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\xae6\x06\t@Sy\x8f\x8ec\x9d\xdci^Ex*\x92}\xdcG\x15A\x97\xd7\xd7\xd1\xccx\xe0\x1e\x08\x02 \x15Q\xa0BT\xde'~\xec\xbd\x027\xd3\xd8\x83\xf7\xe6Z\xc5H\xb4D\xf7\xe2\r\xa7\xe4^f\x10\x85p";

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
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
        })
    }

    #[test]
    fn should_add_and_remove_enclave() {
        with_externalities(&mut build_ext(), || {
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_ok!(Registry::unregister_enclave(Origin::signed(10)));
            assert_eq!(Registry::num_enclaves(), 0);
            assert_eq!(Registry::list_enclaves(), vec![])
        })
    }

    #[test]
    fn should_list_enclaves() {
        with_externalities(&mut build_ext(), || {
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_eq!(Registry::list_enclaves(), vec![(0, 10)])
        })
    }

    #[test]
    fn remove_middle_enclave() {
        with_externalities(&mut build_ext(), || {
            // add enclave 1
            assert_ok!(Registry::register_enclave(Origin::signed(10), CERT.to_vec()));
            assert_eq!(Registry::num_enclaves(), 1);
            assert_eq!(Registry::list_enclaves(), vec![(0, 10)]);

            // add enclave 2
            assert_ok!(Registry::register_enclave(Origin::signed(20), CERT.to_vec()));
            assert_eq!(Registry::num_enclaves(), 2);
            assert_eq!(Registry::list_enclaves(), vec![(1, 20), (0, 10)]);

            // add enclave 3
            assert_ok!(Registry::register_enclave(Origin::signed(30), CERT.to_vec()));
            assert_eq!(Registry::num_enclaves(), 3);
            assert_eq!(Registry::list_enclaves(), vec![(2, 30), (1, 20), (0, 10)]);

            // remove enclave 2
            assert_ok!(Registry::unregister_enclave(Origin::signed(20)));
            assert_eq!(Registry::num_enclaves(), 2);
            assert_eq!(Registry::list_enclaves(), vec![(1, 30), (0, 10)]);
        })
    }

    #[test]
    fn register_invalid_enclave_should_fail() {
        assert!(Registry::register_enclave(Origin::signed(10), Vec::new()).is_err());
    }

//    #[test]
//    fn register_enclave_works_wasm() {
//        let mut msg = "Helloworld".as_bytes().to_vec();
//        WasmExecutor::new().call(&mut build_ext(), 8, &WASM_CODE,
//                                 "runtime_io::verify_ra_report", &msg).unwrap();
//            assert_ok!(Registry::register_enclave(Origin::signed(10), Vec::new()));
//        assert_eq!(Registry::num_enclaves(), 1);
//    }
}

