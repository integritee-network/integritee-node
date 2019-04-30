use rstd::prelude::*;

use support::{decl_storage, decl_module, StorageValue,
	dispatch::Result, decl_event};
use system::ensure_signed;

 pub trait Trait: balances::Trait {
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}

 decl_event!(
	pub enum Event<T>
	where
		<T as system::Trait>::AccountId,
	{
		CounterUpdated(AccountId),
		Forwarded(AccountId, Vec<u8>),
	}
);

 decl_storage! {
	trait Store for Module<T: Trait> as substraTEEProxyStorage {

 		/// Get the counter of all transfers
		AllCount get(all_count): u64;
	}
}

 decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {

 		fn deposit_event<T>() = default;

 		fn update_counter(origin) -> Result {
			let sender = ensure_signed(origin)?;

 			let all_count = Self::all_count();
			let new_all_count = all_count.checked_add(1).ok_or("Overflow by adding 1")?;

 			<AllCount<T>>::put(new_all_count);

 			Self::deposit_event(RawEvent::CounterUpdated(sender));

 			Ok(())
		}

 		fn forward(origin, payload: Vec<u8>) -> Result {
			let sender = ensure_signed(origin)?;

 			Self::deposit_event(RawEvent::Forwarded(sender, payload));

 			Ok(())
		}
	}
}