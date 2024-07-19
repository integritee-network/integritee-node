
//! Autogenerated weights for `pallet_teeracle`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 39.0.0
//! DATE: 2024-07-19, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `caribe`, CPU: `12th Gen Intel(R) Core(TM) i7-1260P`
//! WASM-EXECUTION: `Compiled`, CHAIN: `Some("integritee-solo-fresh")`, DB CACHE: 1024

// Executed Command:
// target/release/integritee-node
// benchmark
// pallet
// --chain=integritee-solo-fresh
// --steps=50
// --repeat=20
// --pallet=pallet_teeracle
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=runtime/src/weights/pallet_teeracle.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_teeracle`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_teeracle::WeightInfo for WeightInfo<T> {
	/// Storage: `Teerex::SovereignEnclaves` (r:1 w:0)
	/// Proof: `Teerex::SovereignEnclaves` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::Whitelists` (r:1 w:0)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::ExchangeRates` (r:1 w:1)
	/// Proof: `Teeracle::ExchangeRates` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn update_exchange_rate() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `454`
		//  Estimated: `3919`
		// Minimum execution time: 44_730_000 picoseconds.
		Weight::from_parts(49_230_000, 0)
			.saturating_add(Weight::from_parts(0, 3919))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Teerex::SovereignEnclaves` (r:1 w:0)
	/// Proof: `Teerex::SovereignEnclaves` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::Whitelists` (r:1 w:0)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	/// Storage: `Teeracle::OracleData` (r:0 w:1)
	/// Proof: `Teeracle::OracleData` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn update_oracle() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `445`
		//  Estimated: `3910`
		// Minimum execution time: 37_526_000 picoseconds.
		Weight::from_parts(41_294_000, 0)
			.saturating_add(Weight::from_parts(0, 3910))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Teeracle::Whitelists` (r:1 w:1)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn add_to_whitelist() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `6`
		//  Estimated: `3471`
		// Minimum execution time: 17_640_000 picoseconds.
		Weight::from_parts(19_529_000, 0)
			.saturating_add(Weight::from_parts(0, 3471))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: `Teeracle::Whitelists` (r:1 w:1)
	/// Proof: `Teeracle::Whitelists` (`max_values`: None, `max_size`: None, mode: `Measured`)
	fn remove_from_whitelist() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `107`
		//  Estimated: `3572`
		// Minimum execution time: 20_741_000 picoseconds.
		Weight::from_parts(21_866_000, 0)
			.saturating_add(Weight::from_parts(0, 3572))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
