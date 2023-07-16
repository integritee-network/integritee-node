
//! Autogenerated weights for `pallet_sidechain`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-07-14, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `caribe`, CPU: `12th Gen Intel(R) Core(TM) i7-1260P`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("integritee-solo-fresh"), DB CACHE: 1024

// Executed Command:
// target/release/integritee-node
// benchmark
// pallet
// --chain=integritee-solo-fresh
// --steps=50
// --repeat=20
// --pallet=pallet_sidechain
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=runtime/src/weights/pallet_sidechain.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weight functions for `pallet_sidechain`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_sidechain::WeightInfo for WeightInfo<T> {
	/// Storage: Teerex SovereignEnclaves (r:1 w:0)
	/// Proof Skipped: Teerex SovereignEnclaves (max_values: None, max_size: None, mode: Measured)
	/// Storage: EnclaveBridge ShardConfigRegistry (r:1 w:0)
	/// Proof Skipped: EnclaveBridge ShardConfigRegistry (max_values: None, max_size: None, mode: Measured)
	/// Storage: EnclaveBridge ShardStatus (r:1 w:1)
	/// Proof Skipped: EnclaveBridge ShardStatus (max_values: None, max_size: None, mode: Measured)
	/// Storage: Sidechain SidechainBlockFinalizationCandidate (r:1 w:1)
	/// Proof Skipped: Sidechain SidechainBlockFinalizationCandidate (max_values: None, max_size: None, mode: Measured)
	/// Storage: Sidechain LatestSidechainBlockConfirmation (r:0 w:1)
	/// Proof Skipped: Sidechain LatestSidechainBlockConfirmation (max_values: None, max_size: None, mode: Measured)
	fn confirm_imported_sidechain_block() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `354`
		//  Estimated: `3819`
		// Minimum execution time: 23_043_000 picoseconds.
		Weight::from_parts(23_511_000, 0)
			.saturating_add(Weight::from_parts(0, 3819))
			.saturating_add(T::DbWeight::get().reads(4))
			.saturating_add(T::DbWeight::get().writes(3))
	}
}
