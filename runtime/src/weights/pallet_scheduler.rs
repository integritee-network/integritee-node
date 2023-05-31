
//! Autogenerated weights for `pallet_scheduler`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2021-11-11, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("integritee-solo-fresh"), DB CACHE: 128

// Executed Command:
// ./integritee-node
// benchmark
// --chain=integritee-solo-fresh
// --steps=50
// --repeat=20
// --pallet=pallet_scheduler
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=runtime/src/weights/pallet_scheduler.rs


#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for pallet_scheduler.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_scheduler::WeightInfo for WeightInfo<T> {
	// Storage: Scheduler IncompleteSince (r:1 w:1)
	fn service_agendas_base() -> Weight {
		// Minimum execution time: 6_333 nanoseconds.
		Weight::from_ref_time(6_580_000 as u64)
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	// Storage: Scheduler Agenda (r:1 w:1)
	/// The range of component `s` is `[0, 50]`.
	fn service_agenda_base(s: u32, ) -> Weight {
		// Minimum execution time: 5_254 nanoseconds.
		Weight::from_ref_time(10_657_333 as u64)
			// Standard Error: 4_756
			.saturating_add(Weight::from_ref_time(928_347 as u64).saturating_mul(s as u64))
			.saturating_add(T::DbWeight::get().reads(1 as u64))
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	fn service_task_base() -> Weight {
		// Minimum execution time: 14_150 nanoseconds.
		Weight::from_ref_time(14_461_000 as u64)
	}
	// Storage: Preimage PreimageFor (r:1 w:1)
	// Storage: Preimage StatusFor (r:1 w:1)
	/// The range of component `s` is `[128, 4194304]`.
	fn service_task_fetched(s: u32, ) -> Weight {
		// Minimum execution time: 33_756 nanoseconds.
		Weight::from_ref_time(34_314_000 as u64)
			// Standard Error: 13
			.saturating_add(Weight::from_ref_time(2_268 as u64).saturating_mul(s as u64))
			.saturating_add(T::DbWeight::get().reads(2 as u64))
			.saturating_add(T::DbWeight::get().writes(2 as u64))
	}
	// Storage: Scheduler Lookup (r:0 w:1)
	fn service_task_named() -> Weight {
		// Minimum execution time: 16_531 nanoseconds.
		Weight::from_ref_time(16_865_000 as u64)
			.saturating_add(T::DbWeight::get().writes(1 as u64))
	}
	fn service_task_periodic() -> Weight {
		// Minimum execution time: 14_223 nanoseconds.
		Weight::from_ref_time(14_588_000 as u64)
	}
	fn execute_dispatch_signed() -> Weight {
		// Minimum execution time: 6_217 nanoseconds.
		Weight::from_ref_time(6_417_000 as u64)
	}
	fn execute_dispatch_unsigned() -> Weight {
		// Minimum execution time: 6_018 nanoseconds.
		Weight::from_ref_time(6_291_000 as u64)
	}
	// Storage: Scheduler Agenda (r:1 w:1)
	fn schedule(s: u32, ) -> Weight {
		Weight::from_parts(54_318_000, 0u64)
			// Standard Error: 7_000
			.saturating_add(Weight::from_parts(180_000, 0u64))
			.saturating_mul(s.into())
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Scheduler Agenda (r:1 w:1)
	// Storage: Scheduler Lookup (r:0 w:1)
	fn cancel(s: u32, ) -> Weight {
		Weight::from_parts(50_614_000, 0u64)
			// Standard Error: 19_000
			.saturating_add(Weight::from_parts(1_809_000, 0u64))
			.saturating_mul(s.into())
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Scheduler Lookup (r:1 w:1)
	// Storage: Scheduler Agenda (r:1 w:1)
	fn schedule_named(s: u32, ) -> Weight {
		Weight::from_parts(70_748_000, 0u64)
			// Standard Error: 6_000
			.saturating_add(Weight::from_parts(245_000, 0u64))
			.saturating_mul(s.into())
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Scheduler Lookup (r:1 w:1)
	// Storage: Scheduler Agenda (r:1 w:1)
	fn cancel_named(s: u32, ) -> Weight {
		Weight::from_parts(62_401_000, 0u64)
			// Standard Error: 23_000
			.saturating_add(Weight::from_parts(1_887_000, 0u64))
			.saturating_mul(s.into())
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
}
