
//! Autogenerated weights for `pallet_proxy`
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
// --pallet=pallet_proxy
// --extrinsic=*
// --execution=wasm
// --wasm-execution=compiled
// --heap-pages=4096
// --output=runtime/src/weights/pallet_proxy.rs


#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for pallet_proxy.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_proxy::WeightInfo for WeightInfo<T> {
	// Storage: Proxy Proxies (r:1 w:0)
	fn proxy(p: u32, ) -> Weight {
		Weight::from_ref_time(49_346_000)
			// Standard Error: 15_000
			.saturating_add(Weight::from_ref_time(423_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
	}
	// Storage: Proxy Proxies (r:1 w:0)
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	fn proxy_announced(a: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(108_778_000)
			// Standard Error: 78_000
			.saturating_add(Weight::from_ref_time(985_000)).saturating_mul(a.into()))
			// Standard Error: 81_000
			.saturating_add(Weight::from_ref_time(472_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	fn remove_announcement(a: u32, _p: u32, ) -> Weight {
		Weight::from_ref_time(80_354_000)
			// Standard Error: 21_000
			.saturating_add(Weight::from_ref_time(1_101_000)).saturating_mul(a.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	fn reject_announcement(a: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(73_831_000)
			// Standard Error: 53_000
			.saturating_add(Weight::from_ref_time(1_185_000)).saturating_mul(a.into()))
			// Standard Error: 55_000
			.saturating_add(Weight::from_ref_time(162_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Proxies (r:1 w:0)
	// Storage: Proxy Announcements (r:1 w:1)
	// Storage: System Account (r:1 w:1)
	fn announce(a: u32, p: u32, ) -> Weight {
		Weight::from_ref_time(97_013_000)
			// Standard Error: 61_000
			.saturating_add(Weight::from_ref_time(1_224_000)).saturating_mul(a.into()))
			// Standard Error: 64_000
			.saturating_add(Weight::from_ref_time(500_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(3))
			.saturating_add(T::DbWeight::get().writes(2))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	fn add_proxy(p: u32, ) -> Weight {
		Weight::from_ref_time(84_020_000)
			// Standard Error: 55_000
			.saturating_add(Weight::from_ref_time(591_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	fn remove_proxy(p: u32, ) -> Weight {
		Weight::from_ref_time(78_733_000)
			// Standard Error: 49_000
			.saturating_add(Weight::from_ref_time(234_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	fn remove_proxies(p: u32, ) -> Weight {
		Weight::from_ref_time(70_957_000)
			// Standard Error: 15_000
			.saturating_add(Weight::from_ref_time(451_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: unknown [0x3a65787472696e7369635f696e646578] (r:1 w:0)
	// Storage: Proxy Proxies (r:1 w:1)
	fn anonymous(p: u32, ) -> Weight {
		Weight::from_ref_time(96_967_000)
			// Standard Error: 55_000
			.saturating_add(Weight::from_ref_time(109_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(2))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: Proxy Proxies (r:1 w:1)
	fn kill_anonymous(p: u32, ) -> Weight {
		Weight::from_ref_time(74_013_000)
			// Standard Error: 8_000
			.saturating_add(Weight::from_ref_time(439_000)).saturating_mul(p.into()))
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
