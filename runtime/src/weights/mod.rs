//! The weights used in the runtime
//!
//! The current weights have been obtained with the following reference hardware:
//! * GenuineIntel CPU MHz: 2494.144
//! * 8GB of RAM
//! * NVMe SSD

// the generated files to not pass clippy
#![allow(clippy::all)]

pub mod pallet_balances;
pub mod pallet_claims;
pub mod pallet_enclave_bridge;
pub mod pallet_multisig;
pub mod pallet_preimage;
pub mod pallet_proxy;
pub mod pallet_scheduler;
pub mod pallet_sidechain;
pub mod pallet_sudo;
pub mod pallet_teeracle;
pub mod pallet_teerex;
pub mod pallet_timestamp;
pub mod pallet_treasury;
pub mod pallet_utility;
pub mod pallet_vesting;
