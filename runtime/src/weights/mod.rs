//! The weights used in the runtime
//!
//! The current weights have been obtained with the following reference hardware:
//! * Core(TM) i7-10875H
//! * 32GB of RAM
//! * NVMe SSD

// the generated files to not pass clippy
#![allow(clippy::all)]

pub mod frame_system;
pub mod pallet_balances;
pub mod pallet_multisig;
pub mod pallet_proxy;
pub mod pallet_teerex;
pub mod pallet_timestamp;
pub mod pallet_treasury;
pub mod pallet_vesting;
