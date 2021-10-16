//! The weights used in the runtime
//!
//! The current weights have been obtained with the following reference hardware:
//! * Intel(R) Xeon(R) E-2276G CPU @ 3.80 GHz
//! * 32GB of RAM
//! * 1TB SSD Samsung 860 EVO Basic, 2.5"

// the generated files to not pass clippy
#![allow(clippy::all)]

// note: Always double check the frame_system generated weights. Sometimes some values are 0, but
// return ridiculously high weights in another run. When re-running the benchmarks always perform
// sanity checks with substrate's weight for this module. The close to 0 values seem to be correct.
//
// Problematic functions are: `remark`, `remark_with_event`.
pub mod frame_system;
pub mod pallet_balances;
pub mod pallet_multisig;
pub mod pallet_proxy;
pub mod pallet_scheduler;
pub mod pallet_teerex;
pub mod pallet_timestamp;
pub mod pallet_treasury;
pub mod pallet_utility;
pub mod pallet_vesting;
