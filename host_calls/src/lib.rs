pub mod remote_attestation;

use remote_attestation::verify_mra_cert;
use runtime_interface::runtime_interface;

#[runtime_interface]
pub trait CustomHostCalls {
	fn verify_ra_report(cert_der: &[u8]) {
		verify_mra_cert([u8]);
	}
}
