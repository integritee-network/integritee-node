#[cfg(feature = "std")]
mod remote_attestation;

#[cfg(feature = "std")]
use remote_attestation::verify_mra_cert;
use runtime_interface::runtime_interface;

#[runtime_interface]
pub trait CustomHostCalls {
	// Only types that implement the RIType (Runtime Interface Type) trait can be returned
	fn verify_ra_report(cert_der: &[u8]) -> Option<()> {
		match verify_mra_cert(cert_der) {
			Ok(_) => Some(()),
			Err(_) => None,
		}
	}
}
