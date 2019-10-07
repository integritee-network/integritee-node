// Copyright 2017-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.
extern crate sgx_tstd as std;

#[macro_use]
use std::fmt;
#[macro_use]
use std::vec::Vec;

use sgx_log::*;

use primitives::{
	blake2_128, blake2_256, twox_128, twox_256, twox_64, ed25519, Blake2Hasher, sr25519, Pair,
};

#[cfg(feature = "enable_host_calls")]
extern crate host_calls;

/*
// Switch to this after PoC-3
// pub use primitives::BlakeHasher;
pub use substrate_state_machine::{
	Externalities, BasicExternalities, TestExternalities, ChildStorageKey,
};
*/
use environmental::environmental;
use primitives::{offchain, H256};
//use primitives::{hexdisplay::HexDisplay};
//use trie::{TrieConfiguration, trie_types::Layout};

use std::{collections::HashMap, convert::TryFrom};
pub type SgxExternalities = HashMap<Vec<u8>, Vec<u8>>;
environmental!(hm: SgxExternalities);


/// Returns a `ChildStorageKey` if the given `storage_key` slice is a valid storage
/// key or panics otherwise.
///
/// Panicking here is aligned with what the `without_std` environment would do
/// in the case of an invalid child storage key.
/*
fn child_storage_key_or_panic(storage_key: &[u8]) -> ChildStorageKey<Blake2Hasher> {
	match ChildStorageKey::from_slice(storage_key) {
		Some(storage_key) => storage_key,
		None => panic!("child storage key is invalid"),
	}
}
*/


// FIXME: the following is redundant: copy-paste from substraTEE-worker/enclave/hex
use std::char;
use sgx_types::*;

#[allow(unused)]
fn encode_hex_digit(digit: u8) -> char {
    match char::from_digit(u32::from(digit), 16) {
        Some(c) => c,
        _ => panic!(),
    }
}

#[allow(unused)]
fn encode_hex_byte(byte: u8) -> [char; 2] {
    [encode_hex_digit(byte >> 4), encode_hex_digit(byte & 0x0Fu8)]
}

#[allow(unused)]
pub fn encode_hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes
        .iter()
        .map(|byte| encode_hex_byte(*byte).iter().copied().collect())
        .collect();
    strs.join("")
}

impl StorageApi for () {
	fn storage(key: &[u8]) -> Option<Vec<u8>> {
		debug!("storage('{}')", encode_hex(key));
		hm::with(|hm| hm.get(key).map(|s| {
			debug!("  returning {}", encode_hex(s));
			s.to_vec()
		}))
			.expect("storage cannot be called outside of an Externalities-provided environment.")
	}

	fn read_storage(key: &[u8], value_out: &mut [u8], value_offset: usize) -> Option<usize> {
		debug!("read_storage('{}' with offset =  {:?}. value_out.len() is {})", encode_hex(key), value_offset, value_out.len());
		hm::with(|hm| hm.get(key).map(|value| {
			debug!("  entire stored value: {:?}", value);
			let value = &value[value_offset..];
			debug!("  stored value at offset: {:?}", value);
			let written = std::cmp::min(value.len(), value_out.len());
			value_out[..written].copy_from_slice(&value[..written]);
			debug!("  write back {:?}, return len {}", value_out, value.len());
			value.len()
		})).expect("read_storage cannot be called outside of an Externalities-provided environment.")
	}

	fn child_storage(storage_key: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        // TODO: unimplemented
		warn!("StorageApi::child_storage() unimplemented");
		Some(vec![0,1,2,3])
	}

	fn set_storage(key: &[u8], value: &[u8]) {
		debug!("set_storage('{}', {:x?})", encode_hex(key), value);
		hm::with(|hm|
			hm.insert(key.to_vec(), value.to_vec())
        );
	}

	fn read_child_storage(
		storage_key: &[u8],
		key: &[u8],
		value_out: &mut [u8],
		value_offset: usize,
	) -> Option<usize> {
        // TODO unimplemented
		warn!("StorageApi::read_child_storage() unimplemented");
		Some(0)
	}

	fn set_child_storage(storage_key: &[u8], key: &[u8], value: &[u8]) {
        warn!("StorageApi::set_child_storage() unimplemented");
	}

	fn clear_storage(key: &[u8]) {
        warn!("StorageApi::clear_storage() unimplemented");
	}

	fn clear_child_storage(storage_key: &[u8], key: &[u8]) {
		warn!("StorageApi::clear_child_storage() unimplemented");
	}

	fn kill_child_storage(storage_key: &[u8]) {
		warn!("StorageApi::kill_child_storage() unimplemented");

	}

	fn exists_storage(key: &[u8]) -> bool {
		warn!("StorageApi::exists_storage() unimplemented");
		false
	}

	fn exists_child_storage(storage_key: &[u8], key: &[u8]) -> bool {
		warn!("StorageApi::exists_child_storage() unimplemented");
		false
	}

	fn clear_prefix(prefix: &[u8]) {
		warn!("StorageApi::clear_storage() unimplemented");
	}

	fn clear_child_prefix(storage_key: &[u8], prefix: &[u8]) {
		warn!("StorageApi::clear_child_prefix() unimplemented");
	}

	fn storage_root() -> [u8; 32] {
		warn!("StorageApi::storage_root() unimplemented");
		[0u8; 32]
	}

	fn child_storage_root(storage_key: &[u8]) -> Vec<u8> {
		warn!("StorageApi::child_storage_root() unimplemented");
		vec![0,1,2,3]
	}

	fn storage_changes_root(parent_hash: [u8; 32]) -> Option<[u8; 32]> {
		warn!("StorageApi::storage_changes_root() unimplemented");
		Some([0u8; 32])
	}

	fn blake2_256_trie_root(_input: Vec<(Vec<u8>, Vec<u8>)>) -> H256 {
		warn!("StorageApi::blake2_256_trie_root unimplemented");
		H256::default()
	}

	fn blake2_256_ordered_trie_root(input: Vec<Vec<u8>>) -> H256 {
		warn!("StorageApi::blake2_256_ordered_trie_root unimplemented");
		H256::default()
	}
}

impl OtherApi for () {
	fn chain_id() -> u64 {
		warn!("OtherApi::chain_id unimplemented");
		0
	}

	fn print_num(val: u64) {
		println!("{}", val)
	}

	fn print_utf8(utf8: &[u8]) {
		println!("{:?}", utf8)

	}

	fn print_hex(data: &[u8]) {
		println!("{:?}", data)
	}

	fn verify_ra_report(cert: &[u8]) -> Result<(), &'static str>{
		#[cfg(feature = "enable_host_calls")]
		let ret = host_calls::verify_mra_cert(cert);
		#[cfg(not(feature = "enable_host_calls"))]
		let ret = Err("enable_host_calls feature not enabled");
		
		ret

	}
}

impl CryptoApi for () {
	fn ed25519_public_keys(id: KeyTypeId) -> Vec<ed25519::Public> {
        warn!("CryptoApi::ed25519_public_keys unimplemented");
        vec!(ed25519::Public::default())
	}

	fn ed25519_generate(id: KeyTypeId, seed: Option<&str>) -> ed25519::Public {
        warn!("CryptoApi::ed25519_generate unimplemented");
        ed25519::Public::default()
	}

	fn ed25519_sign(
		id: KeyTypeId,
		pubkey: &ed25519::Public,
		msg: &[u8],
	) -> Option<ed25519::Signature> {
        warn!("CryptoApi::ed25519_sign unimplemented");
        Some(ed25519::Signature::default())
	}

	fn ed25519_verify(sig: &ed25519::Signature, msg: &[u8], pubkey: &ed25519::Public) -> bool {
		warn!("CryptoApi::ed25519_verify unimplemented");
		true
	}

	fn sr25519_public_keys(id: KeyTypeId) -> Vec<sr25519::Public> {
		warn!("CryptoApi::sr25519_public_key unimplemented");
		vec!(sr25519::Public::default())
	}

	fn sr25519_generate(id: KeyTypeId, seed: Option<&str>) -> sr25519::Public {
		warn!("CryptoApi::sr25519_generate unimplemented");
		sr25519::Public::default()
	}

	fn sr25519_sign(
		id: KeyTypeId,
		pubkey: &sr25519::Public,
		msg: &[u8],
	) -> Option<sr25519::Signature> {
		warn!("CryptoApi::sr25519_sign unimplemented");
		Some(sr25519::Signature::default())
	}

	fn sr25519_verify(sig: &sr25519::Signature, msg: &[u8], pubkey: &sr25519::Public) -> bool {
		warn!("CryptoApi::sr25519_verify unimplemented");
		true
	}

	fn secp256k1_ecdsa_recover(sig: &[u8; 65], msg: &[u8; 32]) -> Result<[u8; 64], EcdsaVerifyError> {
		warn!("CryptoApi::secp256k1_ecdsa_recover unimplemented");
		Ok([0;64])
	}
}

impl HashingApi for () {
	fn keccak_256(data: &[u8]) -> [u8; 32] {
		warn!("HashingApi::keccak256 unimplemented");
		[0u8; 32]
	}

	fn blake2_128(data: &[u8]) -> [u8; 16] {
		debug!("blake2_128 of {}", encode_hex(data));
		let hash = blake2_128(data);
		debug!("  returning hash {}", encode_hex(&hash));
		hash
	}

	fn blake2_256(data: &[u8]) -> [u8; 32] {
		debug!("blake2_256 of {}", encode_hex(data));
		let hash = blake2_256(data);
		debug!("  returning hash {}", encode_hex(&hash));
		hash
	}

	fn twox_256(data: &[u8]) -> [u8; 32] {
		debug!("twox_256 of {}", encode_hex(data));
		let hash = twox_256(data);
		debug!("  returning {}", encode_hex(&hash));
		hash
	}

	fn twox_128(data: &[u8]) -> [u8; 16] {
		debug!("twox_128 of {}", encode_hex(data));
		let hash = twox_128(data);
		debug!("  returning {}", encode_hex(&hash));
		hash
	}

	fn twox_64(data: &[u8]) -> [u8; 8] {
		debug!("twox_64 of {}", encode_hex(data));
		let hash = twox_64(data);
		debug!("  returning {}", encode_hex(&hash));
		hash
	}
}

/*
fn with_offchain<R>(f: impl FnOnce(&mut dyn offchain::Externalities) -> R, msg: &'static str) -> R {
	ext::with(|ext| ext
		.offchain()
		.map(|ext| f(ext))
		.expect(msg)
	).expect("offchain-worker functions cannot be called outside of an Externalities-provided environment.")
}
*/

impl OffchainApi for () {
	fn is_validator() -> bool {
		warn!("OffchainApi::submit_extrinsic unimplemented");
        false
	}

	fn submit_transaction(data: Vec<u8>) -> Result<(), ()> {
		warn!("OffchainApi::submit_transaction unimplemented");
        Err(())
	}

	fn network_state() -> Result<OpaqueNetworkState, ()> {
		warn!("OffchainApi::network_state unimplemented");
        Err(())
	}

	fn timestamp() -> offchain::Timestamp {
		warn!("OffchainApi::timestamp unimplemented");
        offchain::Timestamp::default()
	}

	fn sleep_until(deadline: offchain::Timestamp) {
        warn!("OffchainApi::sleep_until unimplemented");
	}

	fn random_seed() -> [u8; 32] {
		warn!("OffchainApi::random_seed unimplemented");
        [0;32]
	}

	fn local_storage_set(kind: offchain::StorageKind, key: &[u8], value: &[u8]) {
		warn!("OffchainApi::local_storage_set unimplemented");
	}

	fn local_storage_compare_and_set(
		kind: offchain::StorageKind,
		key: &[u8],
		old_value: Option<&[u8]>,
		new_value: &[u8],
	) -> bool {
        warn!("OffchainApi::local_storage_compare_and_set unimplemented");	
        false
    }

	fn local_storage_get(kind: offchain::StorageKind, key: &[u8]) -> Option<Vec<u8>> {
		warn!("OffchainApi::local_storage_get unimplemented");	
        None
	}

	fn http_request_start(
		method: &str,
		uri: &str,
		meta: &[u8]
	) -> Result<offchain::HttpRequestId, ()> {
		warn!("OffchainApi::http_request_start unimplemented");
        Err(())
	}

	fn http_request_add_header(
		request_id: offchain::HttpRequestId,
		name: &str,
		value: &str
	) -> Result<(), ()> {
		warn!("OffchainApi::http_request_add_header unimplemented");
        Err(())
	}

	fn http_request_write_body(
		request_id: offchain::HttpRequestId,
		chunk: &[u8],
		deadline: Option<offchain::Timestamp>
	) -> Result<(), offchain::HttpError> {
		warn!("OffchainApi::http_request_write_body unimplemented");
        Err(offchain::HttpError::IoError)
	}

	fn http_response_wait(
		ids: &[offchain::HttpRequestId],
		deadline: Option<offchain::Timestamp>
	) -> Vec<offchain::HttpRequestStatus> {
		warn!("OffchainApi::http_response_wait unimplemented");
        Vec::new()
	}

	fn http_response_headers(
		request_id: offchain::HttpRequestId
	) -> Vec<(Vec<u8>, Vec<u8>)> {
		warn!("OffchainApi::http_response_wait unimplemented");
        Vec::new()
	}

	fn http_response_read_body(
		request_id: offchain::HttpRequestId,
		buffer: &mut [u8],
		deadline: Option<offchain::Timestamp>
	) -> Result<usize, offchain::HttpError> {
		warn!("OffchainApi::http_response_read_body unimplemented");
        Err(offchain::HttpError::IoError)
	}
}

impl Api for () {}

/// Execute the given closure with global function available whose functionality routes into the
/// externalities `ext`. Forwards the value that the closure returns.
// NOTE: need a concrete hasher here due to limitations of the `environmental!` macro, otherwise a type param would have been fine I think.
pub fn with_externalities<R, F: FnOnce() -> R>(ext: &mut SgxExternalities, f: F) -> R {
	hm::using(ext, f)
}

/// A set of key value pairs for storage.
pub type StorageOverlay = (); // HashMap<Vec<u8>, Vec<u8>>;

/// A set of key value pairs for children storage;
pub type ChildrenStorageOverlay = (); //HashMap<Vec<u8>, StorageOverlay>;

/// Execute the given closure with global functions available whose functionality routes into
/// externalities that draw from and populate `storage` and `children_storage`.
/// Forwards the value that the closure returns.
/*
pub fn with_storage<R, F: FnOnce() -> R>(
	storage: &mut (StorageOverlay, ChildrenStorageOverlay),
	f: F
) -> R {
	let mut alt_storage = Default::default();
	rstd::mem::swap(&mut alt_storage, storage);

	let mut ext = BasicExternalities::new(alt_storage.0, alt_storage.1);
	let r = ext::using(&mut ext, f);

	*storage = ext.into_storages();

	r
}
*/

#[cfg(test)]
mod std_tests {
	use super::*;
//	use primitives::map;

	#[test]
	fn storage_works() {
		let mut t = SgxExternalities::default();
		assert!(with_externalities(&mut t, || {
			assert_eq!(storage(b"hello"), None);
			set_storage(b"hello", b"world");
			assert_eq!(storage(b"hello"), Some(b"world".to_vec()));
			assert_eq!(storage(b"foo"), None);
			set_storage(b"foo", &[1, 2, 3][..]);
			true
		}));

		t = SgxExternalities::new(map![b"foo".to_vec() => b"bar".to_vec()], map![]);
        t.insert(b"foo".to_vec(), b"bar".to_vec());

		assert!(!with_externalities(&mut t, || {
			assert_eq!(storage(b"hello"), None);
			assert_eq!(storage(b"foo"), Some(b"bar".to_vec()));
			false
		}));
	}

	#[test]
	fn read_storage_works() {
		let mut t = SgxExternalities::new();

		with_externalities(&mut t, || {
            set_storage(b"test", b"\x0b\0\0\0Hello world");
			let mut v = [0u8; 4];
			assert!(read_storage(b":test", &mut v[..], 0).unwrap() >= 4);
			assert_eq!(v, [11u8, 0, 0, 0]);
			let mut w = [0u8; 11];
			assert!(read_storage(b":test", &mut w[..], 4).unwrap() >= 11);
			assert_eq!(&w, b"Hello world");
		});
	}

	#[test]
	fn clear_prefix_works() {
		let mut t = SgxExternalities::new();

		with_externalities(&mut t, || {
			clear_prefix(b":abc");

			assert!(storage(b":a").is_some());
			assert!(storage(b":abdd").is_some());
			assert!(storage(b":abcd").is_none());
			assert!(storage(b":abc").is_none());
		});
	}
}
