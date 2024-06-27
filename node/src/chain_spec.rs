use hex::ToHex;
use integritee_node_runtime::{
	AccountId, Balance, Multisig, Signature, TreasuryPalletId, TEER, WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_consensus_grandpa::AuthorityId as GrandpaId;
use sp_core::{crypto::Ss58Codec, ed25519, sr25519, Pair, Public};
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
use std::str::FromStr;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec;

type AccountPublic = <Signature as Verify>::Signer;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

pub fn public_from_ss58<TPublic: Public + FromStr>(ss58: &str) -> TPublic
where
	<TPublic as FromStr>::Err: std::fmt::Debug,
{
	TPublic::from_ss58check(ss58).expect("supply valid ss58!")
}

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

pub fn multisig_account(mut accounts: Vec<AccountId>, threshold: u16) -> AccountId {
	// sort accounts by public key, as js/apps would do
	accounts.sort_by(|a, b| (*a).encode_hex::<String>().cmp(&(*b).encode_hex::<String>()));
	Multisig::multi_account_id(&accounts, threshold)
}

pub fn development_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM binary was not built, please build it!"), None)
		.with_name("Integritee Network (dev)")
		.with_id("integritee-solo-dev")
		.with_protocol_id("teer")
		.with_chain_type(ChainType::Development)
		.with_properties(teer_properties())
		.with_genesis_config_patch(genesis_config(
			// Initial PoA authorities
			vec![authority_keys_from_seed("Alice")],
			// Sudo account
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			// Pre-funded accounts
			vec![
				(get_account_id_from_seed::<sr25519::Public>("Alice"), 1_000 * TEER),
				(get_account_id_from_seed::<sr25519::Public>("Bob"), 1_000 * TEER),
				(get_account_id_from_seed::<sr25519::Public>("Charlie"), 1_000 * TEER),
				(TreasuryPalletId::get().into_account_truncating(), 1_000 * TEER),
				(
					multisig_account(
						vec![
							get_account_id_from_seed::<sr25519::Public>("Alice"),
							get_account_id_from_seed::<sr25519::Public>("Bob"),
							get_account_id_from_seed::<sr25519::Public>("Charlie"),
						],
						2,
					),
					1_000 * TEER,
				),
			],
			true,
		))
		.build()
}

pub fn local_testnet_config() -> ChainSpec {
	ChainSpec::builder(WASM_BINARY.expect("WASM binary was not built, please build it!"), None)
		.with_name("Integritee Network (local)")
		.with_id("integritee-solo-local")
		.with_protocol_id("teer")
		.with_chain_type(ChainType::Development)
		.with_properties(teer_properties())
		.with_genesis_config_patch(genesis_config(
			// Initial PoA authorities
			vec![authority_keys_from_seed("Alice")],
			// Sudo account
			get_account_id_from_seed::<sr25519::Public>("Alice"),
			// Pre-funded accounts
			vec![
				(get_account_id_from_seed::<sr25519::Public>("Alice"), 1_000 * TEER),
				(get_account_id_from_seed::<sr25519::Public>("Bob"), 1_000 * TEER),
				(get_account_id_from_seed::<sr25519::Public>("Charlie"), 1_000 * TEER),
				(TreasuryPalletId::get().into_account_truncating(), 1_000 * TEER),
				(
					multisig_account(
						vec![
							get_account_id_from_seed::<sr25519::Public>("Alice"),
							get_account_id_from_seed::<sr25519::Public>("Bob"),
							get_account_id_from_seed::<sr25519::Public>("Charlie"),
						],
						2,
					),
					1_000 * TEER,
				),
			],
			true,
		))
		.build()
}

pub fn integritee_solo_fresh_config() -> ChainSpec {
	let sudo_account: AccountId =
		public_from_ss58::<sr25519::Public>("2JPGqddf4yEU7waYt7RMp9xwYabm16h8neYEk24tKQs4bAwN")
			.into();
	let multisig_controller_accounts: Vec<AccountId> = vec![
		public_from_ss58::<sr25519::Public>("2P3Yo9DgGxUiBgdrYorLTHpRnwTSwAiF92xhnfen1SpYc4XN")
			.into(),
		public_from_ss58::<sr25519::Public>("2NXxRz9k9V8VBu2Z3HQLWiXocoKBhxYyNR1LqxRQFcNT1m2D")
			.into(),
		public_from_ss58::<sr25519::Public>("2NBSuNod6Vy97nmkXkg7vsyU1guudk9Ygakr6LVCXk8mTuvD")
			.into(),
		public_from_ss58::<sr25519::Public>("2PyzGJkumD4d5byCLxZnn3HESF7qqrMfHBYRgQ4Dx3hdEvuk")
			.into(),
	];
	let multisig_controller_threshold: u16 = 3;

	let mut allocations = vec![(sudo_account.clone(), 100 * TEER)];
	allocations.append(
		&mut multisig_controller_accounts.iter().map(|a| (a.clone(), 100 * TEER)).collect(),
	);
	allocations.append(&mut vec![(
		multisig_account(multisig_controller_accounts, multisig_controller_threshold),
		500 * TEER,
	)]);

	ChainSpec::builder(WASM_BINARY.expect("WASM binary was not built, please build it!"), None)
		.with_name("Integritee Network (Solo)")
		.with_id("integritee-solo")
		.with_protocol_id("teer")
		.with_chain_type(ChainType::Live)
		.with_properties(teer_properties())
		.with_genesis_config_patch(genesis_config(
			// Initial PoA authorities
			vec![
				(
					public_from_ss58::<sr25519::Public>(
						"2PPzpwiTGvcgc4stV326en2mWqY1qFzhQ95SCqYZ4Q5dqwhJ",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"2N8Q3CSCrXjEEBRiSaiXSLTDcbHCSeoKdXePZiSr8ySnoP4f",
					)
					.into(),
				),
				(
					public_from_ss58::<sr25519::Public>(
						"2Px7JZCbMTBhBdWHT7cbC2SGqsVF2cFygdvdaYmuNgV53Bgh",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"2MrnyHrQgJb1omjrCu8ZJ4LYBaczcXnREREYX72gmkZZHYFG",
					)
					.into(),
				),
				(
					public_from_ss58::<sr25519::Public>(
						"2PGjX1Nyq2SC7uuWTHWiEMQuJBMRupaefgaG5t6t588nFMZU",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"2PLiyfMnuEc7mcgSqfqA7ZHstYeQh3kVZ8eJrsUcYsqTKU3W",
					)
					.into(),
				),
				(
					public_from_ss58::<sr25519::Public>(
						"2Jhqi21p3UdGu1SBJzeUyQM9FudC5iC7e4KryAuJ4NZMhYPe",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"2LCKNXvVSWpL6rBusK2RUkYaFV1wv9MnWG2UpGQecsrKpp4R",
					)
					.into(),
				),
				(
					public_from_ss58::<sr25519::Public>(
						"2JwCMVvx8DgzpRD7sF1PKpzCDbmGiB2oa67ka2SuUe2TSJgB",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"2P4Bbk7edF41ny7FSMrQ6u2UsjoTaDhD1DARzwdkeDwBiZfn",
					)
					.into(),
				),
			],
			// Sudo account
			sudo_account.clone(),
			// Pre-funded accounts
			allocations.clone(),
			// println
			false,
		))
		.build()
}

pub fn cranny_fresh_config() -> ChainSpec {
	let sudo_account: AccountId =
		public_from_ss58::<sr25519::Public>("5CVcJfKKo7uqMGvAE9fzqw66tEfngwJat5FruAsa6hbSkejD")
			.into();

	let allocations = vec![(sudo_account.clone(), 10_000_000 * TEER)];

	ChainSpec::builder(WASM_BINARY.expect("WASM binary was not built, please build it!"), None)
		.with_name("Integritee Testnet Cranny")
		.with_id("integritee-cranny")
		.with_protocol_id("teer")
		.with_chain_type(ChainType::Live)
		.with_properties(cranny_properties())
		.with_genesis_config_patch(genesis_config(
			// Initial PoA authorities
			vec![
				(
					public_from_ss58::<sr25519::Public>(
						"5DDBqKzDw4GnEVmqRXvo8iiWzFxT76E3KUDTk79NnM9F6B8V",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"5CyuN5TUy6hd1WN2o3uZLpRoBjsAqzXLxUFD2GNT1Sjv3sS5",
					)
					.into(),
				),
				(
					public_from_ss58::<sr25519::Public>(
						"5GhK3Hm39J7yL6ZYoeUxynhfTkPxCd3EqnAPfgHcDo37wqmz",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"5FBqLTmuJWUFkceoeyWRqrSkYpuqJi9hXNAFFfLL3oTJzSCp",
					)
					.into(),
				),
				(
					public_from_ss58::<sr25519::Public>(
						"5DHwmxfN57NvGpLYFFfxrshnGxccE12VbUGsFCzGSYZQKMfD",
					)
					.into(),
					public_from_ss58::<ed25519::Public>(
						"5DpXQisSziSLWvRKBPH4F8Twdg89gnKbYpMQDtGmgTJrEzyr",
					)
					.into(),
				),
			],
			// Sudo account
			sudo_account.clone(),
			// Pre-funded accounts
			allocations.clone(),
			// println
			false,
		))
		.build()
}

/// Configure initial storage state for FRAME modules.
///
fn genesis_config(
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	root_key: AccountId,
	initial_token_allocation: Vec<(AccountId, Balance)>,
	_enable_println: bool,
) -> serde_json::Value {
	serde_json::json!({
		"balances": { "balances": initial_token_allocation },
		"aura": {
			"authorities": initial_authorities.iter().map(|x| (x.0.clone())).collect::<Vec<_>>(),
		},
		"grandpa": {
			"authorities": initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect::<Vec<_>>(),
		},
		"sudo": {
			// Assign network admin rights.
			"key": Some(root_key),
		},
		"teerex": { "allow_sgx_debug_mode": true, "allow_skipping_attestation": true },
	})
}

/// hard-coded configs

pub fn integritee_solo_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/integritee-solo.json")[..])
}

pub fn cranny_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/cranny.json")[..])
}

fn teer_properties() -> sc_service::Properties {
	serde_json::from_str(
		r#"{
				"ss58Format": 13,
				"tokenDecimals": 12,
				"tokenSymbol": "TEER"
			}"#,
	)
	.unwrap()
}

fn cranny_properties() -> sc_service::Properties {
	serde_json::from_str(
		r#"{
			  	"ss58Format": 42,
				"tokenDecimals": 12,
				"tokenSymbol": "CRA"
			}"#,
	)
	.unwrap()
}
