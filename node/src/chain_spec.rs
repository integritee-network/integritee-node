use hex::ToHex;
use integritee_node_runtime::{
	AccountId, AuraConfig, Balance, BalancesConfig, GenesisConfig, GrandpaConfig, Multisig,
	Signature, SudoConfig, SystemConfig, TeerexConfig, TreasuryPalletId, TEER, WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{crypto::Ss58Codec, ed25519, sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
use std::str::FromStr;

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

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

pub fn development_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;
	Ok(ChainSpec::from_genesis(
		// Name
		"Integritee Development (Solo)",
		// ID
		"integritee-solo-dev",
		ChainType::Development,
		move || {
			genesis_config(
				wasm_binary,
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
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		None,
		// Arbitrary string. Nodes will only synchronize with other nodes that have the same value
		// in their `fork_id`. This can be used in order to segregate nodes in cases when multiple
		// chains have the same genesis hash.
		None,
		// Properties
		None,
		// Extensions
		None,
	))
}

pub fn local_testnet_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;
	Ok(ChainSpec::from_genesis(
		// Name
		"Integritee Local Testnet (Solo)",
		// ID
		"integritee-solo-local-testnet",
		ChainType::Local,
		move || {
			genesis_config(
				wasm_binary,
				// Initial PoA authorities
				vec![authority_keys_from_seed("Alice"), authority_keys_from_seed("Bob")],
				// Sudo account
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				// Pre-funded accounts
				vec![
					(get_account_id_from_seed::<sr25519::Public>("Alice"), 1_000 * TEER),
					(get_account_id_from_seed::<sr25519::Public>("Bob"), 1_000 * TEER),
					(get_account_id_from_seed::<sr25519::Public>("Charlie"), 1_000 * TEER),
					(TreasuryPalletId::get().into_account_truncating(), 1_000 * TEER),
					// The address of a multi-signature account is deterministically generated from the signers and threshold of the multisig wallet.
					// Creating a multi-sig account from Polkadot-JS Apps UI, always sort the accounts according to the keys. Here we do the same
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
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		None,
		// Fork ID.
		None,
		// Properties
		None,
		// Extensions
		None,
	))
}

pub fn integritee_solo_fresh_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "wasm not available".to_string())?;

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

	Ok(ChainSpec::from_genesis(
		// Name
		"Integritee Network (Solo)",
		// ID
		"integritee-solo",
		ChainType::Live,
		move || {
			genesis_config(
				wasm_binary,
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
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		Some("teer"),
		// Arbitrary string. Nodes will only synchronize with other nodes that have the same value
		// in their `fork_id`. This can be used in order to segregate nodes in cases when multiple
		// chains have the same genesis hash.
		None,
		// Properties
		Some(
			serde_json::from_str(
				r#"{
				"ss58Format": 13,
				"tokenDecimals": 12,
				"tokenSymbol": "TEER"
			}"#,
			)
			.unwrap(),
		),
		// Extensions
		None,
	))
}

pub fn cranny_fresh_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "wasm not available".to_string())?;

	let sudo_account: AccountId =
		public_from_ss58::<sr25519::Public>("5CVcJfKKo7uqMGvAE9fzqw66tEfngwJat5FruAsa6hbSkejD")
			.into();

	let allocations = vec![(sudo_account.clone(), 10_000_000 * TEER)];

	Ok(ChainSpec::from_genesis(
		// Name
		"Integritee Testnet Cranny",
		// ID
		"integritee-cranny",
		ChainType::Live,
		move || {
			genesis_config(
				wasm_binary,
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
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		Some("teer"),
		// Arbitrary string. Nodes will only synchronize with other nodes that have the same value
		// in their `fork_id`. This can be used in order to segregate nodes in cases when multiple
		// chains have the same genesis hash.
		None,
		// Properties
		Some(
			serde_json::from_str(
				r#"{
				"ss58Format": 42,
				"tokenDecimals": 12,
				"tokenSymbol": "CRA"
			}"#,
			)
			.unwrap(),
		),
		// Extensions
		None,
	))
}

/// Configure initial storage state for FRAME modules.
///
fn genesis_config(
	wasm_binary: &[u8],
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	root_key: AccountId,
	initial_token_allocation: Vec<(AccountId, Balance)>,
	_enable_println: bool,
) -> GenesisConfig {
	GenesisConfig {
		system: SystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
		},
		balances: BalancesConfig { balances: initial_token_allocation },
		aura: AuraConfig {
			authorities: initial_authorities.iter().map(|x| (x.0.clone())).collect(),
		},
		grandpa: GrandpaConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect(),
		},
		sudo: SudoConfig {
			// Assign network admin rights.
			key: Some(root_key),
		},
		teerex: TeerexConfig { allow_sgx_debug_mode: true },
		claims: Default::default(),
		treasury: Default::default(),
		vesting: Default::default(),
	}
}

/// hard-coded configs

pub fn integritee_solo_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/integritee-solo.json")[..])
}

pub fn cranny_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/cranny.json")[..])
}
