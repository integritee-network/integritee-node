use integritee_node_runtime::{
	AccountId, AuraConfig, BalancesConfig, GenesisConfig, GrandpaConfig, Multisig, Signature,
	SudoConfig, SystemConfig, TeerexConfig, TreasuryPalletId, WASM_BINARY, Balance, TEER
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{crypto::Ss58Codec, ed25519, sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
use std::str::FromStr;
use hex::ToHex;

// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;
pub const TREASURY_FUNDING_PERCENT: u128 = 5;
pub const ENDOWED_FUNDING: u128 = 1 << 60;
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

type AccountPublic = <Signature as Verify>::Signer;

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
///Get the account id for the treasury
pub fn treasury_account_id() -> AccountId {
	TreasuryPalletId::get().into_account()
}

pub fn multisig_account(mut accounts: Vec<AccountId>, threshold: u16) -> AccountId {
	// sort accounts by public key, as js/apps would do
	accounts.sort_by(|a, b| (*a).encode_hex::<String>().cmp(&(*b).encode_hex::<String>()));

	Multisig::multi_account_id(
		&accounts,
		threshold,
	)
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
					(get_account_id_from_seed::<sr25519::Public>("Alice"), 1_000_000_000_000),
					(get_account_id_from_seed::<sr25519::Public>("Bob"), 1_000_000_000_000),
					(get_account_id_from_seed::<sr25519::Public>("Charlie"), 1_000_000_000_000),
					(treasury_account_id(), 1_000_000_000_000),
					// The address of a multi-signature account is deterministically generated from the signers and threshold of the multisig wallet.
					// Creating a multi-sig account from Polkadot-JS Apps UI, always sort the accounts according to the keys. Here we do the same
					(multisig_account(vec![
						get_account_id_from_seed::<sr25519::Public>("Alice"),
						get_account_id_from_seed::<sr25519::Public>("Bob"),
						get_account_id_from_seed::<sr25519::Public>("Charlie")
					], 2), 1_000_000_000_000),
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
					(get_account_id_from_seed::<sr25519::Public>("Alice"), 1_000_000_000_000),
					(get_account_id_from_seed::<sr25519::Public>("Bob"), 1_000_000_000_000),
					(get_account_id_from_seed::<sr25519::Public>("Charlie"), 1_000_000_000_000),
					(treasury_account_id(), 1_000_000_000_000),
					// The address of a multi-signature account is deterministically generated from the signers and threshold of the multisig wallet.
					// Creating a multi-sig account from Polkadot-JS Apps UI, always sort the accounts according to the keys. Here we do the same
					(multisig_account(vec![
						get_account_id_from_seed::<sr25519::Public>("Alice"),
						get_account_id_from_seed::<sr25519::Public>("Bob"),
						get_account_id_from_seed::<sr25519::Public>("Charlie")
					], 2), 1_000_000_000_000),
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
		// Properties
		None,
		// Extensions
		None,
	))
}

// Todo: make token specs configurable
fn chain_spec<F: Fn() -> GenesisConfig + 'static + Send + Sync>(
	chain_name: &str,
	chain_id: &str,
	testnet_constructor: F,
	token_specs: &str,
) -> ChainSpec {
	ChainSpec::from_genesis(
		chain_name,
		chain_id,
		ChainType::Live,
		testnet_constructor,
		Vec::new(),
		// telemetry endpoints
		None,
		// protocol id
		Some("teer"),
		// properties
		Some(serde_json::from_str(token_specs).unwrap()),
		None,
	)
}



#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum GenesisKeys {
	/// Use integriTEE keys.
	Integritee,
	// Use Keys from the keyring for a test setup
	Cranny,
}

struct IntegriteeKeys;

impl IntegriteeKeys {
	fn root() -> AccountId {
		public_from_ss58::<sr25519::Public>("2JPGqddf4yEU7waYt7RMp9xwYabm16h8neYEk24tKQs4bAwN")
			.into()
	}
	fn authorities() -> Vec<(AuraId, GrandpaId)> {
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
		]
	}

}

struct CrannyKeys;

impl CrannyKeys {
	fn root() -> AccountId {
		public_from_ss58::<sr25519::Public>("5CVcJfKKo7uqMGvAE9fzqw66tEfngwJat5FruAsa6hbSkejD")
			.into()
	}
	fn authorities() -> Vec<(AuraId, GrandpaId)> {
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
		]
	}
}

pub fn integritee_mainnet_fresh_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "wasm not available".to_string())?;

	let sudo_account: AccountId = public_from_ss58::<sr25519::Public>("2JPGqddf4yEU7waYt7RMp9xwYabm16h8neYEk24tKQs4bAwN").into();
	let multisig_controller_accounts: Vec<AccountId> = vec![
		public_from_ss58::<sr25519::Public>("2P3Yo9DgGxUiBgdrYorLTHpRnwTSwAiF92xhnfen1SpYc4XN").into(),
		public_from_ss58::<sr25519::Public>("2NXxRz9k9V8VBu2Z3HQLWiXocoKBhxYyNR1LqxRQFcNT1m2D").into(),
		public_from_ss58::<sr25519::Public>("2NBSuNod6Vy97nmkXkg7vsyU1guudk9Ygakr6LVCXk8mTuvD").into(),
		public_from_ss58::<sr25519::Public>("2PyzGJkumD4d5byCLxZnn3HESF7qqrMfHBYRgQ4Dx3hdEvuk").into(),
	];
	let multisig_controller_threshold: u16 = 3;

	let mut allocations = vec![(sudo_account, 5 * TEER)];
	allocations.append(multisig_controller_accounts.iter().map(|a| (*a, 1 * TEER)).collect());
	allocations.append([(multisig_account(
		multisig_controller_accounts, 
		multisig_controller_threshold
	), 1 * TEER)]);
	
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
					(	public_from_ss58::<sr25519::Public>(
							"2PPzpwiTGvcgc4stV326en2mWqY1qFzhQ95SCqYZ4Q5dqwhJ",
						).into(),
						public_from_ss58::<ed25519::Public>(
							"2N8Q3CSCrXjEEBRiSaiXSLTDcbHCSeoKdXePZiSr8ySnoP4f",
						).into()
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
				sudo_account,
				// Pre-funded accounts
				allocations,
				// println
				false,
			)
		},
		// Bootnodes
		vec![
			"/ip4/142.93.162.173/tcp/30333/p2p/12D3KooWNUBDZuDGcmxRGHHHsBwnyZYAY9v2C3vpXjNngzoxYMf3",
			"/ip4/142.93.169.101/tcp/30333/p2p/12D3KooWRu78Bb6M4KCPjUJZ3QX13JbniUaW6eXhFJ5jPH1nvF8M"
		],
		// Telemetry
		vec![["/dns/telemetry.polkadot.io/tcp/443/x-parity-wss/%2Fsubmit%2F", 0]],
		// Protocol ID
		Some("teer"),
		// Properties
		Some(serde_json::from_str(
			r#"{
				"ss58Format": 13,
				"tokenDecimals": 12,
				"tokenSymbol": "TEER"
			}"#
		).unwrap()),
		// Extensions
		None,
	))
}

pub fn cranny_fresh_config() -> Result<ChainSpec, String> {
	integritee_chain_spec(
		"Integritee Testnet Cranny",
		"integritee-cranny",
		GenesisKeys::Cranny,
		r#"{
		"ss58Format": 42,
		"tokenDecimals": 12,
		"tokenSymbol": "CRA"
		}"#,
	)
}


pub fn integritee_chain_spec(
	chain_name: &str,
	chain_id: &str,
	genesis_keys: GenesisKeys,
	token_specs: &str,
) -> Result<ChainSpec, String> {
	let (root, endowed, authorities) = match genesis_keys {
		GenesisKeys::Integritee =>
			(IntegriteeKeys::root(), vec![IntegriteeKeys::root()], IntegriteeKeys::authorities()),
		GenesisKeys::Cranny =>
			(CrannyKeys::root(), vec![CrannyKeys::root()], CrannyKeys::authorities()),
	};

	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(chain_spec(
		&chain_name,
		&chain_id,
		move || {
			genesis_config(wasm_binary, authorities.clone(), root.clone(), endowed.clone(), false)
		},
		token_specs,
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
			changes_trie_config: Default::default(),
		},
		balances: BalancesConfig {
			balances: initial_token_allocation,
		},
		aura: AuraConfig {
			authorities: initial_authorities.iter().map(|x| (x.0.clone())).collect(),
		},
		grandpa: GrandpaConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect(),
		},
		sudo: SudoConfig {
			// Assign network admin rights.
			key: root_key,
		},
		teerex: TeerexConfig { allow_sgx_debug_mode: true },
		treasury: Default::default(),
		vesting: Default::default(),
	}
}

/// hard-coded configs

pub fn integritee_mainnet_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/integritee-mainnet.json")[..])
}

pub fn cranny_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/cranny.json")[..])
}
