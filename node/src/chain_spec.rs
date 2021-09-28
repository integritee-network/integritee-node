use integritee_node_runtime::{
	AccountId, AuraConfig, BalancesConfig, GenesisConfig, GrandpaConfig, Signature, SudoConfig,
	SystemConfig, TreasuryPalletId, WASM_BINARY,
};
use sc_service::ChainType;
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{crypto::Ss58Codec, ed25519, sr25519, Pair, Public};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{AccountIdConversion, IdentifyAccount, Verify};
use std::str::FromStr;

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
	// what's up with this weird trait bound??
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

pub fn development_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;
	Ok(ChainSpec::from_genesis(
		// Name
		"Development",
		// ID
		"dev",
		ChainType::Development,
		move || {
			testnet_genesis(
				wasm_binary,
				// Initial PoA authorities
				vec![authority_keys_from_seed("Alice")],
				// Sudo account
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				// Pre-funded accounts
				vec![
					get_account_id_from_seed::<sr25519::Public>("Alice"),
					get_account_id_from_seed::<sr25519::Public>("Bob"),
					get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
					get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
					treasury_account_id(),
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
		"Local Testnet",
		// ID
		"local_testnet",
		ChainType::Local,
		move || {
			testnet_genesis(
				wasm_binary,
				// Initial PoA authorities
				vec![authority_keys_from_seed("Alice"), authority_keys_from_seed("Bob")],
				// Sudo account
				get_account_id_from_seed::<sr25519::Public>("Alice"),
				// Pre-funded accounts
				vec![
					get_account_id_from_seed::<sr25519::Public>("Alice"),
					get_account_id_from_seed::<sr25519::Public>("Bob"),
					get_account_id_from_seed::<sr25519::Public>("Charlie"),
					get_account_id_from_seed::<sr25519::Public>("Dave"),
					get_account_id_from_seed::<sr25519::Public>("Eve"),
					get_account_id_from_seed::<sr25519::Public>("Ferdie"),
					get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
					get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
					get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
					get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
					get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
					get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
					treasury_account_id(),
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
		Some(
			// make configarble
			serde_json::from_str(token_specs).unwrap(),
		),
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
	integritee_chain_spec(
		"Integritee Mainnet",
		"integritee-mainnet",
		GenesisKeys::Integritee,
		r#"{
		"ss58Format": 13,
		"tokenDecimals": 12,
		"tokenSymbol": "TEER"
		}"#,
	)
}

pub fn cranny_fresh_config() -> Result<ChainSpec, String> {
	integritee_chain_spec(
		"Cranny",
		"cranny",
		GenesisKeys::Cranny,
		r#"{
		"ss58Format": 42,
		"tokenDecimals": 12,
		"tokenSymbol": "CRA"
		}"#,
	)
}

pub fn integritee_mainnet_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/integritee-mainnet.json")[..])
}

pub fn cranny_config() -> Result<ChainSpec, String> {
	ChainSpec::from_json_bytes(&include_bytes!("../res/cranny.json")[..])
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

	// Todo: Chris check wasm binary
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(chain_spec(
		&chain_name,
		&chain_id,
		move || {
			testnet_genesis(wasm_binary, authorities.clone(), root.clone(), endowed.clone(), false)
		},
		token_specs,
	))
}

/// Configure initial storage state for FRAME modules.
///
/// Todo: rename to genesis_config
fn testnet_genesis(
	wasm_binary: &[u8],
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	_enable_println: bool,
) -> GenesisConfig {
	let treasury_funding =
		(endowed_accounts.len() as u128 - 1u128) * ENDOWED_FUNDING * TREASURY_FUNDING_PERCENT /
			100u128;
	GenesisConfig {
		system: SystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
			changes_trie_config: Default::default(),
		},
		balances: BalancesConfig {
			// Configure endowed accounts with initial balance of ENDOWED_FUNDING and allocate the treasury TREASURY_FUNDING_PERCENT of total supply .
			balances: endowed_accounts
				.iter()
				.cloned()
				.map(|k| {
					if k == treasury_account_id() {
						(k, treasury_funding)
					} else if k == CrannyKeys::root() {
						(k, 10_000_000__000_000_000_000)
					} else {
						(k, ENDOWED_FUNDING)
					}
				})
				.collect(),
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
		treasury: Default::default(),
	}
}
