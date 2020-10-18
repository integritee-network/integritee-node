//  Copyright (c) 2019 Alain Brenzikofer
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

//! an RPC client to encointer node using websockets
//!
//! examples:
//! encointer-client-notee get-phase
//! encointer-client-notee transfer //Alice 5G9RtsTbiYJYQYMHbWfyPoeuuxNaCbC16tZ2JGrZ4gRKwz14 1000
//!

#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate log;


use sc_keystore::Store;
use sp_application_crypto::{ed25519, sr25519};
use sp_keyring::AccountKeyring;
use std::path::PathBuf;
use std::collections::HashMap;

use base58::{FromBase58, ToBase58};

use clap::{Arg, ArgMatches, AppSettings};
use clap_nested::{Command, Commander};
use codec::{Decode, Encode};
use log::*;
use sp_core::{crypto::Ss58Codec, hashing::blake2_256, sr25519 as sr25519_core, Pair};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
};

use std::sync::mpsc::channel;
use geojson::GeoJson;
use serde_json;
use std::fs;
use substrate_api_client::{
    compose_extrinsic, compose_extrinsic_offline, extrinsic::xt_primitives::UncheckedExtrinsicV4,
    node_metadata::Metadata, utils::hexstr_to_vec, Api, XtStatus,
};
use encointer_node_notee_runtime::{
    AccountId, Event, Hash, Signature, Moment, ONE_DAY, BalanceType, BalanceEntry, 
    BlockNumber, Header, Call, BalancesCall
};
use encointer_ceremonies::{
    Attestation, AttestationIndexType, ClaimOfAttendance,
    CurrencyCeremony, MeetupIndexType, ParticipantIndexType, ProofOfAttendance, Reputation
};
use encointer_scheduler::{CeremonyIndexType, CeremonyPhaseType};
use encointer_currencies::{CurrencyIdentifier, CurrencyPropertiesType, Location, Degree};
use fixed::transcendental::exp;
use fixed::traits::LossyInto;
use std::convert::TryInto;
use std::str::FromStr;

type AccountPublic = <Signature as Verify>::Signer;
const KEYSTORE_PATH: &str = "my_keystore";
const PREFUNDING_AMOUNT: u128 = 100_000_000_000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    env_logger::init();

    let _ = Commander::new()
        .options(|app| {
            app.arg(
                Arg::with_name("node-url")
                    .short("u")
                    .long("node-url")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("ws://127.0.0.1")
                    .help("node url"),
            )
            .arg(
                Arg::with_name("node-port")
                    .short("p")
                    .long("node-port")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("9944")
                    .help("node port"),
            )
            .arg(
                Arg::with_name("cid")
                    .short("c")
                    .long("cid")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .help("currency identifier, base58 encoded"),
            )            
            .name("encointer-client-notee")
            .version(VERSION)
            .author("Encointer Association <info@encointer.org>")
            .about("interact with encointer-node-notee")
            .after_help("")
            .setting(AppSettings::ColoredHelp)
        })
        .args(|_args, _matches| "")
        .add_cmd(
            Command::new("new-account")
                .description("generates a new account")
                .runner(|_args: &str, _matches: &ArgMatches<'_>| {
                    let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
                    let key: sr25519::AppPair = store.write().generate().unwrap();
                    drop(store);
                    println!("{}", key.public().to_ss58check());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-accounts")
                .description("lists all accounts in keystore")
                .runner(|_args: &str, _matches: &ArgMatches<'_>| {
                    let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
                    info!("sr25519 keys:");
                    for pubkey in store
                        .read()
                        .public_keys::<sr25519::AppPublic>()
                        .unwrap()
                        .into_iter()
                    {
                        println!("{}", pubkey.to_ss58check());
                    }
                    info!("ed25519 keys:");
                    for pubkey in store
                        .read()
                        .public_keys::<ed25519::AppPublic>()
                        .unwrap()
                        .into_iter()
                    {
                        println!("{}", pubkey.to_ss58check());
                    }
                    drop(store);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("print-metadata")
                .description("query node metadata and print it as json to stdout")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let meta = get_chain_api(matches).get_metadata();
                    println!("Metadata:\n {}", Metadata::pretty_format(&meta).unwrap());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("faucet")
                .description("send some bootstrapping funds to supplied account(s)")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("accounts")
                            .takes_value(true)
                            .required(true)
                            .value_name("ACCOUNT")
                            .multiple(true)
                            .min_values(1)
                            .help("Account(s) to be funded, ss58check encoded"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let _api = api.set_signer(AccountKeyring::Alice.pair());
                    let accounts: Vec<_> = matches.values_of("accounts").unwrap().collect();

                    let mut nonce = _api.get_nonce().unwrap();
                    for account in accounts.into_iter() {
                        let to = get_accountid_from_str(account);
                        #[allow(clippy::redundant_clone)]
                        let xt: UncheckedExtrinsicV4<_> = compose_extrinsic_offline!(
                            _api.clone().signer.unwrap(),
                            Call::Balances(BalancesCall::transfer(to.clone(), PREFUNDING_AMOUNT)),
                            nonce,
                            Era::Immortal,
                            _api.genesis_hash,
                            _api.genesis_hash,
                            _api.runtime_version.spec_version,
                            _api.runtime_version.transaction_version
                        );
                        // send and watch extrinsic until finalized
                        println!("Faucet drips to {} (Alice's nonce={})", to, nonce);
                        let _blockh = _api
                            .send_extrinsic(xt.hex_encode(), XtStatus::Ready)
                            .unwrap();
                        nonce += 1;
                    }
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("balance")
                .description("query on-chain balance for AccountId. If --cid is supplied, returns balance in that currency. Otherwise balance of native ERT token")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("AccountId")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let account = matches.value_of("AccountId").unwrap();
                    let accountid = get_accountid_from_str(account);
                    match matches.value_of("cid") {
                        Some(cid_str) => {
                            let cid = verify_cid(&api, cid_str);
                            let bn = get_block_number(&api);
                            let dr = get_demurrage_per_block(&api, cid);
                            let balance = if let Some(entry) = api
                                .get_storage_double_map("EncointerBalances", "Balance", cid, accountid, None) {
                                    apply_demurrage(entry, bn, dr)
                            } else { BalanceType::from_num(0) }; 
                            println!("NCTR balance for {} in currency {} is {} ", account, cid.encode().to_base58(), balance);
                        }
                        None => {
                            let balance = if let Some(data) = api.get_account_data(&accountid) {
                                data.free
                            } else {
                                0
                            };
                            println!("ERT balance for {} is {}", account, balance);
                        }
                    };
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("transfer")
                .description("transfer funds from one account to another. If --cid is supplied, send that currency (amount is fixpoint). Otherwise send native ERT tokens (amount is integer)")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("from")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("sender's AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("to")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("recipient's AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("amount")
                            .takes_value(true)
                            .required(true)
                            .value_name("U128")
                            .help("amount to be transferred"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let arg_from = matches.value_of("from").unwrap();
                    let arg_to = matches.value_of("to").unwrap();
                    let from = get_pair_from_str(arg_from);
                    let to = get_accountid_from_str(arg_to);
                    info!("from ss58 is {}", from.public().to_ss58check());
                    info!("to ss58 is {}", to.to_ss58check());
                    let _api = api.set_signer(sr25519_core::Pair::from(from));
                    let tx_hash = match matches.value_of("cid") {
                        Some(cid_str) => {
                            let cid = verify_cid(&_api, cid_str);
                            let amount = BalanceType::from_str(matches.value_of("amount").unwrap())
                                .expect("amount can be converted to fixpoint");
                            let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
                                _api.clone(),
                                "EncointerBalances",
                                "transfer",
                                to.clone(),
                                cid,
                                amount
                            );
                            _api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap()
                        },
                        None => {
                            let amount = u128::from_str_radix(matches.value_of("amount").unwrap(), 10)
                                .expect("amount can be converted to u128");
                            let xt = _api.balance_transfer(to.clone(), amount);
                            _api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap()
                        }
                    };
                    info!("[+] Transaction included. Hash: {:?}\n", tx_hash);
                    let result = _api.get_account_data(&to.clone()).unwrap();
                    println!("balance for {} is now {}", to, result.free);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("listen")
                .description("listen to on-chain events")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("events")
                            .short("e")
                            .long("await-events")
                            .takes_value(true)
                            .help("exit after given number of encointer events"),
                    )
                    .arg(
                        Arg::with_name("blocks")
                            .short("b")
                            .long("await-blocks")
                            .takes_value(true)
                            .help("exit after given number of blocks"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    listen(matches);
                    Ok(())
                }),
        )
        // start encointer stuff
        .add_cmd(
            Command::new("new-currency")
                .description("register new currency")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("specfile")
                            .takes_value(true)
                            .required(true)
                            .help("enhanced geojson file that specifies a currency"),
                    )
                    .arg(
                        Arg::with_name("signer")
                            .takes_value(true)
                            .required(true)
                            .help("a bootstrapper account to sign the registration extrinsic"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let p_arg = matches.value_of("signer").unwrap();
                    let signer = get_pair_from_str(p_arg);

                    let spec_file = matches.value_of("specfile").unwrap();

                    let spec_str = fs::read_to_string(spec_file).unwrap();
                    let geoloc = spec_str.parse::<GeoJson>().unwrap();

                    let mut loc = Vec::with_capacity(100);
                    match geoloc {
                        GeoJson::FeatureCollection(ref ctn) => {
                            for feature in &ctn.features {
                                let val = &feature.geometry.as_ref().unwrap().value;
                                if let geojson::Value::Point(pt) = val {
                                    let l = Location {
                                        lon: Degree::from_num(pt[0]),
                                        lat: Degree::from_num(pt[1]),
                                    };
                                    loc.push(l);
                                    debug!("lon: {} lat {} => {:?}", pt[0], pt[1], l);
                                }
                            }
                        }
                        _ => (),
                    };
                    let meta: serde_json::Value = serde_json::from_str(&spec_str).unwrap();
                    debug!("meta: {:?}", meta["currency_meta"]);
                    let bootstrappers: Vec<AccountId> = meta["currency_meta"]["bootstrappers"]
                        .as_array()
                        .expect("bootstrappers must be array")
                        .iter()
                        .map(|a| get_accountid_from_str(&a.as_str().unwrap()))
                        .collect();

                    let cid = blake2_256(&(loc.clone(), bootstrappers.clone()).encode());
                    let name = meta["currency_meta"]["name"].as_str().unwrap();
                    info!("bootstrappers: {:?}", bootstrappers);
                    info!("name: {}", name);
                    info!("Currency registered by {}", signer.public().to_ss58check());
                    let api = get_chain_api(matches);
                    let _api = api.clone().set_signer(sr25519_core::Pair::from(signer));
                    let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
                        _api.clone(),
                        "EncointerCurrencies",
                        "new_currency",
                        loc,
                        bootstrappers
                    );
                    let tx_hash = _api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();
                    info!("[+] Transaction got included. Hash: {:?}\n", tx_hash);
                    println!("{}", cid.to_base58());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-currencies")
                .description("list all registered currencies")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let cids = get_currency_identifiers(&api).expect("no currency registered");
                    println!("number of currencies:  {}", cids.len());
                    for cid in cids.iter() {
                        println!("currency with cid {}", cid.encode().to_base58());
                    }
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("get-phase")
                .description("read current ceremony phase from chain")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);

                    // >>>> add some debug info as well     
                    let bn = get_block_number(&api);
                    info!("block number: {}", bn);
                    let cindex = get_ceremony_index(&api);
                    info!("ceremony index: {}", cindex);
                    let tnext: Moment = api.get_storage_value(
                        "EncointerScheduler",
                        "NextPhaseTimestamp",
                        None
                    ).unwrap();
                    info!("next phase timestamp: {}", tnext);
                    // <<<<

                    let phase = get_current_phase(&api);
                    println!("{:?}", phase);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("next-phase")
                .description("Advance ceremony state machine to next phase by ROOT call")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches)
                        .set_signer(AccountKeyring::Alice.pair());

                    let xt: UncheckedExtrinsicV4<_> =
                        compose_extrinsic!(api.clone(), "EncointerScheduler", "next_phase");

                    // send and watch extrinsic until finalized
                    let _ = api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();
                    let phase = get_current_phase(&api);
                    println!("Phase is now: {:?}", phase);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-participants")
                .description("list all registered participants for current ceremony and supplied currency identifier")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    debug!("{:?}", matches);
                    let api = get_chain_api(matches);
                    let cindex = get_ceremony_index(&api);
                    let cid = verify_cid(&api,
                        matches
                            .value_of("cid")
                            .expect("please supply argument --cid"),
                    );
                    println!(
                        "listing participants for cid {} and ceremony nr {}",
                        cid.encode().to_base58(),
                        cindex
                    );
                    let pcount = get_participant_count(&api, (cid, cindex));
                    println!("number of participants assigned:  {}", pcount);
                    for p in 1..pcount + 1 {
                        let accountid = get_participant(&api, (cid, cindex), p).unwrap();
                        println!("ParticipantRegistry[{}, {}] = {}", cindex, p, accountid);
                    }                    
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-meetups")
                .description("list all assigned meetups for current ceremony and supplied currency identifier")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let cindex = get_ceremony_index(&api);
                    let cid = verify_cid(&api,
                        matches
                            .value_of("cid")
                            .expect("please supply argument --cid"),
                    );
                    println!(
                        "listing meetups for cid {} and ceremony nr {}",
                        cid.encode().to_base58(),
                        cindex
                    );
                    let mcount = get_meetup_count(&api, (cid, cindex));
                    println!("number of meetups assigned:  {}", mcount);
                    for m in 1..=mcount {
                        println!("MeetupRegistry[{}, {}] location is {:?}", 
                            cindex, m, get_meetup_location(&api, cid, m));
                        println!("MeetupRegistry[{}, {}] meeting time is {:?}", 
                            cindex, m, get_meetup_time(&api, cid, m));
                        match get_meetup_participants(&api, (cid, cindex), m) {
                            Some(participants) => {
                                println!("MeetupRegistry[{}, {}] participants are:", cindex, m);
                                for p in participants.iter() {
                                    println!("   {}", p);
                                }
                            }
                            None => println!("MeetupRegistry[{}, {}] EMPTY", cindex, m),
                        }
                    }    
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-attestations")
                .description("list all attestations for participants of current ceremony and supplied currency identifier")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let cindex = get_ceremony_index(&api);
                    let cid = verify_cid(&api,
                        matches
                            .value_of("cid")
                            .expect("please supply argument --cid"),
                    );
                    println!(
                        "listing attestations for cid {} and ceremony nr {}",
                        cid.encode().to_base58(),
                        cindex
                    );
                    let wcount = get_attestation_count(&api, (cid, cindex));
                    println!("number of attestations:  {}", wcount);
                    let pcount = get_participant_count(&api, (cid, cindex));
            
                    let mut participants_windex = HashMap::new();
                    for p in 1..pcount + 1 {
                        let accountid =
                            get_participant(&api, (cid, cindex), p).expect("error getting participant");
                        match get_participant_attestation_index(&api, (cid, cindex), &accountid) {
                            Some(windex) => {
                                participants_windex.insert(windex as AttestationIndexType, accountid)
                            }
                            _ => continue,
                        };
                    }
                    for w in 1..wcount + 1 {
                        let attestations = get_attestations(&api, (cid, cindex), w);
                        println!(
                            "AttestationRegistry[{}, {} ({})] = {:?}",
                            cindex, w, participants_windex[&w], attestations
                        );
                    }    
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("register-participant")
                .description("register encointer ceremony participant for supplied currency")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    let accountid = get_accountid_from_str(arg_who);
                    let signer = get_pair_from_str(arg_who);
                    let api = get_chain_api(matches);
                    let cindex = get_ceremony_index(&api);
                    let cid = verify_cid(&api,
                        matches
                            .value_of("cid")
                            .expect("please supply argument --cid"),
                    );
                    let rep = get_reputation(&api, &accountid, cid, cindex -1);
                    info!("{} has reputation {:?}", accountid, rep);
                    let proof = match rep {
                        Reputation::Unverified => None,
                        Reputation::UnverifiedReputable => None, // this should never by the case during REGISTERING!
                        Reputation::VerifiedUnlinked => Some(prove_attendance(accountid, cid, cindex - 1, arg_who)),
                        Reputation::VerifiedLinked => panic!("reputation of {} has already been linked! Not registering again", accountid),
                    };
                    debug!("proof: {:x?}", proof.encode());
                    if get_current_phase(&api) != CeremonyPhaseType::REGISTERING {
                        println!("wrong ceremony phase for registering participant");
                        return Ok(())
                    }
                    let _api = api.clone().set_signer(sr25519_core::Pair::from(signer.clone()));
                    let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
                        _api.clone(),
                        "EncointerCeremonies",
                        "register_participant",
                        cid,
                        proof
                    );
                    // send and watch extrinsic until finalized
                    let _ = _api.send_extrinsic(xt.hex_encode(), XtStatus::Ready).unwrap();
                    println!("Registration sent for {}. status: 'ready'", arg_who);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("register-attestations")
                .description("register encointer ceremony attestations for supplied currency")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("attestations")
                            .takes_value(true)
                            .required(true)
                            .multiple(true)
                            .min_values(2)
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    let who = get_pair_from_str(arg_who);
                    let attestation_args: Vec<_> = matches.values_of("attestations").unwrap().collect();
                    let mut attestations: Vec<Attestation<MultiSignature, AccountId, Moment>> = vec![];
                    for arg in attestation_args.iter() {
                        let w = Attestation::decode(&mut &hex::decode(arg).unwrap()[..]).unwrap();
                        attestations.push(w);
                    }
                    debug!("attestations: {:?}", attestations);
                    info!("send register_attestations for {}", who.public());
                    let api = get_chain_api(matches);
                    let _api = api.set_signer(sr25519_core::Pair::from(who));                    
                    let xt: UncheckedExtrinsicV4<_> = compose_extrinsic!(
                        _api.clone(),
                        "EncointerCeremonies",
                        "register_attestations",
                        attestations.clone()
                    );
                    let _ = _api.send_extrinsic(xt.hex_encode(), XtStatus::Ready).unwrap();
                    println!("Attestations sent for {}. status: 'ready'", arg_who);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("new-claim")
                .description("create a fresh claim of attendance for account")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("ACCOUNT")
                            .help("AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("vote")
                            .takes_value(true)
                            .required(true)
                            .value_name("VOTE")
                            .help("participant's vote on the number of people present at meetup time"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    debug!("{:?}", matches);
                    let arg_who = matches.value_of("accountid").unwrap();
                    let accountid = get_accountid_from_str(arg_who);
                    let api = get_chain_api(matches);
                    let cid = verify_cid(&api,
                        matches
                            .value_of("cid")
                            .expect("please supply argument --cid"),
                    );
                    let n_participants = matches
                        .value_of("vote")
                        .unwrap()
                        .parse::<u32>()
                        .unwrap();
                    let claim = new_claim_for(&api, accountid, cid, n_participants);
                    println!("{}", hex::encode(claim));
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("sign-claim")
                .description("sign someone's claim to attest their personhood")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                    .arg(
                        Arg::with_name("signer")
                            .takes_value(true)
                            .required(true)
                            .value_name("SIGNER")
                            .help("AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("claim")
                            .takes_value(true)
                            .required(true)
                            .value_name("CLAIM")
                            .help("claim of other party to be signed/attested"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    debug!("{:?}", matches);
                    let signer_arg = matches.value_of("signer").unwrap();
                    let claim = ClaimOfAttendance::decode(
                        &mut &hex::decode(matches.value_of("claim").unwrap()).unwrap()[..],
                    ).unwrap();
                    let attestation = sign_claim(claim, signer_arg);
                    println!("{}", hex::encode(attestation));
                    Ok(())
                }),
        )
        // To handle when no subcommands match
        .no_cmd(|_args, _matches| {
            println!("No subcommand matched");
            Ok(())
        })
        .run();
}

fn get_chain_api(matches: &ArgMatches<'_>) -> Api<sr25519::Pair> {
    let url = format!(
        "{}:{}",
        matches.value_of("node-url").unwrap(),
        matches.value_of("node-port").unwrap()
    );
    info!("connecting to {}", url);
    Api::<sr25519::Pair>::new(url)
}

fn listen(matches: &ArgMatches<'_>) {
    let api = get_chain_api(matches);
    info!("Subscribing to events");
    let (events_in, events_out) = channel();
    let mut count = 0u32;
    let mut blocks = 0u32;
    api.subscribe_events(events_in.clone());
    loop {
        if matches.is_present("events")
            && count >= value_t!(matches.value_of("events"), u32).unwrap()
        {
            return;
        };
        if matches.is_present("blocks")
            && blocks >= 1 + value_t!(matches.value_of("blocks"), u32).unwrap()
        {
            return;
        };
        let event_str = events_out.recv().unwrap();
        let _unhex = hexstr_to_vec(event_str).unwrap();
        let mut _er_enc = _unhex.as_slice();
        let _events = Vec::<frame_system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
        blocks += 1;
        match _events {
            Ok(evts) => {
                for evr in &evts {
                    debug!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
                    match &evr.event {
                        Event::encointer_ceremonies(ee) => {
                            count += 1;
                            println!(">>>>>>>>>> ceremony event: {:?}", ee);
                            match &ee {
                                encointer_ceremonies::RawEvent::ParticipantRegistered(
                                    accountid,
                                ) => {
                                    println!(
                                        "Participant registered for ceremony: {:?}",
                                        accountid
                                    );
                                }
                            }
                        }, 
                        Event::encointer_scheduler(ee) => {
                            count += 1;
                            println!(">>>>>>>>>> scheduler event: {:?}", ee);
                            match &ee {
                                encointer_scheduler::Event::PhaseChangedTo(phase) => {
                                    println!("Phase changed to: {:?}", phase);
                                }
                            }
                        }
                        Event::encointer_currencies(ee) => {
                            count += 1;
                            println!(">>>>>>>>>> currency event: {:?}", ee);
                            match &ee {
                                encointer_currencies::RawEvent::CurrencyRegistered(account, cid) => {
                                    println!("Currency registered: by {}, cid: {:?}", account, cid);
                                }
                            }
                        },
                        Event::encointer_balances(ee) => {
                            count += 1;
                            println!(">>>>>>>>>> encointer balances event: {:?}", ee);
                        },
                        _ => debug!("ignoring unsupported module event: {:?}", evr.event),
                    }
                }
            }
            Err(_) => error!("couldn't decode event record list"),
        }
    }
}

fn get_cid(cid: &str) -> CurrencyIdentifier {
    CurrencyIdentifier::decode(&mut &cid.from_base58()
        .expect("cid must be base58 encoded")[..])
        .expect("failed to decode cid")
}

fn verify_cid(api: &Api<sr25519::Pair>, cid: &str) -> CurrencyIdentifier {
    let cids = get_currency_identifiers(&api).expect("no currency registered");
    let cid = get_cid(cid);
    if !cids.contains(&cid) {
        panic!("cid {} does not exist on chain", cid.encode().to_base58());
    }
    cid
}

fn get_accountid_from_str(account: &str) -> AccountId {
    info!("getting AccountId from -{}-", account);
    match &account[..2] {
        "//" => AccountPublic::from(sr25519::Pair::from_string(account, None).unwrap().public())
            .into_account(),
        _ => AccountPublic::from(sr25519::Public::from_ss58check(account).unwrap()).into_account(),
    }
}

// get a pair either form keyring (well known keys) or from the store
fn get_pair_from_str(account: &str) -> sr25519::AppPair {
    info!("getting pair for {}", account);
    match &account[..2] {
        "//" => sr25519::AppPair::from_string(account, None).unwrap(),
        _ => {
            info!("fetching from keystore at {}", &KEYSTORE_PATH);
            // open store without password protection
            let store =
                Store::open(PathBuf::from(&KEYSTORE_PATH), None).expect("store should exist");
            info!("store opened");
            let _pair = store
                .read()
                .key_pair::<sr25519::AppPair>(
                    &sr25519::Public::from_ss58check(account).unwrap().into(),
                )
                .unwrap();
            drop(store);
            _pair
        }
    }
}

fn get_block_number(api: &Api<sr25519::Pair>) -> BlockNumber {
    let hdr: Header = api.get_header(None).unwrap();
    debug!("decoded: {:?}", hdr);
    //let hdr: Header= Decode::decode(&mut .as_bytes()).unwrap();
    hdr.number
}

fn get_demurrage_per_block(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier) -> BalanceType {
    let cp: CurrencyPropertiesType = api
        .get_storage_map("EncointerCurrencies", "CurrencyProperties", cid, None)
        .unwrap();
    debug!("CurrencyProperties are {:?}", cp);
    cp.demurrage_per_block
}

fn get_ceremony_index(api: &Api<sr25519::Pair>) -> CeremonyIndexType {
    api.get_storage_value("EncointerScheduler", "CurrentCeremonyIndex", None)
        .unwrap()
}

fn get_current_phase(api: &Api<sr25519::Pair>) -> CeremonyPhaseType {
    api.get_storage_value("EncointerScheduler", "CurrentPhase", None)
        .or(Some(CeremonyPhaseType::default()))
        .unwrap()
}

fn get_meetup_count(api: &Api<sr25519::Pair>, key: CurrencyCeremony) -> MeetupIndexType {
    api.get_storage_map("EncointerCeremonies", "MeetupCount", key, None)
        .or(Some(0))
        .unwrap()
}

fn get_participant_count(api: &Api<sr25519::Pair>, key: CurrencyCeremony) -> ParticipantIndexType {
    api.get_storage_map(
        "EncointerCeremonies",
        "ParticipantCount",
        key,
        None
    ).or(Some(0)).unwrap()
}

fn get_attestation_count(api: &Api<sr25519::Pair>, key: CurrencyCeremony) -> ParticipantIndexType {
    api.get_storage_map(
            "EncointerCeremonies",
            "AttestationCount",
            key,
            None
    ).or(Some(0)).unwrap()
}

fn get_participant(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    pindex: ParticipantIndexType,
) -> Option<AccountId> {
    api.get_storage_double_map(
        "EncointerCeremonies",
        "ParticipantRegistry",
        key,
        pindex,
        None
    )
}

fn get_meetup_index_for(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    account: &AccountId,
) -> Option<MeetupIndexType> {
    api.get_storage_double_map(
        "EncointerCeremonies",
        "MeetupIndex",
        key,
        account.clone(),
        None
    )
}

fn get_meetup_participants(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    mindex: MeetupIndexType,
) -> Option<Vec<AccountId>> {
    api.get_storage_double_map(
        "EncointerCeremonies",
        "MeetupRegistry",
        key,
        mindex,
        None
    )
}

fn get_attestations(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    windex: ParticipantIndexType,
) -> Option<Vec<AccountId>> {
    api.get_storage_double_map(
        "EncointerCeremonies",
        "AttestationRegistry",
        key,
        windex,
        None
    )
}

fn get_participant_attestation_index(
    api: &Api<sr25519::Pair>,
    key: CurrencyCeremony,
    accountid: &AccountId,
) -> Option<ParticipantIndexType> {
    api.get_storage_double_map(
        "EncointerCeremonies",
        "AttestationIndex",
        key,
        accountid,
        None
    )
}

fn new_claim_for(
    api: &Api<sr25519::Pair>,
    accountid: AccountId,
    cid: CurrencyIdentifier,
    n_participants: u32,
) -> Vec<u8> {
    let cindex = get_ceremony_index(api);
    let mindex = get_meetup_index_for(api, (cid, cindex), &accountid)
        .expect("participant must be assigned to meetup to generate a claim");

    // implicitly assume that participant meet at the right place at the right time
    let mloc = get_meetup_location(api, cid, mindex).unwrap();
    let mtime = get_meetup_time(api, cid, mindex).unwrap();

    let claim = ClaimOfAttendance::<AccountId, Moment> {
        claimant_public: accountid,
        currency_identifier: cid,
        ceremony_index: cindex,
        meetup_index: mindex,
        location: mloc,
        timestamp: mtime,
        number_of_participants_confirmed: n_participants,
    };
    claim.encode()
}

fn sign_claim(claim: ClaimOfAttendance<AccountId, Moment>, account_str: &str) -> Vec<u8> {
    info!("second call to get_pair_from_str");
    let pair = get_pair_from_str(account_str);
    let accountid = get_accountid_from_str(account_str);
    let attestation = Attestation {
        claim: claim.clone(),
        signature: Signature::from(sr25519_core::Signature::from(pair.sign(&claim.encode()))),
        public: accountid,
    };
    attestation.encode()
}

fn get_currency_identifiers(api: &Api<sr25519::Pair>) -> Option<Vec<CurrencyIdentifier>> {
    api.get_storage_value("EncointerCurrencies", "CurrencyIdentifiers", None)
}

fn get_currency_locations(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier) -> Option<Vec<Location>> {
    api.get_storage_map(
        "EncointerCurrencies",
        "Locations",
        cid,
        None
    )
}

fn get_meetup_location(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier, mindex: MeetupIndexType) -> Option<Location> {
    let locations = get_currency_locations(api, cid).or(Some(vec![])).unwrap();
    let lidx = (mindex -1) as usize;
    if lidx >= locations.len() {
        return None 
    } 
    Some(locations[lidx])
}

fn get_meetup_time(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier, mindex: MeetupIndexType) -> Option<Moment> {
    let mlocation = get_meetup_location(api, cid, mindex).unwrap();
    let mlon: f64 = mlocation.lon.lossy_into();

    let next_phase_timestamp: Moment = api.get_storage_value(
        "EncointerScheduler",
        "NextPhaseTimestamp",
        None
    ).unwrap();

    let attesting_start = match get_current_phase(api) {
        CeremonyPhaseType::ASSIGNING => next_phase_timestamp, // - next_phase_timestamp.rem(ONE_DAY),
        CeremonyPhaseType::ATTESTING => {
            let attesting_duration: Moment = api.get_storage_map(
                "EncointerScheduler",
                "PhaseDurations",
                CeremonyPhaseType::ATTESTING,
                None
            ).unwrap();
            next_phase_timestamp - attesting_duration //- next_phase_timestamp.rem(ONE_DAY)
        },
        CeremonyPhaseType::REGISTERING => panic!("ceremony phase must be ASSIGNING or ATTESTING to request meetup location.")
    };
    let mtime = (
        (attesting_start + ONE_DAY/2) as i64
        - (mlon * (ONE_DAY as f64) / 360.0) as i64
        ) as Moment; 
    debug!("meetup time at lon {}: {:?}", mlon, mtime);
    Some(mtime)
}

fn prove_attendance(
    prover: AccountId,
    cid: CurrencyIdentifier,
    cindex: CeremonyIndexType,
    attendee_str: &str,
) -> ProofOfAttendance<Signature, AccountId> {
    let msg = (prover.clone(), cindex);
    let attendee = get_pair_from_str(attendee_str);
    let attendeeid = get_accountid_from_str(attendee_str);
    debug!("generating proof of attendance for {} and cindex: {}", prover, cindex);
    debug!("signature payload is {:x?}", msg.encode());
    ProofOfAttendance {
        prover_public: prover,
        currency_identifier: cid,
        ceremony_index: cindex,
        attendee_public: attendeeid,
        attendee_signature: Signature::from(sr25519_core::Signature::from(
            attendee.sign(&msg.encode()),
        )),
    }
}

fn get_reputation(
    api: &Api<sr25519::Pair>, 
    prover: &AccountId,
    cid: CurrencyIdentifier,
    cindex: CeremonyIndexType,    
) -> Reputation {
    api.get_storage_double_map(
        "EncointerCeremonies",
        "ParticipantReputation",
        (cid, cindex),
        prover.clone(),
        None
    ).or(Some(Reputation::Unverified)).unwrap()   
}

fn apply_demurrage(entry: BalanceEntry<BlockNumber>, current_block: BlockNumber, demurrage_per_block: BalanceType) -> BalanceType {
    let elapsed_time_block_number = current_block.checked_sub(entry.last_update).unwrap();
    let elapsed_time_u32: u32 = elapsed_time_block_number.try_into().unwrap();
    let elapsed_time = BalanceType::from_num(elapsed_time_u32);
    let exponent : BalanceType = -demurrage_per_block * elapsed_time;
    debug!("demurrage per block {}, current_block {}, last {}, elapsed_blocks {}", demurrage_per_block, current_block, entry.last_update, elapsed_time);
    let exp_result : BalanceType = exp(exponent).unwrap();
    entry.principal.checked_mul(exp_result).unwrap()
}