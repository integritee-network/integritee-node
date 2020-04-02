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

//! a simplistic insecure wallet for substrate key storage as plaintext unencrypted json file

use codec::{Codec, Encode, Decode};

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
pub struct WalletEntry {
    suri: Option<String>,
    accountid: AccountId,
    pair: Option<sr25519::Pair>,
}


#[derive(Encode, Decode, Copy, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct wallet {
    keys: Vec<AnyKey>
}

impl wallet {
    pub fn store_pair_from_phrase(phrase: String, suri: Option<String>) -> Result {
        if suri.is_some() {
            if &suri.unwrap()[..2] != "//" { 
                return Err("suri must start with '//'");
            };
        };
        let pair = sr25519::Pair::from_phrase(phrase None).unwrap().0;
        let entry = WalletEntry {
            suri: suri,
            accountid: pair.Public().into(),
            pair: Some(pair),
        }: 
        keys.insert(entry);
        Ok(())
    }

    pub fn generate_new(suri: String) -> Result {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        println!("new account phrase: {}", mnemonic.phrase());
        let newpair = sr25519::Pair::from_phrase(mnemonic.phrase(), None).unwrap().0;
        println!("new account: {:?}", newpair.Public());
        let entry = WalletEntry {
            suri: suri,
            accountid: newpair.Public().into(),
            pair: Some(newpair),
        }: 
        Ok(())
    }

    pub fn get_pair_from_suri(suri: String) {
        let mut pair
        for entry in keys.iter() {

        }
    }


}

