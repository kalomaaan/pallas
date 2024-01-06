use pallas_addresses::Address as PallasAddress;
use pallas_crypto::{
    hash::{Hash, Hasher},
    key::ed25519,
};
use pallas_primitives::{babbage, Fragment};

use std::{collections::HashMap, ops::Deref};

use serde::{Deserialize, Serialize};

use crate::TxBuilderError;

use super::{
    AssetName, Bytes, Bytes32, Bytes64, DatumBytes, DatumHash, Hash28, PolicyId, PubKeyHash,
    PublicKey, ScriptBytes, ScriptHash, Signature, TransactionStatus, TxHash,
};

// TODO: Don't make wrapper types public
#[derive(Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct StagingTransaction {
    pub version: String,
    pub status: TransactionStatus,
    pub inputs: Option<Vec<Input>>,
    pub reference_inputs: Option<Vec<Input>>,
    pub outputs: Option<Vec<Output>>,
    pub fee: Option<u64>,
    pub mint: Option<MintAssets>,
    pub valid_from_slot: Option<u64>,
    pub invalid_from_slot: Option<u64>,
    pub network_id: Option<u8>,
    pub collateral_inputs: Option<Vec<Input>>,
    pub collateral_output: Option<Output>,
    pub disclosed_signers: Option<Vec<PubKeyHash>>,
    pub scripts: Option<HashMap<ScriptHash, Script>>,
    pub datums: Option<HashMap<DatumHash, DatumBytes>>,
    pub redeemers: Option<Redeemers>,
    pub script_data_hash: Option<Bytes32>,
    pub signature_amount_override: Option<u8>,
    pub change_address: Option<Address>,
    // pub certificates: TODO
    // pub withdrawals: TODO
    // pub updates: TODO
    // pub auxiliary_data: TODO
    // pub phase_2_valid: TODO
}

impl StagingTransaction {
    pub fn new() -> Self {
        Self {
            version: String::from("v1"),
            status: TransactionStatus::Staging,
            ..Default::default()
        }
    }

    pub fn input(mut self, input: Input) -> Self {
        let mut txins = self.inputs.unwrap_or_default();
        txins.push(input);
        self.inputs = Some(txins);
        self
    }

    pub fn remove_input(mut self, input: Input) -> Self {
        let mut txins = self.inputs.unwrap_or_default();
        txins.retain(|x| *x != input);
        self.inputs = Some(txins);
        self
    }

    pub fn reference_input(mut self, input: Input) -> Self {
        let mut ref_txins = self.reference_inputs.unwrap_or_default();
        ref_txins.push(input);
        self.reference_inputs = Some(ref_txins);
        self
    }

    pub fn remove_reference_input(mut self, input: Input) -> Self {
        let mut ref_txins = self.reference_inputs.unwrap_or_default();
        ref_txins.retain(|x| *x != input);
        self.reference_inputs = Some(ref_txins);
        self
    }

    pub fn output(mut self, output: Output) -> Self {
        let mut txouts = self.outputs.unwrap_or_default();
        txouts.push(output);
        self.outputs = Some(txouts);
        self
    }

    pub fn remove_output(mut self, index: usize) -> Self {
        let mut txouts = self.outputs.unwrap_or_default();
        txouts.remove(index);
        self.outputs = Some(txouts);
        self
    }

    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    pub fn clear_fee(mut self) -> Self {
        self.fee = None;
        self
    }

    pub fn mint_asset(
        mut self,
        policy: Hash<28>,
        name: Vec<u8>,
        amount: i64,
    ) -> Result<Self, TxBuilderError> {
        if name.len() > 32 {
            return Err(TxBuilderError::AssetNameTooLong);
        }

        let mut mint = self.mint.map(|x| x.0).unwrap_or_default();

        mint.entry(Hash28(*policy))
            .and_modify(|policy_map| {
                policy_map
                    .entry(name.clone().into())
                    .and_modify(|asset_map| {
                        *asset_map += amount;
                    })
                    .or_insert(amount);
            })
            .or_insert_with(|| {
                let mut map: HashMap<Bytes, i64> = HashMap::new();
                map.insert(name.clone().into(), amount);
                map
            });

        self.mint = Some(MintAssets(mint));

        Ok(self)
    }

    pub fn remove_mint_asset(mut self, policy: Hash<28>, name: Vec<u8>) -> Self {
        let mut mint = if let Some(mint) = self.mint {
            mint.0
        } else {
            return self;
        };

        if let Some(assets) = mint.get_mut(&Hash28(*policy)) {
            assets.remove(&name.into());
            if assets.is_empty() {
                mint.remove(&Hash28(*policy));
            }
        }

        self.mint = Some(MintAssets(mint));

        self
    }

    pub fn valid_from_slot(mut self, slot: u64) -> Self {
        self.valid_from_slot = Some(slot);
        self
    }

    pub fn clear_valid_from_slot(mut self) -> Self {
        self.valid_from_slot = None;
        self
    }

    pub fn invalid_from_slot(mut self, slot: u64) -> Self {
        self.invalid_from_slot = Some(slot);
        self
    }

    pub fn clear_invalid_from_slot(mut self) -> Self {
        self.invalid_from_slot = None;
        self
    }

    pub fn network_id(mut self, id: u8) -> Self {
        self.network_id = Some(id);
        self
    }

    pub fn clear_network_id(mut self) -> Self {
        self.network_id = None;
        self
    }

    pub fn collateral_input(mut self, input: Input) -> Self {
        let mut coll_ins = self.collateral_inputs.unwrap_or_default();
        coll_ins.push(input);
        self.collateral_inputs = Some(coll_ins);
        self
    }

    pub fn remove_collateral_input(mut self, input: Input) -> Self {
        let mut coll_ins = self.collateral_inputs.unwrap_or_default();
        coll_ins.retain(|x| *x != input);
        self.collateral_inputs = Some(coll_ins);
        self
    }

    pub fn collateral_output(mut self, output: Output) -> Self {
        self.collateral_output = Some(output);
        self
    }

    pub fn clear_collateral_output(mut self) -> Self {
        self.collateral_output = None;
        self
    }

    pub fn disclosed_signer(mut self, pub_key_hash: Hash<28>) -> Self {
        let mut disclosed_signers = self.disclosed_signers.unwrap_or_default();
        disclosed_signers.push(Hash28(*pub_key_hash));
        self.disclosed_signers = Some(disclosed_signers);
        self
    }

    pub fn remove_disclosed_signer(mut self, pub_key_hash: Hash<28>) -> Self {
        let mut disclosed_signers = self.disclosed_signers.unwrap_or_default();
        disclosed_signers.retain(|x| *x != Hash28(*pub_key_hash));
        self.disclosed_signers = Some(disclosed_signers);
        self
    }

    pub fn script(mut self, language: ScriptKind, bytes: Vec<u8>) -> Self {
        let mut scripts = self.scripts.unwrap_or_default();

        let hash = match language {
            ScriptKind::Native => Hasher::<224>::hash_tagged(bytes.as_ref(), 0),
            ScriptKind::PlutusV1 => Hasher::<224>::hash_tagged(bytes.as_ref(), 1),
            ScriptKind::PlutusV2 => Hasher::<224>::hash_tagged(bytes.as_ref(), 2),
        };

        scripts.insert(
            Hash28(*hash),
            Script {
                kind: language,
                bytes: bytes.into(),
            },
        );

        self.scripts = Some(scripts);
        self
    }

    pub fn remove_script_by_hash(mut self, script_hash: Hash<28>) -> Self {
        let mut scripts = self.scripts.unwrap_or_default();

        scripts.remove(&Hash28(*script_hash));

        self.scripts = Some(scripts);
        self
    }

    pub fn datum(mut self, datum: Vec<u8>) -> Self {
        let mut datums = self.datums.unwrap_or_default();

        let hash = Hasher::<256>::hash_cbor(&datum);

        datums.insert(Bytes32(*hash), datum.into());
        self.datums = Some(datums);
        self
    }

    pub fn remove_datum(mut self, datum: Vec<u8>) -> Self {
        let mut datums = self.datums.unwrap_or_default();

        let hash = Hasher::<256>::hash_cbor(&datum);

        datums.remove(&Bytes32(*hash));
        self.datums = Some(datums);
        self
    }

    pub fn remove_datum_by_hash(mut self, datum_hash: Hash<32>) -> Self {
        let mut datums = self.datums.unwrap_or_default();

        datums.remove(&Bytes32(*datum_hash));
        self.datums = Some(datums);
        self
    }

    pub fn add_spend_redeemer(
        mut self,
        input: Input,
        plutus_data: Vec<u8>,
        ex_units: Option<ExUnits>,
    ) -> Self {
        let mut rdmrs = self.redeemers.map(|x| x.0).unwrap_or_default();

        rdmrs.insert(
            RedeemerPurpose::Spend(input),
            (plutus_data.into(), ex_units),
        );

        self.redeemers = Some(Redeemers(rdmrs));

        self
    }

    pub fn remove_spend_redeemer(mut self, input: Input) -> Self {
        let mut rdmrs = self.redeemers.map(|x| x.0).unwrap_or_default();

        rdmrs.remove(&RedeemerPurpose::Spend(input));

        self.redeemers = Some(Redeemers(rdmrs));

        self
    }

    pub fn add_mint_redeemer(
        mut self,
        policy: Hash<28>,
        plutus_data: Vec<u8>,
        ex_units: Option<ExUnits>,
    ) -> Self {
        let mut rdmrs = self.redeemers.map(|x| x.0).unwrap_or_default();

        rdmrs.insert(
            RedeemerPurpose::Mint(Hash28(*policy)),
            (plutus_data.into(), ex_units),
        );

        self.redeemers = Some(Redeemers(rdmrs));

        self
    }

    pub fn remove_mint_redeemer(mut self, policy: Hash<28>) -> Self {
        let mut rdmrs = self.redeemers.map(|x| x.0).unwrap_or_default();

        rdmrs.remove(&RedeemerPurpose::Mint(Hash28(*policy)));

        self.redeemers = Some(Redeemers(rdmrs));

        self
    }

    // TODO: script_data_hash computation
    pub fn script_data_hash(mut self, hash: Hash<32>) -> Self {
        self.script_data_hash = Some(Bytes32(*hash));
        self
    }

    pub fn script_data_hash_compute(mut self, redeemers: Vec<pallas_primitives::alonzo::Redeemer>,datums: Option<Vec<pallas_primitives::alonzo::PlutusData>>, plutus_v1: bool) -> Self {
        let plutus_v1_costmodel: Vec<u8> = vec![161, 65, 0, 89, 1, 182, 159, 26, 0, 3, 35, 97, 25, 3, 44, 1, 1, 25, 3, 232, 25, 2, 59, 
            0, 1, 25, 3, 232, 25, 94, 113, 4, 1, 25, 3, 232, 24, 32, 26, 0, 1, 202, 118, 25, 40, 235, 4, 25, 89, 216, 24, 100, 25, 89, 
            216, 24, 100, 25, 89, 216, 24, 100, 25, 89, 216, 24, 100, 25, 89, 216, 24, 100, 25, 89, 216, 24, 100, 24, 100, 24, 100, 25, 
            89, 216, 24, 100, 25, 76, 81, 24, 32, 26, 0, 2, 172, 250, 24, 32, 25, 181, 81, 4, 26, 0, 3, 99, 21, 25, 1, 255, 0, 1, 26, 0, 
            1, 92, 53, 24, 32, 26, 0, 7, 151, 117, 25, 54, 244, 4, 2, 26, 0, 2, 255, 148, 26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 25, 3, 
            232, 25, 111, 246, 4, 2, 26, 0, 3, 189, 8, 26, 0, 3, 78, 197, 24, 62, 1, 26, 0, 16, 46, 15, 25, 49, 42, 1, 26, 0, 3, 46, 128, 
            25, 1, 165, 1, 26, 0, 2, 218, 120, 25, 3, 232, 25, 207, 6, 1, 26, 0, 1, 58, 52, 24, 32, 25, 168, 241, 24, 32, 25, 3, 232, 24, 
            32, 26, 0, 1, 58, 172, 1, 25, 225, 67, 4, 25, 3, 232, 10, 26, 0, 3, 2, 25, 24, 156, 1, 26, 0, 3, 2, 25, 24, 156, 1, 26, 0, 3, 
            32, 124, 25, 1, 217, 1, 26, 0, 3, 48, 0, 25, 1, 255, 1, 25, 204, 243, 24, 32, 25, 253, 64, 24, 32, 25, 255, 213, 24, 32, 25, 
            8, 30, 24, 32, 25, 64, 179, 24, 32, 26, 0, 1, 42, 223, 24, 32, 26, 0, 2, 255, 148, 26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 26, 
            0, 1, 15, 146, 25, 45, 167, 0, 1, 25, 234, 187, 24, 32, 26, 0, 2, 255, 148, 26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 26, 0, 2, 
            255, 148, 26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 26, 0, 12, 80, 78, 25, 119, 18, 4, 26, 0, 29, 106, 246, 26, 0, 1, 66, 91, 4, 
            26, 0, 4, 12, 102, 0, 4, 0, 26, 0, 1, 79, 171, 24, 32, 26, 0, 3, 35, 97, 25, 3, 44, 1, 1, 25, 160, 222, 24, 32, 26, 0, 3, 61, 
            118, 24, 32, 25, 121, 244, 24, 32, 25, 127, 184, 24, 32, 25, 169, 93, 24, 32, 25, 125, 247, 24, 32, 25, 149, 170, 24, 32, 26, 
            116, 246, 147, 25, 74, 31, 10, 255];

        let plutus_v2_costmodel: Vec<u8> = vec![161, 1, 152, 175, 26, 0, 3, 35, 97, 25, 3, 44, 1, 1, 25, 3, 232, 25, 2, 59, 0, 1, 25, 
            3, 232, 25, 94, 113, 4, 1, 25, 3, 232, 24, 32, 26, 0, 1, 202, 118, 25, 40, 235, 4, 25, 89, 216, 24, 100, 25, 89, 216, 24, 
            100, 25, 89, 216, 24, 100, 25, 89, 216, 24, 100, 25, 89, 216, 24, 100, 25, 89, 216, 24, 100, 24, 100, 24, 100, 25, 89, 216, 
            24, 100, 25, 76, 81, 24, 32, 26, 0, 2, 172, 250, 24, 32, 25, 181, 81, 4, 26, 0, 3, 99, 21, 25, 1, 255, 0, 1, 26, 0, 1, 92, 
            53, 24, 32, 26, 0, 7, 151, 117, 25, 54, 244, 4, 2, 26, 0, 2, 255, 148, 26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 25, 3, 232, 25, 
            111, 246, 4, 2, 26, 0, 3, 189, 8, 26, 0, 3, 78, 197, 24, 62, 1, 26, 0, 16, 46, 15, 25, 49, 42, 1, 26, 0, 3, 46, 128, 25, 1, 
            165, 1, 26, 0, 2, 218, 120, 25, 3, 232, 25, 207, 6, 1, 26, 0, 1, 58, 52, 24, 32, 25, 168, 241, 24, 32, 25, 3, 232, 24, 32, 26, 
            0, 1, 58, 172, 1, 25, 225, 67, 4, 25, 3, 232, 10, 26, 0, 3, 2, 25, 24, 156, 1, 26, 0, 3, 2, 25, 24, 156, 1, 26, 0, 3, 32, 124, 
            25, 1, 217, 1, 26, 0, 3, 48, 0, 25, 1, 255, 1, 25, 204, 243, 24, 32, 25, 253, 64, 24, 32, 25, 255, 213, 24, 32, 25, 88, 30, 
            24, 32, 25, 64, 179, 24, 32, 26, 0, 1, 42, 223, 24, 32, 26, 0, 2, 255, 148, 26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 26, 0, 1, 
            15, 146, 25, 45, 167, 0, 1, 25, 234, 187, 24, 32, 26, 0, 2, 255, 148, 26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 26, 0, 2, 255, 148, 
            26, 0, 6, 234, 120, 24, 220, 0, 1, 1, 26, 0, 17, 178, 44, 26, 0, 5, 253, 222, 0, 2, 26, 0, 12, 80, 78, 25, 119, 18, 4, 26, 0, 29, 
            06, 246, 26, 0, 1, 66, 91, 4, 26, 0, 4, 12, 102, 0, 4, 0, 26, 0, 1, 79, 171, 24, 32, 26, 0, 3, 35, 97, 25, 3, 44, 1, 1, 25, 
            60, 222, 24, 32, 26, 0, 3, 61, 118, 24, 32, 25, 121, 244, 24, 32, 25, 127, 184, 24, 32, 25, 169, 93, 24, 32, 25, 125, 247, 24, 
            32, 25, 149, 170, 24, 32, 26, 2, 35, 172, 204, 10, 26, 3, 116, 246, 147, 25, 74, 31, 10, 26, 2, 81, 94, 132, 25, 128, 179, 10];

        let mut buf = Vec::new();
        if redeemers.len() == 0 && datums.is_some() {
            buf.push(0x80);
            if let Some(d) = datums {
                let datum_bytes: [Vec<u8>; 1] = [d.encode_fragment().unwrap()];
                buf.extend(datum_bytes[0].clone());
            }
            buf.push(0xA0);
        } else {
            let redeemer_bytes: [Vec<u8>; 1] = [redeemers.encode_fragment().unwrap()];
            buf.extend(&redeemer_bytes[0]);

            if let Some(d) = datums {
                let datum_bytes: [Vec<u8>; 1] = [d.encode_fragment().unwrap()];
                buf.extend(datum_bytes[0].clone());
            }

            if plutus_v1 {
                buf.extend(plutus_v1_costmodel);
            } else {
                buf.extend(plutus_v2_costmodel);
            }
        }

        let hash: Hash<32> = Hasher::<256>::hash(buf.clone().as_ref());
        self.script_data_hash = Some(Bytes32(*hash));
        self
    }

    pub fn clear_script_data_hash(mut self) -> Self {
        self.script_data_hash = None;
        self
    }

    pub fn signature_amount_override(mut self, amount: u8) -> Self {
        self.signature_amount_override = Some(amount);
        self
    }

    pub fn clear_signature_amount_override(mut self) -> Self {
        self.signature_amount_override = None;
        self
    }

    pub fn change_address(mut self, address: PallasAddress) -> Self {
        self.change_address = Some(Address(address));
        self
    }

    pub fn clear_change_address(mut self) -> Self {
        self.change_address = None;
        self
    }
}

// TODO: Don't want our wrapper types in fields public
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Hash)]
pub struct Input {
    pub tx_hash: TxHash,
    pub txo_index: u64,
}

impl Input {
    pub fn new(tx_hash: Hash<32>, txo_index: u64) -> Self {
        Self {
            tx_hash: Bytes32(*tx_hash),
            txo_index,
        }
    }
}

// TODO: Don't want our wrapper types in fields public
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Output {
    pub address: Address,
    pub lovelace: u64,
    pub assets: Option<OutputAssets>,
    pub datum: Option<Datum>,
    pub script: Option<Script>,
}

impl Output {
    pub fn new(address: PallasAddress, lovelace: u64) -> Self {
        Self {
            address: Address(address),
            lovelace,
            assets: None,
            datum: None,
            script: None,
        }
    }

    pub fn add_asset(
        mut self,
        policy: Hash<28>,
        name: Vec<u8>,
        amount: u64,
    ) -> Result<Self, TxBuilderError> {
        if name.len() > 32 {
            return Err(TxBuilderError::AssetNameTooLong);
        }

        let mut assets = self.assets.map(|x| x.0).unwrap_or_default();

        assets
            .entry(Hash28(*policy))
            .and_modify(|policy_map| {
                policy_map
                    .entry(name.clone().into())
                    .and_modify(|asset_map| {
                        *asset_map += amount;
                    })
                    .or_insert(amount);
            })
            .or_insert_with(|| {
                let mut map: HashMap<Bytes, u64> = HashMap::new();
                map.insert(name.clone().into(), amount);
                map
            });

        self.assets = Some(OutputAssets(assets));

        Ok(self)
    }

    pub fn set_inline_datum(mut self, plutus_data: Vec<u8>) -> Self {
        self.datum = Some(Datum {
            kind: DatumKind::Inline,
            bytes: plutus_data.into(),
        });

        self
    }

    pub fn set_datum_hash(mut self, datum_hash: Hash<32>) -> Self {
        self.datum = Some(Datum {
            kind: DatumKind::Hash,
            bytes: datum_hash.to_vec().into(),
        });

        self
    }

    pub fn set_inline_script(mut self, language: ScriptKind, bytes: Vec<u8>) -> Self {
        self.script = Some(Script {
            kind: language,
            bytes: bytes.into(),
        });

        self
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
pub struct OutputAssets(HashMap<PolicyId, HashMap<AssetName, u64>>);

impl Deref for OutputAssets {
    type Target = HashMap<PolicyId, HashMap<Bytes, u64>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl OutputAssets {
    pub fn from_map(map: HashMap<PolicyId, HashMap<Bytes, u64>>) -> Self {
        Self(map)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Default)]
pub struct MintAssets(HashMap<PolicyId, HashMap<AssetName, i64>>);

impl Deref for MintAssets {
    type Target = HashMap<PolicyId, HashMap<Bytes, i64>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl MintAssets {
    pub fn new() -> Self {
        MintAssets(HashMap::new())
    }

    pub fn from_map(map: HashMap<PolicyId, HashMap<Bytes, i64>>) -> Self {
        Self(map)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ScriptKind {
    Native,
    PlutusV1,
    PlutusV2,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Script {
    pub kind: ScriptKind,
    pub bytes: ScriptBytes,
}

impl Script {
    pub fn new(kind: ScriptKind, bytes: Vec<u8>) -> Self {
        Self {
            kind,
            bytes: bytes.into(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum DatumKind {
    Hash,
    Inline,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct Datum {
    pub kind: DatumKind,
    pub bytes: DatumBytes,
}

#[derive(PartialEq, Eq, Hash, Debug)]
pub enum RedeemerPurpose {
    Spend(Input),
    Mint(PolicyId),
    // Reward TODO
    // Cert TODO
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct ExUnits {
    pub mem: u32,
    pub steps: u64,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
pub struct Redeemers(HashMap<RedeemerPurpose, (Bytes, Option<ExUnits>)>);

impl Deref for Redeemers {
    type Target = HashMap<RedeemerPurpose, (Bytes, Option<ExUnits>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Redeemers {
    pub fn from_map(map: HashMap<RedeemerPurpose, (Bytes, Option<ExUnits>)>) -> Self {
        Self(map)
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Address(pub PallasAddress);

impl Deref for Address {
    type Target = PallasAddress;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<PallasAddress> for Address {
    fn from(value: PallasAddress) -> Self {
        Self(value)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum BuilderEra {
    Babbage,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct BuiltTransaction {
    pub version: String,
    pub era: BuilderEra,
    pub status: TransactionStatus,
    pub tx_hash: TxHash,
    pub tx_bytes: Bytes,
    pub signatures: Option<HashMap<PublicKey, Signature>>,
}

impl BuiltTransaction {
    pub fn sign(mut self, secret_key: ed25519::SecretKey) -> Result<Self, TxBuilderError> {
        let pubkey: [u8; 32] = secret_key
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| TxBuilderError::MalformedKey)?;

        let signature: [u8; 64] = secret_key.sign(self.tx_hash.0).as_ref().try_into().unwrap();

        match self.era {
            BuilderEra::Babbage => {
                let mut new_sigs = self.signatures.unwrap_or_default();

                new_sigs.insert(Bytes32(pubkey), Bytes64(signature));

                self.signatures = Some(new_sigs);

                // TODO: chance for serialisation round trip issues?
                let mut tx = babbage::Tx::decode_fragment(&self.tx_bytes.0)
                    .map_err(|_| TxBuilderError::CorruptedTxBytes)?;

                let mut vkey_witnesses = tx.transaction_witness_set.vkeywitness.unwrap_or_default();

                vkey_witnesses.push(babbage::VKeyWitness {
                    vkey: Vec::from(pubkey.as_ref()).into(),
                    signature: Vec::from(signature.as_ref()).into(),
                });

                tx.transaction_witness_set.vkeywitness = Some(vkey_witnesses);

                self.tx_bytes = tx.encode_fragment().unwrap().into();
            }
        }

        Ok(self)
    }

    //for extented
    pub fn sign_extended(mut self, secret_key: ed25519::SecretKeyExtended) -> Result<Self, TxBuilderError> {
        let pubkey: [u8; 32] = secret_key
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| TxBuilderError::MalformedKey)?;

        let signature: [u8; 64] = secret_key.sign(self.tx_hash.0).as_ref().try_into().unwrap();

        match self.era {
            BuilderEra::Babbage => {
                let mut new_sigs = self.signatures.unwrap_or_default();

                new_sigs.insert(Bytes32(pubkey), Bytes64(signature));

                self.signatures = Some(new_sigs);

                // TODO: chance for serialisation round trip issues?
                let mut tx = babbage::Tx::decode_fragment(&self.tx_bytes.0)
                    .map_err(|_| TxBuilderError::CorruptedTxBytes)?;

                let mut vkey_witnesses = tx.transaction_witness_set.vkeywitness.unwrap_or_default();

                vkey_witnesses.push(babbage::VKeyWitness {
                    vkey: Vec::from(pubkey.as_ref()).into(),
                    signature: Vec::from(signature.as_ref()).into(),
                });

                tx.transaction_witness_set.vkeywitness = Some(vkey_witnesses);

                self.tx_bytes = tx.encode_fragment().unwrap().into();
            }
        }

        Ok(self)
    }

    pub fn add_signature(
        mut self,
        pub_key: ed25519::PublicKey,
        signature: [u8; 64],
    ) -> Result<Self, TxBuilderError> {
        match self.era {
            BuilderEra::Babbage => {
                let mut new_sigs = self.signatures.unwrap_or_default();

                new_sigs.insert(
                    Bytes32(
                        pub_key
                            .as_ref()
                            .try_into()
                            .map_err(|_| TxBuilderError::MalformedKey)?,
                    ),
                    Bytes64(signature),
                );

                self.signatures = Some(new_sigs);

                // TODO: chance for serialisation round trip issues?
                let mut tx = babbage::Tx::decode_fragment(&self.tx_bytes.0)
                    .map_err(|_| TxBuilderError::CorruptedTxBytes)?;

                let mut vkey_witnesses = tx.transaction_witness_set.vkeywitness.unwrap_or_default();

                vkey_witnesses.push(babbage::VKeyWitness {
                    vkey: Vec::from(pub_key.as_ref()).into(),
                    signature: Vec::from(signature.as_ref()).into(),
                });

                tx.transaction_witness_set.vkeywitness = Some(vkey_witnesses);

                self.tx_bytes = tx.encode_fragment().unwrap().into();
            }
        }

        Ok(self)
    }

    pub fn remove_signature(mut self, pub_key: ed25519::PublicKey) -> Result<Self, TxBuilderError> {
        match self.era {
            BuilderEra::Babbage => {
                let mut new_sigs = self.signatures.unwrap_or_default();

                let pk = Bytes32(
                    pub_key
                        .as_ref()
                        .try_into()
                        .map_err(|_| TxBuilderError::MalformedKey)?,
                );

                new_sigs.remove(&pk);

                self.signatures = Some(new_sigs);

                // TODO: chance for serialisation round trip issues?
                let mut tx = babbage::Tx::decode_fragment(&self.tx_bytes.0)
                    .map_err(|_| TxBuilderError::CorruptedTxBytes)?;

                let mut vkey_witnesses = tx.transaction_witness_set.vkeywitness.unwrap_or_default();

                vkey_witnesses.retain(|x| *x.vkey != pk.0.to_vec());

                tx.transaction_witness_set.vkeywitness = Some(vkey_witnesses);

                self.tx_bytes = tx.encode_fragment().unwrap().into();
            }
        }

        Ok(self)
    }
}
