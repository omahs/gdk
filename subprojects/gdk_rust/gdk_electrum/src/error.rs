use crate::BETxid;
use bitcoin::util::bip32::ExtendedPubKey;
use bitcoin::util::sighash;
use elements::hash_types::Txid;
use gdk_common::error::Error as CommonError;
use serde::ser::Serialize;
use std::convert::From;
use std::path::PathBuf;
use std::sync::{MutexGuard, PoisonError, RwLockReadGuard, RwLockWriteGuard};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("cannot create a new subaccount while the last one is unused")]
    AccountGapsDisallowed,

    #[error("could not parse SocketAddr `{0}`")]
    AddrParse(String),

    #[error("`asset_id` cannot be empty in Liquid")]
    AssetEmpty,

    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error(transparent)]
    Bitcoin(#[from] bitcoin::util::Error),

    #[error(transparent)]
    BitcoinBIP32Error(#[from] bitcoin::util::bip32::Error),

    #[error(transparent)]
    BitcoinConsensus(#[from] bitcoin::consensus::encode::Error),

    #[error(transparent)]
    BitcoinHashes(#[from] bitcoin::hashes::error::Error),

    #[error(transparent)]
    BitcoinHexError(#[from] bitcoin::hashes::hex::Error),

    #[error(transparent)]
    BitcoinKeyError(#[from] bitcoin::util::key::Error),

    #[error(transparent)]
    ClientError(#[from] electrum_client::Error),

    #[error(transparent)]
    Common(#[from] CommonError),

    #[error(transparent)]
    ElementsEncode(#[from] elements::encode::Error),

    #[error(transparent)]
    ElementsPset(#[from] elements::pset::Error),

    #[error("addressees cannot be empty")]
    EmptyAddressees,

    #[error(transparent)]
    Encryption(#[from] block_modes::BlockModeError),

    #[error("fee rate is below the minimum of {0}sat/kb")]
    FeeRateBelowMinimum(u64),

    #[error(transparent)]
    JSON(#[from] serde_json::error::Error),

    #[error("insufficient funds")]
    InsufficientFunds,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid amount")]
    InvalidAmount,

    #[error("invalid asset id")]
    InvalidAssetId,

    #[error("Invalid Electrum URL: {0}")]
    InvalidElectrumUrl(String),

    #[error("invalid headers")]
    InvalidHeaders,

    #[error(transparent)]
    InvalidKeyIvLength(#[from] block_modes::InvalidKeyIvLength),

    #[error("invalid mnemonic")]
    InvalidMnemonic,

    /// An invalid pin attempt. Should trigger an increment to the caller
    /// counter as after 3 consecutive wrong guesses the server will delete the
    /// corresponding key. Other errors should leave such counter unchanged.
    #[error("id_invalid_pin")]
    InvalidPin,

    #[error("invalid replacement request fields")]
    InvalidReplacementRequest,

    #[error("invalid sighash")]
    InvalidSigHash,

    #[error(transparent)]
    InvalidStringUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    InvalidStrUtf8(#[from] std::str::Utf8Error),

    #[error("invalid subaccount {0}")]
    InvalidSubaccount(u32),

    #[error("Xpubs mismatch ({0} vs {1})")]
    MismatchingXpubs(ExtendedPubKey, ExtendedPubKey),

    #[error("Master blinding key is missing but we need it")]
    MissingMasterBlindingKey,

    #[error("Mutex is poisoned: {0}")]
    MutexPoisonError(String),

    #[error("non confidential address")]
    NonConfidentialAddress,

    #[error("id_connection_failed")]
    PinError,

    #[error("PSET and Tx mismatch ({0} vs {1})")]
    PsetAndTxMismatch(Txid, Txid),

    #[error(transparent)]
    PsetBlindError(#[from] elements::pset::PsetBlindError),

    #[error("RW lock is poisoned: {0}")]
    RwLockPoisonError(String),

    #[error("Scriptpubkey not found")]
    ScriptPubkeyNotFound,

    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),

    #[error(transparent)]
    Secp256k1Zkp(#[from] elements::secp256k1_zkp::Error),

    #[error(transparent)]
    Send(#[from] std::sync::mpsc::SendError<()>),

    #[error("sendall error")]
    SendAll,

    #[error(transparent)]
    SerdeCborError(#[from] serde_cbor::error::Error),

    #[error(transparent)]
    SliceConversionError(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    StdIOError(#[from] std::io::Error),

    #[error("attempt to access the store without calling load_store first")]
    StoreNotLoaded,

    #[error("Transaction not found ({0})")]
    TxNotFound(BETxid),

    #[error(transparent)]
    UnblindError(#[from] elements::UnblindError),

    #[error("unknown call")]
    UnknownCall,

    #[error("unsupported sighash")]
    UnsupportedSigHash,

    #[error(transparent)]
    UreqError(#[from] ureq::Error),

    #[error(transparent)]
    Sighash(#[from] sighash::Error),

    #[error("wallet is not initialized")]
    WalletNotInitialized,

    #[error(
        "{}method not found: {method:?}",
        if *.in_session { "session " } else {""}
    )]
    MethodNotFound {
        method: String,
        in_session: bool,
    },

    #[error("{0} do not exist")]
    FileNotExist(PathBuf),

    #[error("{0}")]
    Generic(String),
}

pub fn fn_err(str: &str) -> impl Fn() -> Error + '_ {
    move || Error::Generic(str.into())
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(_err: std::net::AddrParseError) -> Self {
        Error::AddrParse("SocketAddr parse failure with no additional info".into())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Generic(err)
    }
}

impl<T> From<PoisonError<RwLockReadGuard<'_, T>>> for Error {
    fn from(err: PoisonError<RwLockReadGuard<'_, T>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl<T> From<PoisonError<RwLockWriteGuard<'_, T>>> for Error {
    fn from(err: PoisonError<RwLockWriteGuard<'_, T>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for Error {
    fn from(err: PoisonError<MutexGuard<'_, T>>) -> Self {
        Error::MutexPoisonError(err.to_string())
    }
}

impl Error {
    /// Convert the error to a GDK-compatible code.
    pub fn to_gdk_code(&self) -> String {
        // Unhandled error codes:
        // id_no_amount_specified
        // id_invalid_replacement_fee_rate
        // id_send_all_requires_a_single_output

        use super::Error::*;
        match *self {
            InsufficientFunds => "id_insufficient_funds",
            InvalidAddress => "id_invalid_address",
            NonConfidentialAddress => "id_nonconfidential_addresses_not",
            InvalidAmount => "id_invalid_amount",
            InvalidAssetId => "id_invalid_asset_id",
            FeeRateBelowMinimum(_) => "id_fee_rate_is_below_minimum",
            PinError => "id_connection_failed",
            InvalidPin => "id_invalid_pin",
            _ => "id_unknown",
        }
        .to_string()
    }
}
