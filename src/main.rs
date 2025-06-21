use core::fmt;
use std::{fs, io, path::PathBuf};

use clap::Parser;
use cli_helper::ReportResult;
use openssl::{
    base64,
    bn::{BigNum, BigNumContext},
    ec::{EcGroupRef, EcKey, PointConversionForm},
    nid::Nid,
    sha::sha1,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Jwk {
    kid: String,
    r#use: String,
    kty: String,
    alg: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Parser)]
#[command(name = "ec-to-jwk")]
/// Convert an elliptic curve public key to a JWK.
struct Cli {
    /// Path to the public key PEM.
    pub key: PathBuf,
}

fn main() -> ReportResult<()> {
    let cli = Cli::parse();

    let public_key_pem = fs::read(cli.key).map_err(|source| Error {
        kind: ErrorKind::ReadKeyFile { source },
    })?;

    let key = EcKey::public_key_from_pem(&public_key_pem).map_err(|source| Error {
        kind: ErrorKind::ParsePublicKey { source },
    })?;

    let mut ctx = BigNumContext::new().map_err(|source| Error {
        kind: ErrorKind::CreateBigNumber { source },
    })?;
    let mut x = BigNum::new().map_err(|source| Error {
        kind: ErrorKind::CreateBigNumber { source },
    })?;
    let mut y = BigNum::new().map_err(|source| Error {
        kind: ErrorKind::CreateBigNumber { source },
    })?;

    key.public_key()
        .affine_coordinates(key.group(), &mut x, &mut y, &mut ctx)
        .map_err(|source| Error {
            kind: ErrorKind::ExtractCoordinates { source },
        })?;

    let base64_x = url_encode_base64(&base64::encode_block(&x.to_vec()));
    let base64_y = url_encode_base64(&base64::encode_block(&y.to_vec()));

    let hash = sha1(
        key.public_key()
            .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
            .map_err(|source| Error {
                kind: ErrorKind::GetBytes { source },
            })?
            .as_slice(),
    );
    let hash_base64 = url_encode_base64(&base64::encode_block(&hash));

    let jwk = Jwk {
        x: base64_x,
        y: base64_y,
        kty: "EC".to_string(),
        alg: "ES256".to_string(),
        crv: group_to_curve(key.group()).unwrap_or("Unknown".to_string()),
        kid: hash_base64,
        r#use: "sig".to_string(),
    };

    let json = serde_json::to_string_pretty(&jwk).map_err(|source| Error {
        kind: ErrorKind::Serialize { source },
    })?;

    println!("{json}");

    Ok(())
}

fn group_to_curve(group: &EcGroupRef) -> Option<String> {
    match group.curve_name()? {
        Nid::X9_62_PRIME256V1 => Some("P-256".to_string()),
        _ => None,
    }
}

fn url_encode_base64(base64: &str) -> String {
    base64.replace('+', "-").replace('/', "_").replace('=', "")
}

#[derive(Debug)]
#[non_exhaustive]
struct Error {
    pub kind: ErrorKind,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error converting elliptic curve public key to a JWK")
    }
}
impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.kind)
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    #[non_exhaustive]
    ReadKeyFile { source: io::Error },

    #[non_exhaustive]
    ParsePublicKey { source: openssl::error::ErrorStack },

    #[non_exhaustive]
    CreateBigNumber { source: openssl::error::ErrorStack },

    #[non_exhaustive]
    ExtractCoordinates { source: openssl::error::ErrorStack },

    #[non_exhaustive]
    GetBytes { source: openssl::error::ErrorStack },

    #[non_exhaustive]
    Serialize { source: serde_json::Error },
}
impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::ReadKeyFile { .. } => write!(f, "could not read public key file"),
            Self::ParsePublicKey { .. } => write!(f, "could not parse public key"),
            Self::CreateBigNumber { .. } => write!(f, "could not create a BigNumber"),
            Self::ExtractCoordinates { .. } => write!(f, "could not extract curve co-ordinates"),
            Self::GetBytes { .. } => write!(f, "Could not convert the public key to bytes"),
            Self::Serialize { .. } => write!(f, "could not serialize JWK"),
        }
    }
}
impl core::error::Error for ErrorKind {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self {
            Self::ReadKeyFile { source, .. } => Some(source),
            Self::ParsePublicKey { source, .. } => Some(source),
            Self::CreateBigNumber { source, .. } => Some(source),
            Self::ExtractCoordinates { source, .. } => Some(source),
            Self::GetBytes { source, .. } => Some(source),
            Self::Serialize { source, .. } => Some(source),
        }
    }
}
