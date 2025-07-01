use std::{fs, path::PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use clap::{Parser, Subcommand};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcKey, EcKeyRef, PointConversionForm},
    nid::Nid,
    pkey::{PKey, Private, Public},
    rsa::{Rsa, RsaRef},
    sha::sha256,
};
use serde::{Deserialize, Serialize};
use ts_rust_helper::error::{IntoErrorReport, Report, ReportResult, ReportStyle};

#[derive(Debug, Parser)]
#[command(name = "pem-params")]
/// Extract the parameters from a PEM file
struct Cli {
    /// The PEM key type
    #[clap(subcommand)]
    pub key_type: KeyType,
}

#[derive(Debug, Subcommand)]
enum KeyType {
    Private {
        /// Path to the private key PEM.
        key: PathBuf,
    },
    Public {
        /// Path to the public key PEM.
        key: PathBuf,
    },
}

fn main() -> ReportResult<'static, ()> {
    let cli = Cli::parse();

    match cli.key_type {
        KeyType::Private { key } => {
            let pem = fs::read(key).into_report(ReportStyle::Coloured, "read PEM file")?;
            let key =
                PKey::private_key_from_pem(&pem).into_report(ReportStyle::Coloured, "parse PEM")?;

            if let Ok(ec_key) = key.ec_key() {
                unimplemented!("The key id {:?} is not implemented", key.id())
            } else if let Ok(rsa_key) = key.rsa() {
                let output = RsaOutput::try_from(rsa_key.as_ref())?;
                let json = serde_json::to_string_pretty(&output)
                    .into_report(ReportStyle::Coloured, "serialize output")?;
                println!("{json}");
            } else {
                unimplemented!("The key id {:?} is not implemented", key.id())
            }
        }
        KeyType::Public { key } => {
            let pem = fs::read(key).into_report(ReportStyle::Coloured, "read PEM file")?;
            let key =
                PKey::public_key_from_pem(&pem).into_report(ReportStyle::Coloured, "parse PEM")?;

            if let Ok(ec_key) = key.ec_key() {
                let output = EcOutput::try_from(ec_key.as_ref())?;
                let json = serde_json::to_string_pretty(&output)
                    .into_report(ReportStyle::Coloured, "serialize output")?;
                println!("{json}");
            } else if let Ok(rsa_key) = key.rsa() {
                let output = RsaOutput::try_from(rsa_key.as_ref())?;
                let json = serde_json::to_string_pretty(&output)
                    .into_report(ReportStyle::Coloured, "serialize output")?;
                println!("{json}");
            } else {
                unimplemented!("The key id {:?} is not implemented", key.id())
            }
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EcOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    x: String,
    y: String,
    kid: String,
    crv: String,
    kty: String,
    alg: String,
}

impl TryFrom<&EcKeyRef<Public>> for EcOutput {
    type Error = Report<'static>;

    fn try_from(key: &EcKeyRef<Public>) -> Result<Self, Self::Error> {
        let mut ctx =
            BigNumContext::new().into_report(ReportStyle::Coloured, "create big number")?;
        let mut x = BigNum::new().into_report(ReportStyle::Coloured, "create big number")?;
        let mut y = BigNum::new().into_report(ReportStyle::Coloured, "create big number")?;

        key.public_key()
            .affine_coordinates(key.group(), &mut x, &mut y, &mut ctx)
            .into_report(ReportStyle::Coloured, "extract coordinates")?;

        let base64_x = Base64UrlUnpadded::encode_string(&x.to_vec());
        let base64_y = Base64UrlUnpadded::encode_string(&y.to_vec());

        let hash = sha256(
            key.public_key()
                .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut ctx)
                .into_report(ReportStyle::Coloured, "get key bytes")?
                .as_slice(),
        );
        let hash_base64 = Base64UrlUnpadded::encode_string(&hash);

        let crv = match key
            .group()
            .curve_name()
            .into_report(ReportStyle::Coloured, "get curve name")?
        {
            Nid::X9_62_PRIME256V1 => Some("P-256"), // TODO
            _ => None,
        };

        Ok(EcOutput {
            d: None,
            x: base64_x,
            y: base64_y,
            kty: "EC".to_string(),
            alg: "ES256".to_string(), // TODO
            crv: crv.unwrap_or("Unknown").to_string(),
            kid: hash_base64,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RsaOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    d: Option<String>,
    n: String,
    e: String,
    kid: String,
    kty: String,
    alg: String,
}

impl TryFrom<&RsaRef<Public>> for RsaOutput {
    type Error = Report<'static>;

    fn try_from(key: &RsaRef<Public>) -> Result<Self, Self::Error> {
        let base64_n = Base64UrlUnpadded::encode_string(&key.n().to_vec());
        let base64_e = Base64UrlUnpadded::encode_string(&key.e().to_vec());

        let mut bytes = vec![];
        bytes.extend_from_slice(&key.n().to_vec());
        bytes.extend_from_slice(&key.e().to_vec());
        let hash = sha256(&bytes);
        let hash_base64 = Base64UrlUnpadded::encode_string(&hash);

        Ok(RsaOutput {
            d: None,
            n: base64_n,
            e: base64_e,
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            kid: hash_base64,
        })
    }
}
impl TryFrom<&RsaRef<Private>> for RsaOutput {
    type Error = Report<'static>;

    fn try_from(key: &RsaRef<Private>) -> Result<Self, Self::Error> {
        let base64_n = Base64UrlUnpadded::encode_string(&key.n().to_vec());
        let base64_e = Base64UrlUnpadded::encode_string(&key.e().to_vec());
        let base64_d = Base64UrlUnpadded::encode_string(&key.d().to_vec());

        let mut bytes = vec![];
        bytes.extend_from_slice(&key.n().to_vec());
        bytes.extend_from_slice(&key.e().to_vec());
        bytes.extend_from_slice(&key.d().to_vec());
        let hash = sha256(&bytes);
        let hash_base64 = Base64UrlUnpadded::encode_string(&hash);

        Ok(RsaOutput {
            d: Some(base64_d),
            n: base64_n,
            e: base64_e,
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            kid: hash_base64,
        })
    }
}
