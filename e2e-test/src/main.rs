// This file is part of Astarte.
//
// Copyright 2025 SECO Mind Srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use astarte_device_fdo::astarte_fdo_protocol::utils::Hex;
use astarte_device_fdo::client::Client;
use astarte_device_fdo::crypto::software::SoftwareCrypto;
use astarte_device_fdo::crypto::Crypto;
use astarte_device_fdo::di::Di;
use astarte_device_fdo::storage::{FileStorage, Storage};
use astarte_device_fdo::to1::To1;
use astarte_device_fdo::to2::To2;
use astarte_device_fdo::Ctx;
use clap::{Parser, Subcommand};
use eyre::{bail, eyre};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const MANUFACTURER_URL: &str = "http://127.0.0.1:8038";

const SERIAL: &str = "e626207f-5fcc-456e-b1bc-250c9c8efb47";
const MODEL: &str = "fdo-astarte";

#[derive(Debug, Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    PlainFs {
        #[arg(long, default_value = ".tmp/fdo-astarte")]
        storage: PathBuf,

        #[command(subcommand)]
        proto: Protocol,
    },
    #[cfg(feature = "tpm")]
    UseTpm {
        // TODO: remove
        #[arg(long, default_value = ".tmp/fdo-astarte")]
        storage: PathBuf,

        /// TPM connecting string `device:/dev/tpmrm0`
        #[arg(long)]
        tpm_connection: Option<String>,

        /// PCRs registers to measure
        ///
        /// Defaults to: 0,1,5      Firmware, Options, GPT
        ///              7          Secure Boot
        #[arg(long, default_values_t = vec![0,1,5,7])]
        pcrs: Vec<u8>,

        #[command(subcommand)]
        proto: Protocol,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum Protocol {
    Inspect,
    Di {
        #[arg(long, default_value = MANUFACTURER_URL)]
        manufacturing_url: url::Url,

        #[arg(long, default_value = SERIAL)]
        serial_no: String,

        #[arg(long, default_value = MODEL)]
        model_no: String,

        /// Saves the GUID to file
        #[arg(long)]
        export_guid: Option<PathBuf>,
    },
    To {},
}

impl Protocol {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<()>
    where
        C: Crypto,
        S: Storage,
    {
        match self {
            Protocol::Inspect => {
                let Some(dc) = Di::read_existing(ctx).await? else {
                    info!("device credentials missing, DI not yet completed");

                    return Ok(());
                };

                info!(?dc);
            }
            Protocol::Di {
                manufacturing_url,
                serial_no,
                model_no,
                export_guid,
            } => {
                let client = Client::create(manufacturing_url, ctx.tls().clone())?;

                let di = Di::create(ctx, client, &model_no, &serial_no).await?;

                let done = di.create_credentials(ctx).await?;

                info!(guid = %done.dc_guid, "device initialized");

                if let Some(path) = export_guid {
                    if let Some(dir) = path.parent() {
                        tokio::fs::create_dir_all(dir).await?;
                    }

                    let guid = Hex::new(done.dc_guid.as_ref()).to_string();
                    tokio::fs::write(&path, guid).await?;

                    info!(path = %path.display(), "guid exported");
                }
            }
            Protocol::To {} => {
                let Some(dc) = Di::read_existing(ctx).await? else {
                    bail!("device credentials missing, DI not yet completed");
                };

                if !dc.dc_active {
                    info!("device change TO already run to completion");

                    let dv = To2::read_existing(ctx).await?;

                    info!(?dv, "Astarte mod already stored");

                    return Ok(());
                }

                // TODO: this should be the same from the mfg_info
                let sn = uuid::Uuid::now_v7();

                let rv = To1::new(&dc).rv_owner(ctx).await?;

                let dv = To2::create(dc, rv, &sn.to_string())?
                    .to2_change(ctx)
                    .await?;

                info!(?dv, "credentials received")
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    color_eyre::install()?;

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive("info".parse()?)
                .from_env_lossy(),
        )
        .try_init()?;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("couldn't install crypto provider"))?;

    cfg_if::cfg_if! {
        if #[cfg(feature = "platform-tls")] {
            use rustls_platform_verifier::BuilderVerifierExt;
            let tls = rustls::ClientConfig::builder().with_platform_verifier()?.with_no_client_auth();
        } else if #[cfg(feature = "webpki-roots")] {
            let tls = rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();
        } else {
            compile_error!("select one betwee platform-tls and webpki-roots for TLS")
        }
    };

    let tls = tls;

    match cli.command {
        Command::PlainFs { storage, proto } => {
            let mut storage = FileStorage::open(storage).await?;
            let mut crypto = SoftwareCrypto::create(storage.clone()).await?;
            let mut ctx = Ctx::new(&mut crypto, &mut storage, tls);
            proto.run(&mut ctx).await?;
        }
        #[cfg(feature = "tpm")]
        Command::UseTpm {
            storage,
            tpm_connection,
            pcrs,
            proto,
        } => {
            use astarte_device_fdo::crypto::tpm::Tpm;

            let mut storage = FileStorage::open(storage).await?;
            let mut tpm = if let Some(tpm_connection) = &tpm_connection {
                Tpm::with_connection(&storage, tpm_connection, &pcrs).await?
            } else {
                Tpm::with_pcrs(&storage, &pcrs).await?
            };

            let mut ctx = Ctx::new(&mut tpm, &mut storage, tls);

            proto.run(&mut ctx).await?;
        }
    }

    Ok(())
}
