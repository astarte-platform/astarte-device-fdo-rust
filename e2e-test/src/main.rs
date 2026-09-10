// This file is part of Astarte.
//
// Copyright 2025, 2026 SECO Mind Srl
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{self, IsTerminal};
use std::path::PathBuf;

use astarte_device_fdo::Ctx;
use astarte_device_fdo::astarte_fdo_protocol::utils::Hex;
use astarte_device_fdo::client::http::InitialClient;
use astarte_device_fdo::crypto::Crypto;
use astarte_device_fdo::crypto::software::SoftwareCrypto;
use astarte_device_fdo::di::Di;
use astarte_device_fdo::srv_info::{AstarteMod, AstarteModBuilder, SkipServiceInfo};
use astarte_device_fdo::storage::{FileStorage, Storage};
use astarte_device_fdo::to1::To1;
use astarte_device_fdo::to2::{Hello, To2};
use clap::{ArgAction, Parser, Subcommand};
use eyre::{Context, bail, eyre};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const MANUFACTURER_URL: &str = "http://127.0.0.1:8038";

const SERIAL: &str = "e626207f-5fcc-456e-b1bc-250c9c8efb47";
const MODEL: &str = "fdo-astarte";

/// Command line to run FIDO Ownership transfer
#[derive(Debug, Parser)]
#[clap(version, about)]
struct Cli {
    /// Sets the log level for the program, the `RUST_LOG` env filter variable is also supported.
    #[arg(long, global = true, default_value = "info")]
    log_level: LogLevel,

    /// Allow insecure server connections
    #[arg(long, global = true)]
    insecure_tls: bool,

    #[command(subcommand)]
    command: Command,
}

/// Log level to print to stderror
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LogLevel {
    /// Really verbose output
    Trace,
    /// Preferred level to gather additional information
    Debug,
    /// Show the operation progress
    Info,
    /// Prints only warning and error
    Warn,
    /// Only prints errors
    Error,
}

impl From<LogLevel> for tracing::Level {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }
}

#[derive(Debug, Clone, Subcommand)]
enum Command {
    /// Run FDO using a directory as storage
    PlainFs {
        /// Directory to store the FDO file
        #[arg(long, default_value = ".tmp/fdo-astarte", global = true)]
        storage: PathBuf,

        #[command(subcommand)]
        proto: Operation,
    },
    /// Use a TPM for crypto operations
    #[cfg(all(feature = "tpm", target_os = "linux"))]
    UseTpm {
        /// Directory to store the FDO file
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
        proto: Operation,
    },
}

/// Operation to perform
#[derive(Debug, Clone, Subcommand)]
enum Operation {
    /// Device initialization.
    ///
    /// Generates the device keys and ownership voucher with the manufacturing server.
    Di {
        /// URL of the manufacturing server
        #[arg(long, default_value = MANUFACTURER_URL)]
        manufacturing_url: url::Url,

        /// Serial-number for the device
        #[arg(long, default_value = SERIAL)]
        serial_no: String,

        /// Model-number of the device
        #[arg(long, default_value = MODEL)]
        model_no: String,

        /// Saves the GUID to file
        #[arg(long)]
        export_guid: Option<PathBuf>,
    },
    // Transfers ownership to the cloud.
    To {
        /// Enables or disable the Astarte module
        #[arg(long, default_value = "true", action = ArgAction::Set)]
        astarte_mod: bool,

        /// Serial-number for the device
        #[arg(long, default_value = SERIAL)]
        serial_no: String,

        /// Output the Astarte mod as JSON
        #[arg(long, default_value = "true", requires = "astarte_mod")]
        json: bool,
    },
    /// View the stored files.
    View,
}

impl Operation {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> eyre::Result<()>
    where
        C: Crypto,
        S: Storage,
    {
        match self {
            Operation::View => {
                let Some(dc) = Di::read_existing(ctx).await? else {
                    info!("device credentials missing, DI not yet completed");

                    return Ok(());
                };

                info!(?dc);
            }
            Operation::Di {
                manufacturing_url,
                serial_no,
                model_no,
                export_guid,
            } => {
                let client = InitialClient::create(manufacturing_url, ctx.tls().clone())?;

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
            Operation::To {
                astarte_mod,
                serial_no,
                json,
            } => {
                let Some(dc) = Di::read_existing(ctx).await? else {
                    bail!("device credentials missing, DI not yet completed");
                };

                if !dc.dc_active {
                    info!("device change TO already run to completion");

                    let dv = To2::<'_, AstarteModBuilder, Hello>::read_existing(ctx).await?;

                    info!(?dv, "Astarte mod already stored");

                    return Ok(());
                }

                let rv = To1::new(&dc).rv_owner(ctx).await?;

                if astarte_mod {
                    let (to2, srv_mod) = To2::create(dc, rv, &serial_no, AstarteMod::builder())?
                        .to2_change(ctx)
                        .await?;

                    info!("credentials received");

                    if json {
                        let out = serde_json::json!({
                            "base_url": srv_mod.base_url,
                            "realm": srv_mod.realm,
                            "device_id": srv_mod.device_id,
                            "secret": srv_mod.secret,
                        });

                        let stdout = io::stdout();

                        serde_json::to_writer(stdout, &out)
                            .wrap_err("couldn't print astarte info")?;
                    } else {
                        println!("{srv_mod}");
                    }

                    to2.done(ctx).await?;
                } else {
                    let (to2, ()) = To2::create(dc, rv, &serial_no, SkipServiceInfo::default())?
                        .to2_change(ctx)
                        .await?;

                    to2.done(ctx).await?;
                }
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    color_eyre::install()?;

    let is_terminal = cfg!(not(windows)) || io::stderr().is_terminal();

    let level = tracing::Level::from(cli.log_level);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(is_terminal)
                .with_writer(io::stderr),
        )
        .with(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(level.into())
                .from_env_lossy(),
        )
        .with(tracing_error::ErrorLayer::default())
        .try_init()?;

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("couldn't install crypto provider"))?;

    let tls = if cli.insecure_tls {
        astarte_device_tls::insecure::insecure().wrap_err("couldn't configure TLS")?
    } else {
        astarte_device_tls::config().wrap_err("couldn't configure TLS")?
    };

    match cli.command {
        Command::PlainFs { storage, proto } => {
            let mut storage = FileStorage::open(storage).await?;
            let mut crypto = SoftwareCrypto::create(storage.clone()).await?;
            let mut ctx = Ctx::new(&mut crypto, &mut storage, tls);
            proto.run(&mut ctx).await?;
        }
        #[cfg(all(feature = "tpm", target_os = "linux"))]
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
