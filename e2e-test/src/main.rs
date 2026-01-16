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
                let client = Client::create(manufacturing_url)?;

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

                let _rv = To1::new(&dc).rv_owner(ctx).await?;
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

    match cli.command {
        Command::PlainFs { storage, proto } => {
            let mut storage = FileStorage::open(storage).await?;

            let mut crypto = SoftwareCrypto::create(storage.clone()).await?;

            let mut ctx = Ctx::new(&mut crypto, &mut storage);

            proto.run(&mut ctx).await?;
        }
    }

    Ok(())
}
