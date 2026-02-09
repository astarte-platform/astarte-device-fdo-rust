// This file is part of Astarte.
//
// Copyright 2025, 2026 SECO Mind Srl
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

//! Trait to store data in a persistent way.

use std::future::Future;
use std::io;
use std::path::PathBuf;

use astarte_fdo_protocol::Error;
use astarte_fdo_protocol::error::ErrorKind;
use tokio::fs::{DirBuilder, File};
use tokio::io::AsyncWriteExt;
use tracing::{error, instrument};
use zeroize::Zeroizing;

/// Stores the information used for the protocol
pub trait Storage: Send + Sync {
    /// Writes the file and marks it as immutable.
    fn write_immutable(
        &self,
        file: &str,
        content: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Creates and writes a file, errors if already exists.
    fn write(&self, file: &str, content: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;

    /// Creates and writes a file, truncates any existing one.
    fn overwrite(
        &self,
        file: &str,
        content: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Reads a files if it exists.
    fn read(&self, file: &str) -> impl Future<Output = Result<Option<Vec<u8>>, Error>> + Send;

    /// Reads a files that is a secret.
    fn read_secret(
        &self,
        file: &str,
    ) -> impl std::future::Future<Output = Result<Option<Zeroizing<Vec<u8>>>, Error>> + Send {
        async { self.read(file).await.map(|value| value.map(Zeroizing::new)) }
    }

    /// Checks if a file exists.
    fn exists(&self, file: &str) -> impl Future<Output = Result<bool, Error>> + Send;
}

/// File storage to use for the protocol
#[derive(Debug, Clone)]
pub struct FileStorage {
    dir: PathBuf,
}

impl FileStorage {
    /// Opens the directory to use as file storage
    pub async fn open(dir: PathBuf) -> io::Result<Self> {
        let mut builder = DirBuilder::new();
        builder.recursive(true);

        #[cfg(unix)]
        builder.mode(0o700);

        builder.create(&dir).await?;

        Ok(Self { dir })
    }
}

impl Storage for FileStorage {
    #[instrument(skip(self, content))]
    async fn write_immutable(&self, file: &str, content: &[u8]) -> Result<(), Error> {
        self.write(file, content).await?;

        // TODO make immutable

        Ok(())
    }

    #[instrument(skip(self, content))]
    async fn write(&self, file: &str, content: &[u8]) -> Result<(), Error> {
        let mut options = File::options();

        #[cfg(unix)]
        options.mode(0o700);

        let mut file = options
            .create_new(true)
            .write(true)
            .open(self.dir.join(file))
            .await
            .map_err(|err| {
                error!(error = %err, "couldn't create file");

                Error::new(ErrorKind::Io, "couldn't create file")
            })?;

        file.write_all(content).await.map_err(|err| {
            error!(error = %err, "couldn't write to file");

            Error::new(ErrorKind::Io, "couldn't write to file")
        })?;

        Ok(())
    }

    #[instrument(skip(self, content))]
    async fn overwrite(&self, file: &str, content: &[u8]) -> Result<(), Error> {
        let mut options = File::options();

        #[cfg(unix)]
        options.mode(0o700);

        let mut file = options
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.dir.join(file))
            .await
            .map_err(|err| {
                error!(error = %err, "couldn't create file");

                Error::new(ErrorKind::Io, "couldn't create file")
            })?;

        file.write_all(content).await.map_err(|err| {
            error!(error = %err, "couldn't write to file");

            Error::new(ErrorKind::Io, "couldn't write to file")
        })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn read(&self, file: &str) -> Result<Option<Vec<u8>>, Error> {
        match tokio::fs::read(self.dir.join(file)).await {
            Ok(file) => Ok(Some(file)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => {
                error!(error = %err, "couldn't read to file");

                Err(Error::new(ErrorKind::Io, "couldn't read to file"))
            }
        }
    }

    #[instrument(skip(self))]
    async fn exists(&self, file: &str) -> Result<bool, Error> {
        tokio::fs::try_exists(self.dir.join(file))
            .await
            .map_err(|err| {
                error!(error = %err, "couldn't stat file");

                Error::new(ErrorKind::Io, "couldn't stat to file")
            })
    }
}
