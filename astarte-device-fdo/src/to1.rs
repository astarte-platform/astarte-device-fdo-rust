// This file is part of Astarte.
//
// Copyright 2025 SECO Mind Srl
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

//! Transfer Ownership Protocol 1 (TO1).
//!
//! Transfer Ownership Protocol 1 (TO1) finishes the rendezvous started between the New Owner and
//! the Rendezvous Server in the Transfer Ownership Protocol 0 (TO0). In this protocol, the Device
//! ROE communicates with the Rendezvous Server and obtains the IP addressing info for the
//! prospective new Owner

use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;

use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::v101::device_credentials::DeviceCredential;
use astarte_fdo_protocol::v101::eat_signature::{EAT_NONCE, EAT_UEID};
use astarte_fdo_protocol::v101::hash_hmac::Hash;
use astarte_fdo_protocol::v101::rendezvous_info::{
    RendezvousDirective, RvMediumValue, RvProtocolValue, RvVariable,
};
use astarte_fdo_protocol::v101::sign_info::EASigInfo;
use astarte_fdo_protocol::v101::sign_info::SigInfo;
use astarte_fdo_protocol::v101::to1::hello_rv::HelloRv;
use astarte_fdo_protocol::v101::to1::hello_rv_ack::HelloRvAck;
use astarte_fdo_protocol::v101::to1::prove_to_rv::ProveToRv;
use astarte_fdo_protocol::v101::to1::rv_redirect::RvRedirect;
use astarte_fdo_protocol::v101::{DnsAddress, IpAddress};
use astarte_fdo_protocol::v101::{NonceTo1Proof, Port};
use astarte_fdo_protocol::Error;
use coset::HeaderBuilder;
use tracing::{debug, error, info, instrument, warn};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::client::Client;
use crate::crypto::Crypto;
use crate::storage::Storage;
use crate::Ctx;

/// From spec example
const DEFAULT_DELAY: Duration = Duration::from_secs(120);

macro_rules! builder_replace_opt {
    ($this:ident, $field:ident, $value:expr) => {
        if $this.$field.replace($value).is_some() {
            return Err(Error::new(
                ErrorKind::Invalid,
                concat!(stringify!($field), " was overwritten"),
            ));
        }
    };
}
macro_rules! decode_rv_value {
    ($value:expr, $name:literal) => {
        ciborium::from_reader::<_, &[u8]>($value)
            .map_err(|err| {
                error!(error = %err, concat!("couldn't decode ", $name));

                Error::new(ErrorKind::Decode, $name)
            })
    };
}

// TODO missing imple https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html#rendezvous-bypass
#[derive(Debug, Default)]
struct RvDevBuilder<'a> {
    ip: Option<IpAddr>,
    dns: Option<DnsAddress<'a>>,
    port: Option<Port>,
    tls_server_cert_hash: Option<Hash<'a>>,
    tls_ca_cert_hash: Option<Hash<'a>>,
    user_input: Option<bool>,
    wifi_ssid: Option<Cow<'a, str>>,
    wifi_passwd: Option<zeroize::Zeroizing<String>>,
    medium: Option<RvMediumValue>,
    protocol: Option<RvProtocolValue>,
    delay: Option<Duration>,
    // TODO: implement this
    // bypass: Option<Bypass>,
    // external_rv: Option<Bypass>,
}

impl RvDevBuilder<'_> {
    fn try_from(value: &RendezvousDirective<'_>) -> Result<Option<Self>, Error> {
        let mut this = RvDevBuilder::default();

        for instr in value.iter() {
            match instr.rv_variable {
                RvVariable::DevOnly => {
                    debug!("device only instruction");
                }
                RvVariable::OwnerOnly => {
                    debug!("owner instruction skipping");

                    return Ok(None);
                }
                RvVariable::IPAddress => {
                    let ip: IpAddress = decode_rv_value!(instr.rv_value.as_ref(), "ip address")?;

                    let ip = ip.into();

                    builder_replace_opt!(this, ip, ip);
                }
                RvVariable::DevPort => {
                    let port: u16 = decode_rv_value!(instr.rv_value.as_ref(), "device port")?;

                    builder_replace_opt!(this, port, port);
                }
                RvVariable::OwnerPort => {
                    debug!("skipping owner port");
                }
                RvVariable::Dns => {
                    let dns: DnsAddress = decode_rv_value!(instr.rv_value.as_ref(), "dns")?;

                    builder_replace_opt!(this, dns, dns);
                }
                RvVariable::SvCertHash => {
                    let hash: Hash = decode_rv_value!(instr.rv_value.as_ref(), "server cert hash")?;

                    builder_replace_opt!(this, tls_server_cert_hash, hash);
                }
                RvVariable::ClCertHash => {
                    let hash: Hash = decode_rv_value!(instr.rv_value.as_ref(), "ca cert hash")?;

                    builder_replace_opt!(this, tls_ca_cert_hash, hash);
                }
                RvVariable::UserInput => {
                    let input: bool =
                        decode_rv_value!(instr.rv_value.as_ref(), "needs user input")?;

                    builder_replace_opt!(this, user_input, input);
                }
                RvVariable::WifiSsid => {
                    let ssid: Cow<'_, str> =
                        decode_rv_value!(instr.rv_value.as_ref(), "wifi ssid")?;

                    builder_replace_opt!(this, wifi_ssid, ssid);
                }
                RvVariable::WifiPw => {
                    let pw: String = decode_rv_value!(instr.rv_value.as_ref(), "wifi ssid")?;

                    let pw = Zeroizing::new(pw);

                    builder_replace_opt!(this, wifi_passwd, pw);
                }
                RvVariable::Medium => {
                    let medium: RvMediumValue =
                        decode_rv_value!(instr.rv_value.as_ref(), "medium")?;

                    builder_replace_opt!(this, medium, medium);
                }
                RvVariable::Protocol => {
                    let proto: RvProtocolValue =
                        decode_rv_value!(instr.rv_value.as_ref(), "protocol value")?;

                    builder_replace_opt!(this, protocol, proto);
                }
                RvVariable::Delaysec => {
                    let delay: u32 = decode_rv_value!(instr.rv_value.as_ref(), "delay")?;

                    let delay = Duration::from_secs(delay.into());

                    builder_replace_opt!(this, delay, delay);
                }
                RvVariable::Bypass | RvVariable::ExtRV => {
                    // TODO
                    warn!("rv bypass not implemented");

                    return Ok(None);
                }
            }
        }

        Ok(Some(this))
    }

    fn protocol(&self) -> RvProtocolValue {
        self.protocol.unwrap_or(RvProtocolValue::Tls)
    }

    fn delay(&self) -> Duration {
        self.delay.unwrap_or(DEFAULT_DELAY)
    }

    fn http_urls(&self) -> Result<Vec<Url>, Error> {
        let port = self.port.unwrap_or(80);

        self.get_urls("http", port)
    }

    fn https_urls(&self) -> Result<Vec<Url>, Error> {
        let port = self.port.unwrap_or(443);

        self.get_urls("https", port)
    }

    fn get_urls(&self, scheme: &'static str, port: u16) -> Result<Vec<Url>, Error> {
        if self.dns.is_none() && self.ip.is_none() {
            return Err(Error::new(ErrorKind::Invalid, "address is unset"));
        }

        let mut addrs = Vec::with_capacity(2);

        if let Some(dns) = &self.dns {
            let host = Host::Domain(dns);

            let url = Url::parse(&format!("{scheme}://{host}:{port}")).map_err(|err| {
                error!(error = %err, %dns,"couldn't parse URL");

                Error::new(ErrorKind::Invalid, "url")
            })?;

            addrs.push(url);
        }

        if let Some(ip) = &self.ip {
            let host: Host<String> = match ip {
                IpAddr::V4(ipv4_addr) => Host::Ipv4(*ipv4_addr),
                IpAddr::V6(ipv6_addr) => Host::Ipv6(*ipv6_addr),
            };

            let url = Url::parse(&format!("{scheme}://{host}:{port}")).map_err(|err| {
                error!(error = %err, %host,"couldn't parse URL");

                Error::new(ErrorKind::Invalid, "url")
            })?;

            addrs.push(url);
        }

        Ok(addrs)
    }
}

/// Transfer ownership protocol to contact the Rendezvous Server.
pub struct To1<'a, T> {
    device_creds: &'a DeviceCredential<'static>,
    state: T,
}

/// Hello message to the Rendezvous Server
pub struct Hello {}

impl<'a> To1<'a, Hello> {
    /// Create the TO1 Client
    pub fn new(device_creds: &'a DeviceCredential<'static>) -> Self {
        Self {
            device_creds,
            state: Hello {},
        }
    }

    /// Tries to retrieve the [`RvRedirect`].
    pub async fn rv_owner<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> Result<RvRedirect, Error>
    where
        C: Crypto,
        S: Storage,
    {
        let ack = self.run(ctx).await?;

        let prove = ack.run(ctx).await?;

        let addr = prove.run().await?;

        info!("To1 Done");

        Ok(addr)
    }

    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> Result<To1<'a, Ack>, Error>
    where
        C: Crypto,
    {
        let mut delay = None;

        // TODO: impl actual retry
        for _ in 0..10 {
            for i in self.device_creds.dc_rv_info.iter() {
                // Skip delay on first try
                if let Some(delay) = delay {
                    let delay = self.wait_for(delay).await?;

                    info!(seconds = delay.as_secs(), "waiting before retrying");

                    tokio::time::sleep(delay).await;
                }

                let Some(rv) = RvDevBuilder::try_from(i)? else {
                    continue;
                };

                if let Some(prove) = self.follow_instr(ctx, &rv).await? {
                    info!("To1.HelloRv done");

                    return Ok(To1 {
                        device_creds: self.device_creds,
                        state: prove,
                    });
                }

                delay.replace(rv.delay());
            }
        }

        Err(Error::new(ErrorKind::Io, "nothing matched, should retry"))
    }

    async fn follow_instr<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        rv: &RvDevBuilder<'_>,
    ) -> Result<Option<Ack>, Error>
    where
        C: Crypto,
    {
        match rv.protocol() {
            RvProtocolValue::Rest => {
                if let Some(ack) = self.http_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                if let Some(ack) = self.https_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                Ok(None)
            }
            RvProtocolValue::Http => {
                if let Some(ack) = self.http_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                Ok(None)
            }
            RvProtocolValue::Https => {
                if let Some(ack) = self.https_instr(ctx, rv).await? {
                    return Ok(Some(ack));
                }

                Ok(None)
            }
            RvProtocolValue::Tcp
            | RvProtocolValue::Tls
            | RvProtocolValue::CoapTcp
            | RvProtocolValue::CoapUdp => {
                error!("protocol not supported");

                Ok(None)
            }
        }
    }

    async fn http_instr<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        rv: &RvDevBuilder<'_>,
    ) -> Result<Option<Ack>, Error>
    where
        C: Crypto,
    {
        let urls = rv.http_urls()?;

        for url in urls {
            debug!(%url, "contacting rv");

            match self.http(ctx, url).await {
                Ok((ack, client)) => {
                    debug!(?ack, "ack received");

                    return Ok(Some(Ack {
                        client,
                        nonce: ack.nonce_to1_proof(),
                    }));
                }
                Err(err) => {
                    error!(
                        error = format!("{err:#}"),
                        "failure wile contacting rv server"
                    )
                }
            }
        }

        Ok(None)
    }

    async fn https_instr<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        rv: &RvDevBuilder<'_>,
    ) -> Result<Option<Ack>, Error>
    where
        C: Crypto,
    {
        let urls = rv.https_urls()?;

        for url in urls {
            debug!(%url, "contacting rv");

            match self.https(ctx, url).await {
                Ok((ack, client)) => {
                    debug!(?ack, "ack received");

                    return Ok(Some(Ack {
                        client,
                        nonce: ack.nonce_to1_proof(),
                    }));
                }
                Err(err) => {
                    error!(
                        error = format!("{err:#}"),
                        "failure wile contacting rv server"
                    )
                }
            }
        }

        Ok(None)
    }

    async fn http<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        url: Url,
    ) -> Result<(HelloRvAck<'static>, Client), Error>
    where
        C: Crypto,
    {
        let mut client = Client::create(url)?;

        let sg_type = ctx.crypto.sign_info_type();

        let (ack, auth) = client
            .init(&HelloRv::new(
                self.device_creds.dc_guid,
                EASigInfo(SigInfo::new(sg_type)),
            ))
            .await?;

        Ok((ack, client.set_auth(auth)))
    }

    // TODO: check the certificate validity following the spec
    async fn https<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        url: Url,
    ) -> Result<(HelloRvAck<'static>, Client), Error>
    where
        C: Crypto,
    {
        let mut client = Client::create(url)?;

        let sg_type = ctx.crypto.sign_info_type();

        let (ack, auth) = client
            .init(&HelloRv::new(
                self.device_creds.dc_guid,
                EASigInfo(SigInfo::new(sg_type)),
            ))
            .await?;

        Ok((ack, client.set_auth(auth)))
    }

    #[instrument(skip(self))]
    async fn wait_for(&self, mut delay: Duration) -> Result<Duration, Error> {
        // Use millis to produce a non empty range when approximating (secs/100)
        // random range up to 25%
        let add =
            i64::try_from(delay.as_millis().div_euclid(100).saturating_mul(25)).map_err(|err| {
                error!(error = %err, "couldn't calculate the range from delay");

                Error::new(ErrorKind::OutOfRange, "overflow")
            })?;

        let range = (-add)..add;

        if range.is_empty() {
            warn!("empty range, returning delay as is");

            return Ok(delay);
        }

        let value = rand::random_range(range);

        let add = Duration::from_millis(value.unsigned_abs());

        if value.is_negative() {
            delay -= add;
        } else {
            delay += add;
        }

        Ok(delay)
    }
}

struct Ack {
    client: Client,
    nonce: NonceTo1Proof,
}

impl<'a> To1<'a, Ack> {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> Result<To1<'a, Prove>, Error>
    where
        C: Crypto,
    {
        let nonce = self.state.nonce.0.to_vec();
        let mut guid = vec![1u8; 17];

        guid.get_mut(1..)
            .ok_or(Error::new(
                ErrorKind::Invalid,
                "BUG: guid must be more then 1 byte",
            ))?
            .copy_from_slice(self.device_creds.dc_guid.as_ref());

        let payload = ciborium::Value::Map(vec![
            (EAT_NONCE.into(), ciborium::Value::Bytes(nonce)),
            (EAT_UEID.into(), ciborium::Value::Bytes(guid)),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).map_err(|err| {
            error!(error = %err, "couldn't encode EAT");

            Error::new(ErrorKind::Encode, "EAT")
        })?;

        let sign = ctx.crypto.cose_sign(HeaderBuilder::new(), buf).await?;

        info!("To1.HelloRvAck signed");

        Ok(To1 {
            device_creds: self.device_creds,
            state: Prove {
                client: self.state.client,
                proof: ProveToRv::new(sign),
            },
        })
    }
}

struct Prove {
    client: Client,
    proof: ProveToRv,
}

impl<'a> To1<'a, Prove> {
    async fn run(mut self) -> Result<RvRedirect, Error> {
        let msg = self.state.client.send_msg(&self.state.proof).await?;

        info!("To1.ProveToRv sent");

        let addr = msg.rv_to2_addr()?;

        debug!(?addr);

        info!("To1.RVRedirect received");

        Ok(msg)
    }
}
