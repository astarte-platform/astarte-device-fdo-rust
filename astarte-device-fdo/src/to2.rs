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

//! Transfer Ownership Protocol 2 (TO2)
//!
//! Transfer Ownership Protocol 2 (TO2) is an interaction between the Device ROE and the Owner
//! Onboarding Service where the transfer of ownership to the new Owner actually happens.

use std::marker::PhantomData;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use astarte_fdo_protocol::Error;
use astarte_fdo_protocol::error::ErrorKind;
use astarte_fdo_protocol::utils::CborBstr;
use astarte_fdo_protocol::v101::device_credentials::DeviceCredential;
use astarte_fdo_protocol::v101::eat_signature::{EAT_FDO, EAT_NONCE, EAT_UEID, EUPH_NONCE};
use astarte_fdo_protocol::v101::error::{ErrorCode, ErrorMessage, Timestamp};
use astarte_fdo_protocol::v101::key_exchange::XAKeyExchange;
use astarte_fdo_protocol::v101::ownership_voucher::OvHeader;
use astarte_fdo_protocol::v101::public_key::PublicKey;
use astarte_fdo_protocol::v101::rv_to2_addr::{RvTo2Addr, RvTo2AddrEntry};
use astarte_fdo_protocol::v101::sign_info::{EASigInfo, SigInfo};
use astarte_fdo_protocol::v101::to1::rv_redirect::RvRedirect;
use astarte_fdo_protocol::v101::to2::device_service_info::DeviceServiceInfo;
use astarte_fdo_protocol::v101::to2::device_service_info_ready::DeviceServiceInfoReady;
use astarte_fdo_protocol::v101::to2::done::Done;
use astarte_fdo_protocol::v101::to2::get_ov_next_entry::GetOvNextEntry;
use astarte_fdo_protocol::v101::to2::hello_device::HelloDevice;
use astarte_fdo_protocol::v101::to2::ov_next_entry::OvNextEntry;
use astarte_fdo_protocol::v101::to2::prove_device::ProveDevice;
use astarte_fdo_protocol::v101::to2::prove_ov_hdr::{
    ProveOvHdr, PvOvHdrPayload, PvOvHdrUnprotected,
};
use astarte_fdo_protocol::v101::{Message, NonceTo2ProveDv, NonceTo2ProveOv};
use astarte_fdo_protocol::v101::{NonceTo2SetupDv, TransportProtocol};
use coset::HeaderBuilder;
use coset::iana::EnumI64;
use tracing::{debug, error, info, instrument, warn};
use url::{Host, Url};

use crate::client::http::{AuthClient, EncryptedClient, InitialClient};
use crate::crypto::Crypto;
use crate::di::DEVICE_CREDS;
use crate::srv_info::ServiceInfoDecode;
use crate::{Ctx, Storage};

const MAX_DEVICE_MESSAGE_SIZE: u16 = 0;

#[derive(Debug)]
enum Address {
    Http(Url),
}

impl Address {
    fn http(
        idx: usize,
        acc: &mut Vec<Self>,
        schema: &'static str,
        addr: &RvTo2AddrEntry,
    ) -> Result<(), Error> {
        if addr.rv_dns().is_none() && addr.rv_ip().is_none() {
            error!(idx, "address is missing both ip and domain name");

            return Err(Error::new(
                ErrorKind::Invalid,
                "RvTo2AddrEntry missing ip and domain",
            ));
        }

        if let Some(dns) = addr.rv_dns() {
            debug!(idx, %dns, "adding dns address");

            let url =
                Url::parse(&format!("{schema}://{dns}:{}", addr.rv_port())).map_err(|err| {
                    error!(error = %err, %dns, "couldn't parse url");

                    Error::new(ErrorKind::Invalid, "RvTo2AddrEntry dns")
                })?;

            acc.push(Address::Http(url));
        }

        if let Some(ip) = addr.rv_ip() {
            let ip = IpAddr::from(*ip);

            debug!(idx, %ip, "adding ip address");

            let host: Host<String> = match ip {
                IpAddr::V4(ipv4_addr) => Host::Ipv4(ipv4_addr),
                IpAddr::V6(ipv6_addr) => Host::Ipv6(ipv6_addr),
            };

            let url =
                Url::parse(&format!("{schema}://{host}:{}", addr.rv_port())).map_err(|err| {
                    error!(error = %err, %host, "couldn't parse url");

                    Error::new(ErrorKind::Invalid, "RvTo2AddrEntry ip")
                })?;

            acc.push(Address::Http(url));
        }

        Ok(())
    }

    fn rv_to2_addr_decode(value: RvTo2Addr) -> Result<Vec<Self>, Error> {
        value
            .iter()
            .enumerate()
            .try_fold(Vec::new(), |mut acc, (idx, addr)| {
                match addr.rv_protocol() {
                    TransportProtocol::Http => {
                        Address::http(idx, &mut acc, "http", addr)?;
                    }
                    TransportProtocol::Https => {
                        Address::http(idx, &mut acc, "https", addr)?;
                    }
                    TransportProtocol::Tcp
                    | TransportProtocol::Tls
                    | TransportProtocol::CoAp
                    | TransportProtocol::CoAps => {
                        warn!(protocol = ?addr.rv_protocol(), "not supported");
                    }
                }

                Ok(acc)
            })
    }
}

const ASTARTE_MOD_PATH: &str = "astarte.mod.cbor";

/// TO2 protocol
pub struct To2<'a, D, S> {
    device_creds: DeviceCredential<'static>,
    sn: &'a str,
    service_info: D,
    state: S,
}

/// Fist state of TO2
pub struct Hello {
    rv: RvRedirect,
    addresses: Vec<Address>,
}

impl<'a, D> To2<'a, D, Hello> {
    /// Create the TO2 client
    pub fn create(
        device_creds: DeviceCredential<'static>,
        rv: RvRedirect,
        sn: &'a str,
        service_info: D,
    ) -> Result<Self, Error> {
        let addresses = rv
            .rv_to2_addr()
            .and_then(|blob| Address::rv_to2_addr_decode(blob.take_to1d_rv()))?;

        let state = Hello { rv, addresses };

        Ok(Self {
            device_creds,
            state,
            sn,
            service_info,
        })
    }

    /// Changes the owner
    pub async fn to2_change<C, S>(
        self,
        ctx: &mut Ctx<'_, C, S>,
    ) -> Result<(To2<'a, D, DvDone>, D::Output), Error>
    where
        C: Crypto,
        S: Storage,
        D: ServiceInfoDecode<'static>,
    {
        info!("To2 started");

        let prove_ov = self.run(ctx).await?;
        let verify = prove_ov.run(ctx).await?;
        let prove_dv = verify.run(ctx).await?;
        let setup = prove_dv.run(ctx).await?;
        let ready = setup.run(ctx).await?;

        ready.run(ctx).await
    }

    /// Read an already stored Astarte mod
    pub async fn read_existing<C, S>(ctx: &mut Ctx<'_, C, S>) -> Result<Option<D::Output>, Error>
    where
        S: Storage,
        D: ServiceInfoDecode<'static>,
    {
        let Some(buf) = ctx.storage.read(ASTARTE_MOD_PATH).await? else {
            return Ok(None);
        };

        ciborium::from_reader(buf.as_slice())
            .map(Some)
            .map_err(|error| {
                error!(%error, "couldn't decode Astarte mod");

                Error::new(ErrorKind::Decode, "couldn't decode Astarte mod")
            })
    }

    async fn hello<C, S>(&self, ctx: &mut Ctx<'_, C, S>) -> Result<HelloDevice<'static>, Error>
    where
        C: Crypto,
    {
        let nonce = ctx.crypto.create_nonce().map(NonceTo2ProveOv)?;

        Ok(HelloDevice::new(
            MAX_DEVICE_MESSAGE_SIZE,
            self.device_creds.dc_guid,
            nonce,
            ctx.crypto.kex_suit(),
            ctx.crypto.cipher_suite().to_i64(),
            EASigInfo(SigInfo::new(ctx.crypto.sign_info_type())),
        ))
    }

    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> Result<To2<'a, D, Prove>, Error>
    where
        C: Crypto,
    {
        for addr in &self.state.addresses {
            match addr {
                Address::Http(url) => match self.http(ctx, url).await {
                    Ok((hello_device, hdr, client)) => {
                        return Ok(To2 {
                            device_creds: self.device_creds,
                            sn: self.sn,
                            service_info: self.service_info,
                            state: Prove {
                                hello_device,
                                rv: self.state.rv,
                                hdr,
                                client,
                            },
                        });
                    }
                    Err(err) => {
                        error!(error = format!("{err:#}"), %url, "tried connecting to server");
                    }
                },
            }
        }

        Err(Error::new(
            ErrorKind::Io,
            "to connect with the ownership server",
        ))
    }

    async fn http<C, S>(
        &self,
        ctx: &mut Ctx<'_, C, S>,
        base_url: &Url,
    ) -> Result<(HelloDevice<'static>, ProveOvHdr, AuthClient), Error>
    where
        C: Crypto,
    {
        let mut client = InitialClient::create(base_url.clone(), ctx.tls.clone())?;

        let hello = self.hello(ctx).await?;

        let (pv_ov, auth) = client.send(&hello).await?;

        info!("To2.HelloDevice sent");

        Ok((hello, pv_ov, client.into_session(auth)))
    }
}

struct Prove {
    hello_device: HelloDevice<'static>,
    rv: RvRedirect,
    hdr: ProveOvHdr,
    client: AuthClient,
}

impl<'a, D> To2<'a, D, Prove> {
    async fn run<C, S>(mut self, ctx: &mut Ctx<'_, C, S>) -> Result<To2<'a, D, VerifyChain>, Error>
    where
        C: Crypto,
    {
        let payload = self.state.hdr.payload()?;
        let hdr = self.state.hdr.header()?;

        // 1. Verify with CUPH owner key
        C::verify_cose_signature(self.state.rv.to1d(), hdr.pubkey())
            .inspect_err(|_| error!("couldn't verify To1.RvRedirect.to1d signature"))?;

        info!("To2.ProveOvHdr RvRedirect verified");

        C::verify_cose_signature(self.state.hdr.sign(), hdr.pubkey())
            .inspect_err(|_| error!("couldn't verify To2.ProveOvHdr signature"))?;

        info!("To2.ProveOvHdr ProveOvHdr verified");

        // 2. Verify OVHeder against device credentials
        let mut buf = Vec::new();
        ciborium::into_writer(&payload.ov_header.ov_pub_key, &mut buf).map_err(|err| {
            error!(error = %err, "couldn't encode ov header public key");

            Error::new(ErrorKind::Encode, "ov header public key")
        })?;
        C::verify_hash(&self.device_creds.dc_pub_key_hash, &buf)
            .inspect_err(|_| error!("couldn't verify device public key hash"))?;

        info!("To2.ProveOvHdr OVPubKey verified");

        let data = payload.ov_header.bytes()?;

        ctx.crypto
            .verify_hmac(&self.device_creds.dc_hmac_secret, &payload.hmac, data)
            .await
            .inspect_err(|_| error!("couldn't verify device credentials hmac"))?;

        info!("To2.ProveOvHdr Hmac verified");

        // 3. Verify HelloDevice hash
        buf.clear();
        self.state.hello_device.encode(&mut buf)?;

        let res = C::verify_hash(&payload.hello_device_hash, &buf)
            .inspect_err(|_| error!("couldn't verify hello device hash"));

        if let Err(err) = res {
            // TODO improve timestamp
            let system_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let timestamp = Timestamp::TimeT(system_time);

            let err_msg = ErrorMessage::new(
                ErrorCode::MessageBodyError,
                ProveOvHdr::MSG_TYPE as u8,
                "failed to validate HelloDevice hash".into(),
                // Make go server client happy
                Some(timestamp),
                None,
            );

            self.state.client.send_err(&err_msg).await?;

            return Err(err);
        }

        info!("To2.ProveOvHdr HelloDevice verified");

        // 4. Create variable to validate the chain
        // let dev_chain_hash = payload
        //     .ov_header
        //     .ov_dev_cert_chain_hash
        //     .as_ref()
        //     .ok_or(Error::new(ErrorKind::Invalid, "device cert chain missing"))?
        //     .clone()
        //     .into_owned();

        Ok(To2 {
            device_creds: self.device_creds,
            sn: self.sn,
            service_info: self.service_info,
            state: VerifyChain {
                hdr,
                payload,
                full: self.state.hdr,
                // dev_chain_hash,
                client: self.state.client,
            },
        })
    }
}

struct VerifyChain {
    full: ProveOvHdr,
    payload: PvOvHdrPayload<'static>,
    hdr: PvOvHdrUnprotected<'static>,
    // TODO: do we need to check this?
    // dev_chain_hash: Hash<'static>,
    // dev_chain_hash: Hash<'static>,
    client: AuthClient,
}

impl<'a, D> To2<'a, D, VerifyChain> {
    async fn run<C, S>(mut self, ctx: &mut Ctx<'_, C, S>) -> Result<To2<'a, D, ProveDv>, Error>
    where
        C: Crypto,
    {
        let num_ov_entries = self.state.payload.num_ov_entries;

        if num_ov_entries == 0 {
            return Err(Error::new(
                ErrorKind::Invalid,
                "number of entries must be greater than 0",
            ));
        }

        debug!(num_ov_entries, "checking entries");

        // SHA[TO2.ProveOVHdr.OVHeader||TO2.ProveOVHdr.HMac] (no cbor hdr)
        let mut hash_prev_entry = self.state.payload.ov_header.bytes()?.to_vec();
        // Use the vec as writer to extend it
        ciborium::into_writer(&self.state.payload.hmac, &mut hash_prev_entry).map_err(|err| {
            error!(error = %err, "couldn't hmac");

            Error::new(ErrorKind::Encode, "Hmac")
        })?;

        // SHA[TO2.ProveOVHdr.OVHeader.Guid||TO2.ProveOVHdr.OVHeader.DeviceInfo]
        let mut hash_hdr_info = self.state.payload.ov_header.ov_guid.to_vec();
        hash_hdr_info.extend_from_slice(self.state.payload.ov_header.ov_device_info.as_bytes());

        let mut variable = Variables {
            hash_prev_entry,
            pub_key: self.state.payload.ov_header.ov_pub_key.clone(),
            hash_hdr_info,
        };

        for ov_entry_num in 0..num_ov_entries {
            let entry = self
                .state
                .client
                .send(&GetOvNextEntry::new(ov_entry_num))
                .await?;

            info!("To2.GetOvNextEntry sent");

            debug!(ov_entry_num, "entry received, validating");

            self.validate(ctx, &mut variable, entry)?;

            info!("To2.OvNextEntry validated");
        }

        // 6. If OVEntryNum == TO2.ProveOpHdr.NumOVEntries-1 then verify
        //    TO2.ProveOVHdr.pk == TO2.OVNextEntry.OVNextEntry.OVPubKey
        if variable.pub_key.key() != self.state.hdr.pubkey().key() {
            debug!(
                k1 = ?variable.pub_key,
                k2 = ?self.state.hdr.pubkey(),
                "final key mismatch"
            );

            return Err(Error::new(ErrorKind::Invalid, "final key mismatch"));
        }

        C::verify_cose_signature(self.state.full.sign(), &variable.pub_key)?;

        info!("To2.OvNextEntry chain verified");

        Ok(To2 {
            device_creds: self.device_creds,
            sn: self.sn,
            service_info: self.service_info,
            state: ProveDv {
                ov_header: self.state.payload.ov_header,
                // ow_pubkey: variable.pub_key,
                // owner_sing_info: self.state.payload.eb_sign_info,
                nonce_to2_prove_dv: self.state.hdr.nonce(),
                x_a_key_exchange: self.state.payload.x_a_key_exchange,
                client: self.state.client,
            },
        })
    }

    /// Validate an ownership voucher entry.
    ///
    /// 1. Verify signature TO2.OVNextEntry.OVEntry using variable PubKey
    /// 2. Verify variable HashHdrInfo matches TO2.OVEntry.OVEHashHdrInfo
    /// 3. Verify HashPrevEntry matches SHA[TO2.OpNextEntry.OVEntry.OVEPubKey]
    /// 4. Update variable PubKey to TO2.OVNextEntry.OVEPubKey.OVPubKey
    /// 5. Update variable HashPrevEntry to SHA[TO2.OpNextEntryPayload]
    ///
    /// Last step is done outside
    #[instrument(skip_all, fields(nbr = entry.num()))]
    fn validate<C, S>(
        &self,
        _ctx: &mut Ctx<'_, C, S>,
        variables: &mut Variables,
        entry: OvNextEntry,
    ) -> Result<(), Error>
    where
        C: Crypto,
    {
        // 1. Verify signature TO2.OVNextEntry.OVEntry using variable PubKey
        C::verify_cose_signature(entry.ov_entry().sign(), &variables.pub_key)
            .inspect_err(|_| error!("coudln't validate ov entry signature"))?;
        info!("cose signature verified");

        // 2. Verify variable HashHdrInfo matches TO2.OVEntry.OVEHashHdrInfo
        let (entry, payload) = entry.take_ov_entry().payload()?;

        C::verify_hash(payload.hdr(), &variables.hash_hdr_info)
            .inspect_err(|_| error!("couldn't validating hash hdr info"))?;
        info!("hash hdr info verified");

        // 3. Verify HashPrevEntry matches SHA[TO2.OpNextEntry.OVEntry.OVEPubKey]
        C::verify_hash(payload.prev(), &variables.hash_prev_entry)
            .inspect_err(|_| error!("coudln't validate ove pubkey hash"))?;
        info!("hash prev entry verified");

        // 4. Update variable PubKey to TO2.OVNextEntry.OVEPubKey.OVPubKey
        variables.pub_key = payload.take_pubkey();

        // 5. Update variable HashPrevEntry to SHA[TO2.OpNextEntryPayload] (this is wrong)
        // TODO: use the correct hashing of the owner public key
        // https://github.com/astarte-platform/astarte-device-fdo-rust/issues/34
        variables.hash_prev_entry = entry;

        Ok(())
    }
}

/// Variables steps:
/// - **HashPrevEntry** – hash of previous entry. The hash of the previous entry’s OVEntryPayload.
///   For the first entry, the hash is SHA[TO2.ProveOVHdr.OVHeader||TO2.ProveOVHdr.HMac]. The bstr
///   wrapping for the OVHeader is not included.
/// - **PubKey** – public key signed in previous entry (initialize with
///   TO2.ProveOVHdr.OVHeader.OVPubKey)
/// - **HashHdrInfo** – hash of GUID and DeviceInfo, compute from TO2.ProveOVHdr as:
///   SHA[TO2.ProveOVHdr.OVHeader.Guid||TO2.ProveOVHdr.OVHeader.DeviceInfo]
///   - Pad the hash text on the right with zeros to match the hash length.
struct Variables<'a> {
    hash_prev_entry: Vec<u8>,
    pub_key: PublicKey<'a>,
    hash_hdr_info: Vec<u8>,
}

struct ProveDv {
    ov_header: CborBstr<'static, OvHeader<'static>>,
    // TODO: do we need to check this?
    // ow_pubkey: PublicKey<'static>,
    // owner_sing_info: EBSigInfo<'static>,
    nonce_to2_prove_dv: NonceTo2ProveDv,
    x_a_key_exchange: XAKeyExchange<'static>,
    client: AuthClient,
}

impl<'a, D> To2<'a, D, ProveDv> {
    async fn run<C, S>(self, ctx: &mut Ctx<'_, C, S>) -> Result<To2<'a, D, Setup<C>>, Error>
    where
        C: Crypto,
    {
        let (xb, key) = ctx.crypto.key_exchange(&self.state.x_a_key_exchange)?;

        info!("To2.ProveDevice key exchange generated");

        // TODO: deduplicate
        let mut guid = vec![1u8; 17];
        guid.get_mut(1..)
            .ok_or(Error::new(
                ErrorKind::Invalid,
                "BUG: guid must be more then 1 byte",
            ))?
            .copy_from_slice(self.device_creds.dc_guid.as_ref());

        let prv_dv_payload =
            ciborium::Value::Array(vec![ciborium::Value::Bytes(xb.as_ref().to_vec())]);

        let payload = ciborium::Value::Map(vec![
            (
                EAT_NONCE.into(),
                ciborium::Value::Bytes(self.state.nonce_to2_prove_dv.0.to_vec()),
            ),
            (EAT_UEID.into(), ciborium::Value::Bytes(guid)),
            (EAT_FDO.into(), prv_dv_payload),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&payload, &mut buf).map_err(|err| {
            error!(error = %err, "coudln't encode EAT");

            Error::new(ErrorKind::Encode, "EAT")
        })?;

        let nonce_setup_dv = ctx.crypto.create_nonce().map(NonceTo2SetupDv)?;

        let unprotected = HeaderBuilder::new().value(
            EUPH_NONCE,
            ciborium::Value::Bytes(nonce_setup_dv.0.to_vec()),
        );

        let sign = ctx.crypto.cose_sign(unprotected, buf).await?;

        let prove_dv = ProveDevice::new(sign);

        Ok(To2 {
            device_creds: self.device_creds,
            sn: self.sn,
            service_info: self.service_info,
            state: Setup {
                ov_header: self.state.ov_header,
                nonce_setup_dv,
                prove_dv,
                client: self.state.client.into_encrypted(key),
                _marker: PhantomData,
                nonce_to2_prove_dv: self.state.nonce_to2_prove_dv,
            },
        })
    }
}

struct Setup<C>
where
    C: Crypto,
{
    ov_header: CborBstr<'static, OvHeader<'static>>,
    nonce_to2_prove_dv: NonceTo2ProveDv,
    nonce_setup_dv: NonceTo2SetupDv,
    prove_dv: ProveDevice,
    client: EncryptedClient,
    _marker: PhantomData<C>,
}

// TODO: check for credential reuse and send CRED_REUSE_ERROR, or actually support credential reuse
//
// https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html#credreuse
impl<'a, C, D> To2<'a, D, Setup<C>>
where
    C: Crypto,
{
    async fn run<S>(mut self, ctx: &mut Ctx<'_, C, S>) -> Result<To2<'a, D, DvReady>, Error>
    where
        C: Crypto,
    {
        let setup_dv = self
            .state
            .client
            .send_plain::<C, _>(&self.state.prove_dv)
            .await?;

        info!("To2.ProveDevice succeeded");

        let payload = setup_dv.payload()?;

        C::verify_cose_signature(setup_dv.sign(), payload.ow_pubkey())?;
        info!("To2.SetupDevice signature verified");

        if *payload.nonce() != self.state.nonce_setup_dv {
            return Err(Error::new(
                ErrorKind::Invalid,
                "mismatched setup device nonce",
            ));
        }
        info!("To2.SetupDevice nonce verified");

        info!("To2.SetupDevice done");

        // TODO credential reuse check
        let hmac = ctx
            .crypto
            .hmac(
                &self.device_creds.dc_hmac_secret,
                self.state.ov_header.bytes()?,
            )
            .await?;

        Ok(To2 {
            device_creds: self.device_creds,
            sn: self.sn,
            service_info: self.service_info,
            state: DvReady {
                dv_srv_info_ready: DeviceServiceInfoReady::new(Some(hmac), None),
                client: self.state.client,
                nonce_to2_prove_dv: self.state.nonce_to2_prove_dv,
                nonce_to2_setup_dv: self.state.nonce_setup_dv,
            },
        })
    }
}

struct DvReady {
    dv_srv_info_ready: DeviceServiceInfoReady<'static>,
    nonce_to2_prove_dv: NonceTo2ProveDv,
    nonce_to2_setup_dv: NonceTo2SetupDv,
    client: EncryptedClient,
}

impl<'a, D> To2<'a, D, DvReady> {
    async fn run<C, S>(
        mut self,
        ctx: &mut Ctx<'_, C, S>,
    ) -> Result<(To2<'a, D, DvDone>, D::Output), Error>
    where
        C: Crypto,
        D: ServiceInfoDecode<'static>,
    {
        let own_srv_info_ready = self
            .state
            .client
            .send(ctx, &self.state.dv_srv_info_ready)
            .await?;

        info!(
            srv_max = own_srv_info_ready.max_size(),
            "To2.DeviceServiceInfoReady done"
        );

        // TODO: this part should be improved
        let device_srv_info = DeviceServiceInfo::example(self.sn);

        self.service_info.reset()?;

        loop {
            info!("To2.DeviceServiceInfo started");

            let own_srv_info = self.state.client.send(ctx, &device_srv_info).await?;

            debug!(?own_srv_info, "Owner service info");

            info!(
                len = own_srv_info.service_info.len(),
                "To2.OwnerServiceInfo received"
            );

            for i in &own_srv_info.service_info {
                self.service_info.decode(i)?;
            }

            if own_srv_info.is_done {
                break;
            }
        }

        let srv_mod = self.service_info.finalize()?;

        info!("To2.OwnerServiceInfo done");

        let this = To2 {
            device_creds: self.device_creds,
            sn: self.sn,
            service_info: self.service_info,
            state: DvDone {
                nonce_to2_prove_dv: self.state.nonce_to2_prove_dv,
                nonce_to2_setup_dv: self.state.nonce_to2_setup_dv,
                client: self.state.client,
            },
        };

        Ok((this, srv_mod))
    }
}

/// Final message for the FDO
pub struct DvDone {
    nonce_to2_prove_dv: NonceTo2ProveDv,
    nonce_to2_setup_dv: NonceTo2SetupDv,
    client: EncryptedClient,
}

impl<'a, D> To2<'a, D, DvDone> {
    /// Finishes the transfer protocol.
    ///
    /// This should be called after establishing a connection with the Cloud.
    pub async fn done<C, S>(mut self, ctx: &mut Ctx<'_, C, S>) -> Result<(), Error>
    where
        C: Crypto,
        S: Storage,
    {
        let done = self
            .state
            .client
            .send(ctx, &Done::new(self.state.nonce_to2_prove_dv))
            .await?;

        // TODO: separate store credentials
        // TODO: update the hmac, rvinfo, guid, ovpubkey
        // TODO: add a message to permit multiple FDO
        // TODO: connect to astarte before chainging this
        self.device_creds.dc_active = false;

        let mut buf = Vec::new();
        ciborium::into_writer(&self.device_creds, &mut buf).map_err(|err| {
            error!(error = %err, "couldn't encode device credentials");

            Error::new(ErrorKind::Encode, "device credentials")
        })?;

        ctx.storage.overwrite(DEVICE_CREDS, &buf).await?;

        if *done.nonce() != self.state.nonce_to2_setup_dv {
            return Err(Error::new(
                ErrorKind::Invalid,
                "mismatched setup device nonce",
            ));
        }

        info!("To2.Done finished");

        Ok(())
    }
}
