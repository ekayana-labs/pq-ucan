//! Delegations: signed, attenuable grants of authority.

use alloc::{collections::BTreeMap, string::String};

use ipld_core::{cid::Cid, ipld::Ipld};

use crate::{
    command::Command,
    crypto::{Algorithm, Signature, Signer},
    did::{Did, Resolver},
    envelope::{self, DecodeOptions, Envelope, EnvelopeError, Fields, TokenKind},
    nonce::Nonce,
    policy::Policy,
    time::{self, Expiry, Timestamp},
    Error,
};

/// The principal a delegation is about.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Subject {
    /// A specific principal, which for a root delegation is also the issuer.
    Did(Did),
    /// `null` on the wire. The subject is whatever the previous hop's was.
    /// Never valid at the root of a chain.
    Powerline,
}

impl Subject {
    /// The DID, unless this is a powerline.
    #[must_use]
    pub const fn did(&self) -> Option<&Did> {
        match self {
            Subject::Did(did) => Some(did),
            Subject::Powerline => None,
        }
    }
}

/// The signed fields of a delegation.
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationPayload {
    issuer: Did,
    audience: Did,
    subject: Subject,
    command: Command,
    policy: Policy,
    nonce: Nonce,
    meta: BTreeMap<String, Ipld>,
    not_before: Option<Timestamp>,
    expiration: Expiry,
}

impl DelegationPayload {
    /// Who signed.
    #[must_use]
    pub const fn issuer(&self) -> &Did {
        &self.issuer
    }

    /// Who receives the authority.
    #[must_use]
    pub const fn audience(&self) -> &Did {
        &self.audience
    }

    /// Whose authority it is.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.subject
    }

    /// What may be done.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    /// Under what conditions on the invocation's `args`.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The nonce.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Signed facts that carry no authority.
    #[must_use]
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.meta
    }

    /// Valid from, if bounded below.
    #[must_use]
    pub const fn not_before(&self) -> Option<Timestamp> {
        self.not_before
    }

    /// Valid until.
    #[must_use]
    pub const fn expiration(&self) -> Expiry {
        self.expiration
    }

    fn to_ipld(&self) -> Ipld {
        let mut map = BTreeMap::new();
        map.insert(
            String::from("iss"),
            Ipld::String(String::from(self.issuer.as_str())),
        );
        map.insert(
            String::from("aud"),
            Ipld::String(String::from(self.audience.as_str())),
        );
        map.insert(
            String::from("sub"),
            match &self.subject {
                Subject::Did(did) => Ipld::String(String::from(did.as_str())),
                Subject::Powerline => Ipld::Null,
            },
        );
        map.insert(
            String::from("cmd"),
            Ipld::String(String::from(self.command.as_str())),
        );
        map.insert(String::from("pol"), self.policy.to_ipld());
        map.insert(
            String::from("nonce"),
            Ipld::Bytes(self.nonce.as_bytes().to_vec()),
        );
        map.insert(
            String::from("exp"),
            match self.expiration {
                Expiry::At(at) => Ipld::Integer(i128::from(at.as_unix())),
                Expiry::Never => Ipld::Null,
            },
        );
        if let Some(nbf) = self.not_before {
            map.insert(
                String::from("nbf"),
                Ipld::Integer(i128::from(nbf.as_unix())),
            );
        }
        if !self.meta.is_empty() {
            map.insert(String::from("meta"), Ipld::Map(self.meta.clone()));
        }
        Ipld::Map(map)
    }

    fn from_ipld(payload: Ipld) -> Result<Self, Error> {
        let mut fields = Fields::new(payload)?;
        let issuer = envelope::did(fields.require("iss")?, "iss")?;
        let audience = envelope::did(fields.require("aud")?, "aud")?;
        let subject = match fields.require("sub")? {
            Ipld::Null => Subject::Powerline,
            value => Subject::Did(envelope::did(value, "sub")?),
        };
        let command = Command::parse(&envelope::text(fields.require("cmd")?, "cmd")?)?;
        let policy = Policy::from_ipld(&fields.require("pol")?)?;
        let nonce = Nonce::from(envelope::bytes(fields.require("nonce")?, "nonce")?);
        let expiration = match fields.require("exp")? {
            Ipld::Null => Expiry::Never,
            value => Expiry::At(envelope::timestamp(&value, "exp")?),
        };
        let not_before = fields
            .take("nbf")
            .map(|v| envelope::timestamp(&v, "nbf"))
            .transpose()?;
        // An empty `meta` is tolerated here because rs-ucan and the JavaScript
        // implementation always write one; invocations are stricter.
        let meta = fields
            .take("meta")
            .map(|v| envelope::map(v, "meta"))
            .transpose()?
            .unwrap_or_default();
        fields.finish()?;
        Ok(DelegationPayload {
            issuer,
            audience,
            subject,
            command,
            policy,
            nonce,
            meta,
            not_before,
            expiration,
        })
    }
}

/// A signed delegation, with the bytes it was decoded from.
#[derive(Debug, Clone)]
pub struct Delegation {
    envelope: Envelope,
    payload: DelegationPayload,
}

impl Delegation {
    /// Start building a delegation to `audience` over `subject` for
    /// `command`. The issuer is whoever signs.
    #[must_use]
    pub fn builder(
        audience: Did,
        subject: Subject,
        command: Command,
    ) -> DelegationBuilder<false, false> {
        DelegationBuilder {
            audience,
            subject,
            command,
            policy: Policy::default(),
            meta: BTreeMap::new(),
            not_before: None,
            expiry: None,
            nonce: None,
        }
    }

    /// Decode under the released specification only.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_with(bytes, DecodeOptions::STRICT)
    }

    /// Decode with the given allowances.
    pub fn decode_with(bytes: &[u8], options: DecodeOptions) -> Result<Self, Error> {
        let (envelope, payload) = Envelope::open(bytes, options)?;
        if envelope.kind() != TokenKind::Delegation {
            return Err(EnvelopeError::WrongKind {
                expected: TokenKind::Delegation,
                found: envelope.kind(),
            }
            .into());
        }
        let payload = DelegationPayload::from_ipld(payload)?;
        Ok(Delegation { envelope, payload })
    }

    /// The token bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.envelope.bytes()
    }

    /// The CID of the token bytes.
    #[must_use]
    pub const fn cid(&self) -> &Cid {
        self.envelope.cid()
    }

    /// The envelope: header, signature, signed range.
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// The signed fields.
    #[must_use]
    pub const fn payload(&self) -> &DelegationPayload {
        &self.payload
    }

    /// The algorithm that signed.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.envelope.header().algorithm()
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        self.envelope.signature()
    }

    /// Who signed.
    #[must_use]
    pub const fn issuer(&self) -> &Did {
        self.payload.issuer()
    }

    /// Who receives the authority.
    #[must_use]
    pub const fn audience(&self) -> &Did {
        self.payload.audience()
    }

    /// Whose authority it is.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        self.payload.subject()
    }

    /// What may be done.
    #[must_use]
    pub const fn command(&self) -> &Command {
        self.payload.command()
    }

    /// Conditions on the invocation's `args`.
    #[must_use]
    pub const fn policy(&self) -> &Policy {
        self.payload.policy()
    }

    /// The nonce.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        self.payload.nonce()
    }

    /// Signed facts that carry no authority.
    #[must_use]
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        self.payload.meta()
    }

    /// Valid from, if bounded below.
    #[must_use]
    pub const fn not_before(&self) -> Option<Timestamp> {
        self.payload.not_before()
    }

    /// Valid until.
    #[must_use]
    pub const fn expiration(&self) -> Expiry {
        self.payload.expiration()
    }

    /// Check the signature against the key the issuer resolves to.
    pub fn verify(&self, resolver: &impl Resolver) -> Result<(), Error> {
        let key = resolver.resolve(self.issuer())?;
        self.envelope.verify(&key)
    }

    /// Check the validity window at `now`, allowing `skew` seconds.
    pub fn check_time(&self, now: Timestamp, skew: u32) -> Result<(), Error> {
        time::check_window(self.not_before(), self.expiration(), now, skew)
    }
}

/// Builds a [`Delegation`].
///
/// The type parameters record whether an expiry and a nonce have been
/// chosen; [`DelegationBuilder::sign`] exists only once both have. Neither
/// has a default because both are decisions.
#[derive(Debug, Clone)]
pub struct DelegationBuilder<const EXPIRY: bool, const NONCE: bool> {
    audience: Did,
    subject: Subject,
    command: Command,
    policy: Policy,
    meta: BTreeMap<String, Ipld>,
    not_before: Option<Timestamp>,
    expiry: Option<Expiry>,
    nonce: Option<Nonce>,
}

impl<const EXPIRY: bool, const NONCE: bool> DelegationBuilder<EXPIRY, NONCE> {
    fn transition<const E: bool, const N: bool>(self) -> DelegationBuilder<E, N> {
        DelegationBuilder {
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            meta: self.meta,
            not_before: self.not_before,
            expiry: self.expiry,
            nonce: self.nonce,
        }
    }

    /// Conditions on the invocation's `args`. Empty by default.
    #[must_use]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Valid from `at`.
    #[must_use]
    pub fn not_before(mut self, at: Timestamp) -> Self {
        self.not_before = Some(at);
        self
    }

    /// Replace the signed facts.
    #[must_use]
    pub fn meta(mut self, meta: BTreeMap<String, Ipld>) -> Self {
        self.meta = meta;
        self
    }

    /// Add one signed fact.
    #[must_use]
    pub fn meta_entry(mut self, key: impl Into<String>, value: Ipld) -> Self {
        self.meta.insert(key.into(), value);
        self
    }
}

impl<const NONCE: bool> DelegationBuilder<false, NONCE> {
    /// Valid until `at`, inclusive.
    #[must_use]
    pub fn expires_at(mut self, at: Timestamp) -> DelegationBuilder<true, NONCE> {
        self.expiry = Some(Expiry::At(at));
        self.transition()
    }

    /// Never expires. The specification recommends against it.
    #[must_use]
    pub fn never_expires(mut self) -> DelegationBuilder<true, NONCE> {
        self.expiry = Some(Expiry::Never);
        self.transition()
    }
}

impl<const EXPIRY: bool> DelegationBuilder<EXPIRY, false> {
    /// The nonce. [`Nonce::random`] is the usual choice.
    #[must_use]
    pub fn nonce(mut self, nonce: Nonce) -> DelegationBuilder<EXPIRY, true> {
        self.nonce = Some(nonce);
        self.transition()
    }
}

impl DelegationBuilder<true, true> {
    /// Sign with `signer`, whose DID becomes the issuer.
    pub fn sign(self, signer: &impl Signer) -> Result<Delegation, Error> {
        let payload = DelegationPayload {
            issuer: signer.did(),
            audience: self.audience,
            subject: self.subject,
            command: self.command,
            policy: self.policy,
            nonce: self.nonce.unwrap_or_else(Nonce::empty),
            meta: self.meta,
            not_before: self.not_before,
            expiration: self.expiry.unwrap_or(Expiry::Never),
        };
        let envelope = Envelope::seal(signer, TokenKind::Delegation, payload.to_ipld())?;
        Ok(Delegation { envelope, payload })
    }
}
