//! Invocations: signed requests to exercise delegated authority.

use alloc::{collections::BTreeMap, string::String, vec::Vec};

use ipld_core::{cid::Cid, ipld::Ipld};

use crate::{
    cid, codec,
    command::Command,
    crypto::{Algorithm, Signature, Signer},
    did::{Did, Resolver},
    envelope::{self, DecodeOptions, Envelope, EnvelopeError, Fields, TokenKind},
    error::PayloadError,
    nonce::Nonce,
    time::{self, Expiry, Timestamp},
    Error,
};

/// The signed fields of an invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct InvocationPayload {
    issuer: Did,
    subject: Did,
    audience: Option<Did>,
    command: Command,
    args: BTreeMap<String, Ipld>,
    proofs: Vec<Cid>,
    meta: BTreeMap<String, Ipld>,
    nonce: Nonce,
    expiration: Expiry,
    issued_at: Option<Timestamp>,
    cause: Option<Cid>,
}

impl InvocationPayload {
    /// Who is invoking.
    #[must_use]
    pub const fn issuer(&self) -> &Did {
        &self.issuer
    }

    /// Whose authority is being exercised.
    #[must_use]
    pub const fn subject(&self) -> &Did {
        &self.subject
    }

    /// The intended executor when it is not the subject.
    #[must_use]
    pub const fn audience(&self) -> Option<&Did> {
        self.audience.as_ref()
    }

    /// Who should execute: the audience if given, else the subject.
    #[must_use]
    pub fn executor(&self) -> &Did {
        self.audience.as_ref().unwrap_or(&self.subject)
    }

    /// What to do.
    #[must_use]
    pub const fn command(&self) -> &Command {
        &self.command
    }

    /// With what.
    #[must_use]
    pub const fn args(&self) -> &BTreeMap<String, Ipld> {
        &self.args
    }

    /// The delegation chain, root first.
    #[must_use]
    pub fn proofs(&self) -> &[Cid] {
        &self.proofs
    }

    /// Unsigned-authority metadata.
    #[must_use]
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        &self.meta
    }

    /// The nonce; empty for idempotent commands.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// When the request times out.
    #[must_use]
    pub const fn expiration(&self) -> Expiry {
        self.expiration
    }

    /// The invoker's claim of when it was issued. Not to be trusted.
    #[must_use]
    pub const fn issued_at(&self) -> Option<Timestamp> {
        self.issued_at
    }

    /// The receipt that enqueued this task, if any.
    #[must_use]
    pub const fn cause(&self) -> Option<&Cid> {
        self.cause.as_ref()
    }

    fn to_ipld(&self) -> Ipld {
        let text = |s: &str| Ipld::String(String::from(s));
        let mut map = BTreeMap::new();
        map.insert(String::from("iss"), text(self.issuer.as_str()));
        map.insert(String::from("sub"), text(self.subject.as_str()));
        if let Some(aud) = &self.audience {
            map.insert(String::from("aud"), text(aud.as_str()));
        }
        map.insert(String::from("cmd"), text(self.command.as_str()));
        map.insert(String::from("args"), Ipld::Map(self.args.clone()));
        map.insert(
            String::from("prf"),
            Ipld::List(self.proofs.iter().copied().map(Ipld::Link).collect()),
        );
        if !self.meta.is_empty() {
            map.insert(String::from("meta"), Ipld::Map(self.meta.clone()));
        }
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
        if let Some(iat) = self.issued_at {
            map.insert(
                String::from("iat"),
                Ipld::Integer(i128::from(iat.as_unix())),
            );
        }
        if let Some(cause) = self.cause {
            map.insert(String::from("cause"), Ipld::Link(cause));
        }
        Ipld::Map(map)
    }

    fn from_ipld(payload: Ipld) -> Result<Self, Error> {
        let mut fields = Fields::new(payload)?;
        let issuer = envelope::did(fields.require("iss")?, "iss")?;
        let subject = envelope::did(fields.require("sub")?, "sub")?;
        let audience = fields
            .take("aud")
            .map(|v| envelope::did(v, "aud"))
            .transpose()?;
        if audience
            .as_ref()
            .is_some_and(|aud| aud.same_principal(&subject))
        {
            return Err(PayloadError::Forbidden("aud").into());
        }
        let command = Command::parse(&envelope::text(fields.require("cmd")?, "cmd")?)?;
        let args = envelope::map(fields.require("args")?, "args")?;
        let proofs = envelope::list(fields.require("prf")?, "prf")?
            .into_iter()
            .map(|v| envelope::link(&v, "prf"))
            .collect::<Result<Vec<_>, _>>()?;
        let meta = fields
            .take("meta")
            .map(|v| envelope::map(v, "meta"))
            .transpose()?;
        if meta.as_ref().is_some_and(BTreeMap::is_empty) {
            return Err(PayloadError::Forbidden("meta").into());
        }
        let nonce = Nonce::from(envelope::bytes(fields.require("nonce")?, "nonce")?);
        let expiration = match fields.require("exp")? {
            Ipld::Null => Expiry::Never,
            value => Expiry::At(envelope::timestamp(&value, "exp")?),
        };
        let issued_at = fields
            .take("iat")
            .map(|v| envelope::timestamp(&v, "iat"))
            .transpose()?;
        let cause = fields
            .take("cause")
            .map(|v| envelope::link(&v, "cause"))
            .transpose()?;
        fields.finish()?;
        Ok(InvocationPayload {
            issuer,
            subject,
            audience,
            command,
            args,
            proofs,
            meta: meta.unwrap_or_default(),
            nonce,
            expiration,
            issued_at,
            cause,
        })
    }
}

/// A signed invocation, with the bytes it was decoded from.
#[derive(Debug, Clone)]
pub struct Invocation {
    envelope: Envelope,
    payload: InvocationPayload,
}

impl Invocation {
    /// Start building an invocation of `command` on `subject`. The issuer
    /// is whoever signs.
    #[must_use]
    pub fn builder(subject: Did, command: Command) -> InvocationBuilder<false, false> {
        InvocationBuilder {
            subject,
            command,
            audience: None,
            args: BTreeMap::new(),
            proofs: Vec::new(),
            meta: BTreeMap::new(),
            issued_at: None,
            cause: None,
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
        if envelope.kind() != TokenKind::Invocation {
            return Err(EnvelopeError::WrongKind {
                expected: TokenKind::Invocation,
                found: envelope.kind(),
            }
            .into());
        }
        let payload = InvocationPayload::from_ipld(payload)?;
        Ok(Invocation { envelope, payload })
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
    pub const fn payload(&self) -> &InvocationPayload {
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

    /// Who is invoking.
    #[must_use]
    pub const fn issuer(&self) -> &Did {
        self.payload.issuer()
    }

    /// Whose authority is being exercised.
    #[must_use]
    pub const fn subject(&self) -> &Did {
        self.payload.subject()
    }

    /// The intended executor when it is not the subject.
    #[must_use]
    pub const fn audience(&self) -> Option<&Did> {
        self.payload.audience()
    }

    /// Who should execute.
    #[must_use]
    pub fn executor(&self) -> &Did {
        self.payload.executor()
    }

    /// What to do.
    #[must_use]
    pub const fn command(&self) -> &Command {
        self.payload.command()
    }

    /// With what.
    #[must_use]
    pub const fn args(&self) -> &BTreeMap<String, Ipld> {
        self.payload.args()
    }

    /// The delegation chain, root first.
    #[must_use]
    pub fn proofs(&self) -> &[Cid] {
        self.payload.proofs()
    }

    /// Unsigned-authority metadata.
    #[must_use]
    pub const fn meta(&self) -> &BTreeMap<String, Ipld> {
        self.payload.meta()
    }

    /// The nonce.
    #[must_use]
    pub const fn nonce(&self) -> &Nonce {
        self.payload.nonce()
    }

    /// When the request times out.
    #[must_use]
    pub const fn expiration(&self) -> Expiry {
        self.payload.expiration()
    }

    /// The invoker's claim of when it was issued.
    #[must_use]
    pub const fn issued_at(&self) -> Option<Timestamp> {
        self.payload.issued_at()
    }

    /// The receipt that enqueued this task, if any.
    #[must_use]
    pub const fn cause(&self) -> Option<&Cid> {
        self.payload.cause()
    }

    /// The task ID: the CID of `{sub, cmd, args, nonce}`. Equal for
    /// invocations that request the same work.
    pub fn task_id(&self) -> Result<Cid, Error> {
        let text = |s: &str| Ipld::String(String::from(s));
        let mut map = BTreeMap::new();
        map.insert(String::from("sub"), text(self.subject().as_str()));
        map.insert(String::from("cmd"), text(self.command().as_str()));
        map.insert(String::from("args"), Ipld::Map(self.args().clone()));
        map.insert(
            String::from("nonce"),
            Ipld::Bytes(self.nonce().as_bytes().to_vec()),
        );
        Ok(cid::of_dag_cbor(&codec::encode(&Ipld::Map(map))?))
    }

    /// Check the signature against the key the issuer resolves to.
    pub fn verify(&self, resolver: &impl Resolver) -> Result<(), Error> {
        let key = resolver.resolve(self.issuer())?;
        self.envelope.verify(&key)
    }

    /// Check the expiry at `now`, allowing `skew` seconds.
    pub fn check_time(&self, now: Timestamp, skew: u32) -> Result<(), Error> {
        time::check_window(None, self.expiration(), now, skew)
    }
}

/// Builds an [`Invocation`].
///
/// As with delegations, an expiry and a nonce must be chosen before
/// [`InvocationBuilder::sign`] is available. An empty nonce is the right
/// choice for idempotent commands and must be asked for.
#[derive(Debug, Clone)]
pub struct InvocationBuilder<const EXPIRY: bool, const NONCE: bool> {
    subject: Did,
    command: Command,
    audience: Option<Did>,
    args: BTreeMap<String, Ipld>,
    proofs: Vec<Cid>,
    meta: BTreeMap<String, Ipld>,
    issued_at: Option<Timestamp>,
    cause: Option<Cid>,
    expiry: Option<Expiry>,
    nonce: Option<Nonce>,
}

impl<const EXPIRY: bool, const NONCE: bool> InvocationBuilder<EXPIRY, NONCE> {
    fn transition<const E: bool, const N: bool>(self) -> InvocationBuilder<E, N> {
        InvocationBuilder {
            subject: self.subject,
            command: self.command,
            audience: self.audience,
            args: self.args,
            proofs: self.proofs,
            meta: self.meta,
            issued_at: self.issued_at,
            cause: self.cause,
            expiry: self.expiry,
            nonce: self.nonce,
        }
    }

    /// Direct the invocation at an executor other than the subject. An
    /// audience equal to the subject is dropped, as the wire format
    /// requires.
    #[must_use]
    pub fn audience(mut self, audience: Did) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Replace the arguments.
    #[must_use]
    pub fn args(mut self, args: BTreeMap<String, Ipld>) -> Self {
        self.args = args;
        self
    }

    /// Set one argument.
    #[must_use]
    pub fn arg(mut self, key: impl Into<String>, value: Ipld) -> Self {
        self.args.insert(key.into(), value);
        self
    }

    /// Replace the proof chain. Root first.
    #[must_use]
    pub fn proofs(mut self, proofs: impl IntoIterator<Item = Cid>) -> Self {
        self.proofs = proofs.into_iter().collect();
        self
    }

    /// Append one proof.
    #[must_use]
    pub fn proof(mut self, proof: Cid) -> Self {
        self.proofs.push(proof);
        self
    }

    /// Replace the metadata.
    #[must_use]
    pub fn meta(mut self, meta: BTreeMap<String, Ipld>) -> Self {
        self.meta = meta;
        self
    }

    /// Add one metadata entry.
    #[must_use]
    pub fn meta_entry(mut self, key: impl Into<String>, value: Ipld) -> Self {
        self.meta.insert(key.into(), value);
        self
    }

    /// Claim an issuance time.
    #[must_use]
    pub fn issued_at(mut self, at: Timestamp) -> Self {
        self.issued_at = Some(at);
        self
    }

    /// Name the receipt that enqueued this task.
    #[must_use]
    pub fn cause(mut self, receipt: Cid) -> Self {
        self.cause = Some(receipt);
        self
    }
}

impl<const NONCE: bool> InvocationBuilder<false, NONCE> {
    /// Times out at `at`, inclusive. A few minutes is the recommendation.
    #[must_use]
    pub fn expires_at(mut self, at: Timestamp) -> InvocationBuilder<true, NONCE> {
        self.expiry = Some(Expiry::At(at));
        self.transition()
    }

    /// Never times out. Appropriate for attestations, and little else.
    #[must_use]
    pub fn never_expires(mut self) -> InvocationBuilder<true, NONCE> {
        self.expiry = Some(Expiry::Never);
        self.transition()
    }
}

impl<const EXPIRY: bool> InvocationBuilder<EXPIRY, false> {
    /// The nonce: [`Nonce::random`] for effects, [`Nonce::empty`] for
    /// idempotent commands.
    #[must_use]
    pub fn nonce(mut self, nonce: Nonce) -> InvocationBuilder<EXPIRY, true> {
        self.nonce = Some(nonce);
        self.transition()
    }
}

impl InvocationBuilder<true, true> {
    /// Sign with `signer`, whose DID becomes the issuer.
    pub fn sign(self, signer: &impl Signer) -> Result<Invocation, Error> {
        let audience = self
            .audience
            .filter(|aud| !aud.same_principal(&self.subject));
        let payload = InvocationPayload {
            issuer: signer.did(),
            subject: self.subject,
            audience,
            command: self.command,
            args: self.args,
            proofs: self.proofs,
            meta: self.meta,
            nonce: self.nonce.unwrap_or_else(Nonce::empty),
            expiration: self.expiry.unwrap_or(Expiry::Never),
            issued_at: self.issued_at,
            cause: self.cause,
        };
        let envelope = Envelope::seal(signer, TokenKind::Invocation, payload.to_ipld())?;
        Ok(Invocation { envelope, payload })
    }
}
