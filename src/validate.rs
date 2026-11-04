//! Execution time validation of an invocation against its proof chain.
//!
//! The pipeline, its order and its failures are specified in
//! `docs/validation.md`. Everything here is that document, in code.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::fmt;

use ipld_core::{cid::Cid, ipld::Ipld};
use thiserror::Error;

use crate::{
    command::Command,
    delegation::{Delegation, Subject},
    did::{Did, KeyResolver, ResolveError, Resolver},
    invocation::Invocation,
    time::{Expiry, Timestamp},
    Error,
};

/// Where a validator finds the delegations an invocation names.
pub trait ProofStore {
    /// The delegation with this CID, if held.
    fn get(&self, cid: &Cid) -> Option<Delegation>;
}

impl<S: ProofStore + ?Sized> ProofStore for &S {
    fn get(&self, cid: &Cid) -> Option<Delegation> {
        (**self).get(cid)
    }
}

/// Delegations held in memory, keyed by CID.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    delegations: BTreeMap<Cid, Delegation>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold a delegation. Returns its CID.
    pub fn insert(&mut self, delegation: Delegation) -> Cid {
        let cid = *delegation.cid();
        self.delegations.insert(cid, delegation);
        cid
    }

    /// Stop holding a delegation.
    pub fn remove(&mut self, cid: &Cid) -> Option<Delegation> {
        self.delegations.remove(cid)
    }

    /// How many are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.delegations.len()
    }

    /// Whether none are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.delegations.is_empty()
    }

    /// Drop delegations that expired before `now`, less `skew`.
    pub fn prune_expired(&mut self, now: Timestamp, skew: u32) {
        self.delegations
            .retain(|_, d| !d.expiration().is_past(now, skew));
    }
}

impl ProofStore for MemoryStore {
    fn get(&self, cid: &Cid) -> Option<Delegation> {
        self.delegations.get(cid).cloned()
    }
}

/// Remembers invocations so that none executes twice.
pub trait ReplayGuard {
    /// Record `cid`. Returns `false` if it had been recorded before.
    fn record(&mut self, cid: &Cid, expiry: Expiry) -> bool;
}

/// A replay guard held in memory.
#[derive(Debug, Clone, Default)]
pub struct MemoryReplayGuard {
    seen: BTreeMap<Cid, Expiry>,
}

impl MemoryReplayGuard {
    /// An empty guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget invocations that can no longer be replayed because they have
    /// expired.
    pub fn prune_expired(&mut self, now: Timestamp, skew: u32) {
        self.seen.retain(|_, exp| !exp.is_past(now, skew));
    }
}

impl ReplayGuard for MemoryReplayGuard {
    fn record(&mut self, cid: &Cid, expiry: Expiry) -> bool {
        self.seen.insert(*cid, expiry).is_none()
    }
}

/// Says whether a delegation has been revoked.
///
/// The validator asks about the CID of each delegation in a chain. It does not
/// judge the revocations themselves: whoever fills the store decides which
/// ones count. See `docs/validation.md`.
pub trait RevocationStore {
    /// Whether the delegation with this CID has been revoked. A store that
    /// cannot tell should answer `true`, so that an outage refuses requests
    /// rather than letting a revoked chain through.
    fn is_revoked(&self, cid: &Cid) -> bool;
}

/// Revocations held in memory.
///
/// There is no way to take one back: the specification makes a revocation
/// irreversible, and a mistake is fixed by issuing a new delegation.
#[derive(Debug, Clone, Default)]
pub struct MemoryRevocationStore {
    revoked: BTreeSet<Cid>,
}

impl MemoryRevocationStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the delegation with this CID is revoked. It need not have
    /// been seen yet, since a revocation can arrive first.
    pub fn revoke(&mut self, cid: Cid) {
        self.revoked.insert(cid);
    }
}

impl RevocationStore for MemoryRevocationStore {
    fn is_revoked(&self, cid: &Cid) -> bool {
        self.revoked.contains(cid)
    }
}

/// A position in the chain that a failure points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hop {
    /// The n-th delegation, root first.
    Proof(usize),
    /// The invocation itself.
    Invocation,
}

impl fmt::Display for Hop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Hop::Proof(n) => write!(f, "proof {n}"),
            Hop::Invocation => f.write_str("invocation"),
        }
    }
}

/// Why a chain was rejected, and where.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// The invocation names no proofs.
    #[error("invocation carries no proofs")]
    EmptyChain,

    /// A named proof is not in the store.
    #[error("proof {0} is not available")]
    MissingProof(Cid),

    /// The invocation names more proofs than this validator accepts.
    #[error("invocation carries {count} proofs, the limit is {max}")]
    TooManyProofs {
        /// How many it names.
        count: usize,
        /// The limit.
        max: usize,
    },

    /// The root delegation was not issued by the subject.
    #[error("root delegation issued by {issuer}, subject is {subject}")]
    RootNotSubject {
        /// Who issued the root.
        issuer: Did,
        /// Whose authority the invocation claims.
        subject: Did,
    },

    /// The root delegation is a powerline.
    #[error("root delegation has a null subject")]
    PowerlineAtRoot,

    /// A delegation is about a different subject.
    #[error("{hop}: subject does not match the invocation")]
    SubjectMismatch {
        /// Where.
        hop: Hop,
    },

    /// A delegation's audience is not the next issuer.
    #[error("{hop}: audience {audience} is not the next issuer {issuer}")]
    PrincipalMismatch {
        /// Where.
        hop: Hop,
        /// The delegation's audience.
        audience: Did,
        /// Who issued the next token.
        issuer: Did,
    },

    /// A delegation grants less than the next token needs.
    #[error("{hop}: {granted} does not cover {requested}")]
    CommandNotCovered {
        /// Where.
        hop: Hop,
        /// What the delegation grants.
        granted: Command,
        /// What the next token needs.
        requested: Command,
    },

    /// A token is not valid yet.
    #[error("{hop}: not valid before {not_before}")]
    NotYetValid {
        /// Where.
        hop: Hop,
        /// When it becomes valid.
        not_before: Timestamp,
    },

    /// A token has expired.
    #[error("{hop}: expired at {at}")]
    Expired {
        /// Where.
        hop: Hop,
        /// When it expired.
        at: Timestamp,
    },

    /// An issuer could not be turned into a key.
    #[error("{hop}: cannot resolve issuer: {source}")]
    Unresolvable {
        /// Where.
        hop: Hop,
        /// Why.
        source: ResolveError,
    },

    /// A signature does not verify.
    #[error("{hop}: signature does not verify")]
    BadSignature {
        /// Where.
        hop: Hop,
    },

    /// A delegation in the chain has been revoked.
    #[error("{hop}: delegation {cid} has been revoked")]
    Revoked {
        /// Where.
        hop: Hop,
        /// The revoked delegation.
        cid: Cid,
    },

    /// The arguments fail a delegation's policy.
    #[error("{hop}: policy statement {statement} rejected the arguments")]
    PolicyRejected {
        /// Where.
        hop: Hop,
        /// Which statement of the policy list, counted from zero.
        statement: usize,
    },

    /// The invocation is addressed to someone else.
    #[error("invocation is for {found}, this executor is {expected}")]
    WrongExecutor {
        /// This executor.
        expected: Did,
        /// The invocation's target.
        found: Did,
    },

    /// The invocation has been seen before.
    #[error("invocation {0} was already executed")]
    Replay(Cid),

    /// A token problem outside the categories above.
    #[error("{hop}: {source}")]
    Token {
        /// Where.
        hop: Hop,
        /// What.
        source: Error,
    },
}

/// The outcome of a successful validation: the chain that was checked.
#[derive(Debug, Clone)]
pub struct Proof {
    chain: Vec<Delegation>,
    subject: Did,
    invocation: Cid,
}

impl Proof {
    /// The delegations, root first.
    #[must_use]
    pub fn chain(&self) -> &[Delegation] {
        &self.chain
    }

    /// The subject every hop was checked against.
    #[must_use]
    pub const fn subject(&self) -> &Did {
        &self.subject
    }

    /// The invocation that was validated.
    #[must_use]
    pub const fn invocation(&self) -> &Cid {
        &self.invocation
    }
}

static KEY_RESOLVER: KeyResolver = KeyResolver;

/// Runs the validation pipeline.
pub struct Validator<'a> {
    store: &'a dyn ProofStore,
    resolver: &'a dyn Resolver,
    now: Timestamp,
    skew: u32,
    executor: Option<&'a Did>,
    replay: Option<&'a mut dyn ReplayGuard>,
    max_proofs: Option<usize>,
    revocations: Option<&'a dyn RevocationStore>,
}

impl<'a> Validator<'a> {
    /// The recommended clock skew allowance, in seconds.
    pub const DEFAULT_SKEW: u32 = 60;

    /// A validator over `store` at time `now`, resolving `did:key` only,
    /// with the default skew, checking neither executor, replay nor
    /// revocation, and with no limit on the number of proofs.
    #[must_use]
    pub fn new(store: &'a dyn ProofStore, now: Timestamp) -> Self {
        Validator {
            store,
            resolver: &KEY_RESOLVER,
            now,
            skew: Self::DEFAULT_SKEW,
            executor: None,
            replay: None,
            max_proofs: None,
            revocations: None,
        }
    }

    /// Resolve issuers through `resolver` instead of `did:key` alone.
    #[must_use]
    pub fn resolver(mut self, resolver: &'a dyn Resolver) -> Self {
        self.resolver = resolver;
        self
    }

    /// Allow `seconds` of clock skew on every time bound.
    #[must_use]
    pub const fn skew(mut self, seconds: u32) -> Self {
        self.skew = seconds;
        self
    }

    /// Require the invocation to be addressed to `did`.
    #[must_use]
    pub const fn executor(mut self, did: &'a Did) -> Self {
        self.executor = Some(did);
        self
    }

    /// Refuse invocations the guard has seen; record the ones that pass.
    #[must_use]
    pub fn replay_guard(mut self, guard: &'a mut dyn ReplayGuard) -> Self {
        self.replay = Some(guard);
        self
    }

    /// Refuse invocations that name more than `max` proofs.
    ///
    /// UCAN has no depth limit in the token, so this is the executor's own
    /// policy and it applies to every chain alike.
    #[must_use]
    pub const fn max_proofs(mut self, max: usize) -> Self {
        self.max_proofs = Some(max);
        self
    }

    /// Refuse chains holding a delegation that `store` says is revoked.
    #[must_use]
    pub const fn revocations(mut self, store: &'a dyn RevocationStore) -> Self {
        self.revocations = Some(store);
        self
    }

    /// Run every check. Stops at the first failure.
    pub fn validate(&mut self, invocation: &Invocation) -> Result<Proof, ValidationError> {
        let subject = invocation.subject();

        // 0: before anything is looked up or verified, so that a long chain
        // costs nothing to refuse.
        if let Some(max) = self.max_proofs {
            let count = invocation.proofs().len();
            if count > max {
                return Err(ValidationError::TooManyProofs { count, max });
            }
        }

        // 1, 2: every proof resolves, and there is at least one.
        let chain = invocation
            .proofs()
            .iter()
            .map(|cid| {
                self.store
                    .get(cid)
                    .ok_or(ValidationError::MissingProof(*cid))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // 2 to 7.
        check_structure(
            &chain,
            subject,
            Some((invocation.issuer(), invocation.command())),
        )?;

        // 8: every token is inside its validity window.
        for (i, delegation) in chain.iter().enumerate() {
            delegation
                .check_time(self.now, self.skew)
                .map_err(|e| time_error(Hop::Proof(i), e))?;
        }
        invocation
            .check_time(self.now, self.skew)
            .map_err(|e| time_error(Hop::Invocation, e))?;

        // 9: every signature verifies under its issuer's key.
        self.verify_chain(&chain)?;
        invocation
            .verify(&self.resolver)
            .map_err(|e| signature_error(Hop::Invocation, e))?;

        // 9a: no delegation in the chain has been revoked.
        self.check_revocations(&chain)?;

        // 10: the arguments satisfy every policy in the chain.
        let args = Ipld::Map(invocation.args().clone());
        for (i, delegation) in chain.iter().enumerate() {
            delegation.policy().check(&args).map_err(|statement| {
                ValidationError::PolicyRejected {
                    hop: Hop::Proof(i),
                    statement,
                }
            })?;
        }

        // 11: the invocation is addressed to this executor.
        if let Some(me) = self.executor {
            let target = invocation.executor();
            if !target.same_principal(me) {
                return Err(ValidationError::WrongExecutor {
                    expected: me.clone(),
                    found: target.clone(),
                });
            }
        }

        // 12: last, so that a rejected invocation is never recorded.
        if let Some(guard) = self.replay.as_deref_mut() {
            if !guard.record(invocation.cid(), invocation.expiration()) {
                return Err(ValidationError::Replay(*invocation.cid()));
            }
        }

        Ok(Proof {
            chain,
            subject: subject.clone(),
            invocation: *invocation.cid(),
        })
    }

    fn verify_chain(&self, chain: &[Delegation]) -> Result<(), ValidationError> {
        for (i, delegation) in chain.iter().enumerate() {
            delegation
                .verify(&self.resolver)
                .map_err(|e| signature_error(Hop::Proof(i), e))?;
        }
        Ok(())
    }

    /// Asks about each delegation's own CID rather than the link in `prf`,
    /// which a store may resolve from another CID of the same bytes.
    fn check_revocations(&self, chain: &[Delegation]) -> Result<(), ValidationError> {
        let Some(revocations) = self.revocations else {
            return Ok(());
        };
        for (i, delegation) in chain.iter().enumerate() {
            if revocations.is_revoked(delegation.cid()) {
                return Err(ValidationError::Revoked {
                    hop: Hop::Proof(i),
                    cid: *delegation.cid(),
                });
            }
        }
        Ok(())
    }
}

/// The checks on the shape of a chain, which look at no signature. `last` is
/// the issuer and command of the token the last hop was given for, if any.
fn check_structure(
    chain: &[Delegation],
    subject: &Did,
    last: Option<(&Did, &Command)>,
) -> Result<(), ValidationError> {
    let root = chain.first().ok_or(ValidationError::EmptyChain)?;

    // 3, 4: the root is issued by the subject and is not a powerline.
    if !root.issuer().same_principal(subject) {
        return Err(ValidationError::RootNotSubject {
            issuer: root.issuer().clone(),
            subject: subject.clone(),
        });
    }
    if matches!(root.subject(), Subject::Powerline) {
        return Err(ValidationError::PowerlineAtRoot);
    }

    // 5: subjects align. A powerline inherits its predecessor's subject,
    // which by induction is the invocation's.
    for (i, delegation) in chain.iter().enumerate() {
        if let Subject::Did(did) = delegation.subject() {
            if !did.same_principal(subject) {
                return Err(ValidationError::SubjectMismatch { hop: Hop::Proof(i) });
            }
        }
    }

    // 6, 7: each hop's audience issues the next token, and each hop's
    // command covers the next token's.
    for (i, delegation) in chain.iter().enumerate() {
        let next = chain
            .get(i + 1)
            .map(|next| (next.issuer(), next.command()))
            .or(last);
        let Some((next_issuer, next_command)) = next else {
            continue;
        };
        if !delegation.audience().same_principal(next_issuer) {
            return Err(ValidationError::PrincipalMismatch {
                hop: Hop::Proof(i),
                audience: delegation.audience().clone(),
                issuer: next_issuer.clone(),
            });
        }
        if !delegation.command().covers(next_command) {
            return Err(ValidationError::CommandNotCovered {
                hop: Hop::Proof(i),
                granted: delegation.command().clone(),
                requested: next_command.clone(),
            });
        }
    }
    Ok(())
}

fn time_error(hop: Hop, error: Error) -> ValidationError {
    match error {
        Error::NotYetValid(not_before) => ValidationError::NotYetValid { hop, not_before },
        Error::Expired(at) => ValidationError::Expired { hop, at },
        source => ValidationError::Token { hop, source },
    }
}

fn signature_error(hop: Hop, error: Error) -> ValidationError {
    match error {
        Error::Resolve(source) => ValidationError::Unresolvable { hop, source },
        Error::Crypto(_) => ValidationError::BadSignature { hop },
        source => ValidationError::Token { hop, source },
    }
}
