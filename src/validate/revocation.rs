//! Reading and judging `/ucan/revoke` invocations, so that a
//! [`RevocationStore`](super::RevocationStore) holds only revocations from
//! someone entitled to make them. The rules, and where they part from the
//! Revocation specification's text, are in `docs/validation.md`.

use alloc::{string::String, vec::Vec};

use ipld_core::{cid::Cid, ipld::Ipld};
use thiserror::Error;

use super::{check_structure, signature_error, time_error, Hop, ValidationError, Validator};
use crate::{command::Command, delegation::Delegation, did::Did, invocation::Invocation};

/// The command a revocation invokes.
pub const REVOKE_COMMAND: &str = "/ucan/revoke";

/// Why a revocation was refused.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// The invocation is for another command.
    #[error("command {0} is not /ucan/revoke")]
    NotARevocation(Command),

    /// `args` has no `revoke`.
    #[error("args has no `revoke`")]
    MissingTarget,

    /// An argument holds the wrong kind of value.
    #[error("argument `{0}` has the wrong type")]
    MalformedArgument(&'static str),

    /// An argument the command does not define.
    #[error("unknown argument `{0}`")]
    UnknownArgument(String),

    /// The chain does not end in the delegation being revoked.
    #[error("the chain does not end in {named}, which the revocation names")]
    WrongTarget {
        /// What `revoke` names.
        named: Cid,
    },

    /// `path` was given and does not list the chain, root first.
    #[error("`path` does not list the chain")]
    PathMismatch,

    /// A principal issues twice in the chain. Such a chain can always be
    /// shortened, so it can only serve to put someone above a delegation that
    /// was issued above them.
    #[error("{hop}: {issuer} already issued earlier in the chain")]
    RepeatedIssuer {
        /// Where it issues again.
        hop: Hop,
        /// Who.
        issuer: Did,
    },

    /// The revocation's `sub` issued nothing in the chain, so it has no right
    /// to revoke and none to hand on.
    #[error("revocation subject {subject} issued nothing in the chain")]
    SubjectNotInChain {
        /// The revocation's `sub`.
        subject: Did,
    },

    /// The revoker issued nothing in the chain and offers no proof that it
    /// was given `/ucan/revoke`.
    #[error("{revoker} issued nothing in the chain and offers no proof of /ucan/revoke")]
    NotAuthorized {
        /// Who signed the revocation.
        revoker: Did,
    },

    /// The revocation or the chain it came with failed a check the validator
    /// also makes. The hop says which token.
    #[error("{0}")]
    Invalid(#[source] ValidationError),

    /// The proof that the revoker was given `/ucan/revoke` does not hold.
    #[error("proof of /ucan/revoke: {0}")]
    Grant(#[source] ValidationError),
}

/// The arguments of a `/ucan/revoke` invocation. This says nothing about
/// whether the invocation counts: for that, see
/// [`Validator::check_revocation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    target: Cid,
    path: Option<Vec<Cid>>,
}

impl Revocation {
    /// Read the arguments. Names other than `revoke` and `path` are refused,
    /// so that a token spelling them another way is not half understood.
    pub fn read(invocation: &Invocation) -> Result<Self, RevocationError> {
        if invocation.command().as_str() != REVOKE_COMMAND {
            return Err(RevocationError::NotARevocation(
                invocation.command().clone(),
            ));
        }
        let mut target = None;
        let mut path = None;
        for (name, value) in invocation.args() {
            match (name.as_str(), value) {
                ("revoke", Ipld::Link(cid)) => target = Some(*cid),
                ("revoke", _) => return Err(RevocationError::MalformedArgument("revoke")),
                ("path", Ipld::List(links)) => path = Some(links_in(links)?),
                ("path", _) => return Err(RevocationError::MalformedArgument("path")),
                (other, _) => return Err(RevocationError::UnknownArgument(other.into())),
            }
        }
        Ok(Revocation {
            target: target.ok_or(RevocationError::MissingTarget)?,
            path,
        })
    }

    /// The CID of the delegation to revoke.
    #[must_use]
    pub const fn target(&self) -> &Cid {
        &self.target
    }

    /// The chain the revoker names, root first, ending in the target. A
    /// caller can look these up to get the chain to check.
    #[must_use]
    pub fn path(&self) -> Option<&[Cid]> {
        self.path.as_deref()
    }
}

fn links_in(values: &[Ipld]) -> Result<Vec<Cid>, RevocationError> {
    values
        .iter()
        .map(|value| match value {
            Ipld::Link(cid) => Ok(*cid),
            _ => Err(RevocationError::MalformedArgument("path")),
        })
        .collect()
}

/// A revocation that passed [`Validator::check_revocation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRevocation {
    target: Cid,
    revoker: Did,
    hop: usize,
    last_hop: usize,
    delegated: bool,
}

impl AcceptedRevocation {
    /// The CID to record: the one computed from the delegation's bytes.
    #[must_use]
    pub const fn target(&self) -> &Cid {
        &self.target
    }

    /// Who signed the revocation.
    #[must_use]
    pub const fn revoker(&self) -> &Did {
        &self.revoker
    }

    /// The hop whose issuer's right to revoke was used. Root is zero.
    #[must_use]
    pub const fn hop(&self) -> usize {
        self.hop
    }

    /// Whether that right reached the revoker through `/ucan/revoke`.
    #[must_use]
    pub const fn is_delegated(&self) -> bool {
        self.delegated
    }

    /// Whether the right rests on an issuer between the root and the target.
    ///
    /// A delegation has no ancestors of its own and anyone can sign one to
    /// anyone, so a principal holding overlapping authority can present a
    /// path that puts them here. See `docs/validation.md`. A caller that will
    /// not take that risk can refuse these.
    #[must_use]
    pub const fn rests_on_intermediate_issuer(&self) -> bool {
        self.hop != 0 && self.hop != self.last_hop
    }
}

impl Validator<'_> {
    /// Decide whether `invocation` is a revocation this `subject` should
    /// record, given the `chain` of the delegation it revokes: root first,
    /// ending in that delegation.
    ///
    /// `subject` is whose revocations are being kept, and it is not read from
    /// the token because a powerline has no subject of its own.
    ///
    /// The validator's resolver, clock, skew and proof limit apply, and its
    /// proof store is where the proofs of a delegated `/ucan/revoke` are
    /// found. The executor and replay guard do not apply: a revocation is
    /// idempotent and may arrive by gossip.
    pub fn check_revocation(
        &self,
        subject: &Did,
        invocation: &Invocation,
        chain: &[Delegation],
    ) -> Result<AcceptedRevocation, RevocationError> {
        use RevocationError::{Invalid, NotAuthorized, SubjectNotInChain};

        let revocation = Revocation::read(invocation)?;
        if let Some(max) = self.max_proofs {
            if chain.len() > max {
                return Err(Invalid(ValidationError::TooManyProofs {
                    count: chain.len(),
                    max,
                }));
            }
        }

        check_structure(chain, subject, None).map_err(Invalid)?;
        let target = check_names_chain(&revocation, chain)?;
        check_no_issuer_repeats(chain)?;

        invocation
            .verify(&self.resolver)
            .map_err(|e| Invalid(signature_error(Hop::Invocation, e)))?;
        invocation
            .check_time(self.now, self.skew)
            .map_err(|e| Invalid(time_error(Hop::Invocation, e)))?;
        self.verify_chain(chain).map_err(Invalid)?;

        let issued_at = |did: &Did| chain.iter().position(|d| d.issuer().same_principal(did));
        let source = issued_at(invocation.subject()).ok_or_else(|| SubjectNotInChain {
            subject: invocation.subject().clone(),
        })?;
        let (hop, delegated) = match issued_at(invocation.issuer()) {
            Some(hop) => (hop, false),
            None if invocation.proofs().is_empty() => {
                return Err(NotAuthorized {
                    revoker: invocation.issuer().clone(),
                });
            }
            None => {
                self.check_grant(invocation)?;
                (source, true)
            }
        };

        Ok(AcceptedRevocation {
            target,
            revoker: invocation.issuer().clone(),
            hop,
            last_hop: chain.len().saturating_sub(1),
            delegated,
        })
    }

    /// A `/ucan/revoke` proof is an ordinary invocation chain, rooted in the
    /// revocation's `sub`.
    fn check_grant(&self, invocation: &Invocation) -> Result<(), RevocationError> {
        let mut validator = Validator::new(self.store, self.now)
            .resolver(self.resolver)
            .skew(self.skew);
        validator.max_proofs = self.max_proofs;
        validator.revocations = self.revocations;
        validator
            .validate(invocation)
            .map(|_| ())
            .map_err(RevocationError::Grant)
    }
}

/// The target's own CID, once the arguments are shown to name this chain.
fn check_names_chain(
    revocation: &Revocation,
    chain: &[Delegation],
) -> Result<Cid, RevocationError> {
    let found = chain
        .last()
        .map(|delegation| *delegation.cid())
        .ok_or(RevocationError::Invalid(ValidationError::EmptyChain))?;
    if *revocation.target() != found {
        return Err(RevocationError::WrongTarget {
            named: *revocation.target(),
        });
    }
    if let Some(path) = revocation.path() {
        if !path.iter().eq(chain.iter().map(Delegation::cid)) {
            return Err(RevocationError::PathMismatch);
        }
    }
    Ok(found)
}

fn check_no_issuer_repeats(chain: &[Delegation]) -> Result<(), RevocationError> {
    for (i, delegation) in chain.iter().enumerate() {
        let issuer = delegation.issuer();
        if chain
            .iter()
            .take(i)
            .any(|earlier| earlier.issuer().same_principal(issuer))
        {
            return Err(RevocationError::RepeatedIssuer {
                hop: Hop::Proof(i),
                issuer: issuer.clone(),
            });
        }
    }
    Ok(())
}
