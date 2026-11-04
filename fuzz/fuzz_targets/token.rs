//! Whole tokens from the network, down every path that reads them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pq_ucan::{
    delegation::Delegation,
    did::KeyResolver,
    envelope::DecodeOptions,
    invocation::Invocation,
    time::Timestamp,
    validate::{MemoryRevocationStore, MemoryStore, Revocation, Validator},
    Ipld,
};

fn exercise_delegation(delegation: &Delegation) {
    assert_eq!(
        Delegation::decode_with(
            delegation.bytes(),
            DecodeOptions::STRICT.release_candidate_tags(true)
        )
        .unwrap()
        .cid(),
        delegation.cid(),
    );
    let _ = delegation.verify(&KeyResolver);
    let _ = delegation.to_dag_json();
    let _ = delegation.policy().check(&Ipld::Map(Default::default()));
}

fuzz_target!(|bytes: &[u8]| {
    let options = DecodeOptions::STRICT.release_candidate_tags(true);
    let now = Timestamp::from_unix(1_800_000_000).unwrap();

    if let Ok(delegation) = Delegation::decode_with(bytes, options) {
        exercise_delegation(&delegation);
    }

    if let Ok(invocation) = Invocation::decode_with(bytes, options) {
        let _ = invocation.verify(&KeyResolver);
        let _ = invocation.to_dag_json();
        let _ = invocation.task_id();
        let _ = Revocation::read(&invocation);

        let store = MemoryStore::new();
        let revoked = MemoryRevocationStore::new();
        let _ = Validator::new(&store, now)
            .revocations(&revoked)
            .validate(&invocation);
        let _ = Validator::new(&store, now).check_revocation(invocation.issuer(), &invocation, &[]);
    }
});
