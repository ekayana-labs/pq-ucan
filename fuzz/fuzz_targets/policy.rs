//! A policy and arguments from the network: parsing, printing and evaluating.
//! The input splits at the first zero byte into a policy and its arguments.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pq_ucan::{codec, policy::Policy};

fuzz_target!(|bytes: &[u8]| {
    let split = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let (policy, args) = bytes.split_at(split);
    let Ok(policy) = codec::decode(policy) else {
        return;
    };
    let Ok(parsed) = Policy::from_ipld(&policy) else {
        return;
    };

    // A policy is signed, so what is printed has to read back the same.
    let printed = parsed.to_ipld();
    assert_eq!(
        Policy::from_ipld(&printed).unwrap(),
        parsed,
        "printing changed the policy"
    );

    let args = args.get(1..).unwrap_or_default();
    if let Ok(args) = codec::decode(args) {
        let _ = parsed.check(&args);
    }
});
