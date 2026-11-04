//! The strict DAG-JSON codec against `serde_ipld_dagjson`, and against itself.

#![no_main]

use ipld_core::ipld::Ipld;
use libfuzzer_sys::fuzz_target;
use pq_ucan::codec::{self, json};

/// The reference reads an integer below `i64::MIN` as a float and loses digits.
/// DAG-JSON says digits alone are an integer, and DAG-CBOR can hold it, so that
/// difference is not ours to match.
fn agrees(ours: &Ipld, theirs: &Ipld) -> bool {
    match (ours, theirs) {
        (Ipld::Integer(i), Ipld::Float(_)) => *i < i128::from(i64::MIN),
        (Ipld::List(a), Ipld::List(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| agrees(x, y))
        }
        (Ipld::Map(a), Ipld::Map(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((k, x), (l, y))| k == l && agrees(x, y))
        }
        _ => ours == theirs,
    }
}

fuzz_target!(|bytes: &[u8]| {
    if let Ok(value) = json::decode(bytes) {
        assert_eq!(
            json::encode(&value).unwrap().as_bytes(),
            bytes,
            "not canonical"
        );
        let theirs = serde_ipld_dagjson::from_slice::<Ipld>(bytes)
            .expect("accepted what the reference refused");
        assert!(agrees(&value, &theirs), "{value:?} decoded as {theirs:?}");
    }

    // Text is signed in place of DAG-CBOR, so the same value has to survive
    // both, and one value has one text.
    if let Ok(value) = codec::decode(bytes) {
        if let Ok(text) = json::encode(&value) {
            assert_eq!(
                json::decode(text.as_bytes()).unwrap(),
                value,
                "text changed the value"
            );
        }
    }
});
