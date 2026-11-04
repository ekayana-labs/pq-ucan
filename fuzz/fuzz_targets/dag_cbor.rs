//! The strict decoder against `serde_ipld_dagcbor`, and against its own encoder.

#![no_main]

use ipld_core::ipld::Ipld;
use libfuzzer_sys::fuzz_target;
use pq_ucan::codec;
use serde_ipld_dagcbor::DecodeError;

fuzz_target!(|bytes: &[u8]| {
    let ours = codec::decode(bytes);
    let theirs = serde_ipld_dagcbor::from_slice::<Ipld>(bytes);

    if let Ok(value) = &ours {
        // One value has one encoding, so what is accepted is what is emitted.
        assert_eq!(codec::encode(value).unwrap(), bytes, "not canonical");
        // Strict means a subset: nothing here that the reference refuses, apart
        // from nesting, where each decoder has its own limit.
        match &theirs {
            Ok(theirs) => assert_eq!(value, theirs, "decoded to a different value"),
            Err(DecodeError::DepthOverflow { .. }) => {}
            Err(error) => panic!("accepted what the reference refused: {error:?}"),
        }
    } else if let Ok(value) = &theirs {
        // Refusing is right only if the reference would write something else.
        if serde_ipld_dagcbor::to_vec(value).is_ok_and(|canonical| canonical == bytes) {
            panic!("refused the reference's canonical encoding");
        }
    }
});
