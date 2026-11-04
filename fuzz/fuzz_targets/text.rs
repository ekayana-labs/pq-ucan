//! The small text and binary parsers a token's fields go through.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pq_ucan::{
    cid,
    command::Command,
    did::Did,
    policy::{Pattern, Selector},
    varsig::Header,
    Ipld,
};

fuzz_target!(|bytes: &[u8]| {
    let _ = Header::decode(bytes);
    let Ok(text) = core::str::from_utf8(bytes) else {
        return;
    };

    if let Ok(did) = Did::parse(text) {
        assert!(did.same_principal(&did));
        let _ = did.key();
    }
    if let Ok(command) = Command::parse(text) {
        assert!(command.covers(&command));
        assert!(Command::root().covers(&command));
    }
    if let Ok(parsed) = cid::parse(text) {
        let _ = cid::to_base58btc(&parsed);
    }

    let (left, right) = text.split_at(text.floor_char_boundary(text.len() / 2));
    let _ = Pattern::parse(left).matches(right);
    if let Ok(selector) = Selector::parse(text) {
        let value = Ipld::List(vec![Ipld::String(left.into()), Ipld::Bytes(right.into())]);
        let _ = selector.resolve(&value);
    }
});
