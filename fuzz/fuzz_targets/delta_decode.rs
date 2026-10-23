//! Arbitrary bytes as a delta from another node: decoding refuses or
//! accepts, and importing what was accepted never panics.

#![no_main]

use bouncer_io::{Actor, Bouncer, Delta, NodeId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(delta) = Delta::from_bytes(data) {
        let b = Bouncer::builder()
            .node(NodeId(9))
            .ban_capacity(1024)
            .revocation_capacity(64)
            .tickets(64)
            .budgets(bouncer_io::Budgets::off())
            .try_build()
            .unwrap();
        let _ = b.import(&delta, Actor::Channel(1));
        let _ = b.door("192.0.2.1".parse().unwrap());
    }
});
