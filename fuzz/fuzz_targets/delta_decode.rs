//! Arbitrary bytes as a delta from another node: decoding refuses or
//! accepts, and importing what was accepted never panics. Inputs whose
//! first byte is odd are framed (magic, format, CRC) so mutations reach the
//! record decoder; the others go in as they are.

#![no_main]

mod frame;

use bouncer_io::{Actor, Bouncer, Delta, NodeId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let bytes = if mode & 1 != 0 {
        frame::delta(if mode & 2 != 0 { 2 } else { 1 }, rest)
    } else {
        data.to_vec()
    };
    if let Ok(delta) = Delta::from_bytes(&bytes) {
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
