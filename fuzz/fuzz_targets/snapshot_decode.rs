//! Arbitrary bytes as a persisted snapshot: loading either refuses with an
//! error or starts a bouncer that works. Never a panic, never a partial load
//! that breaks the door. With bit 2 of the first byte set, the rest is
//! framed as a snapshot without a MAC (magic, length, CRC), so mutations
//! reach the record decoder.

#![no_main]

mod frame;

use bouncer_io::{Bouncer, LoadFailure, PersistError, Persistence};
use libfuzzer_sys::fuzz_target;

struct Bytes(Option<Vec<u8>>);

impl Persistence for Bytes {
    fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError> {
        Ok(self.0.clone())
    }
    fn journal(&mut self) -> Result<Vec<u8>, PersistError> {
        Ok(Vec::new())
    }
    fn append(&mut self, _: &[u8]) -> Result<(), PersistError> {
        Ok(())
    }
    fn sync(&mut self) -> Result<(), PersistError> {
        Ok(())
    }
    fn replace_snapshot(&mut self, s: &[u8]) -> Result<(), PersistError> {
        self.0 = Some(s.to_vec());
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let framed = mode & 4 != 0;
    let bytes = if framed {
        frame::snapshot(if mode & 8 != 0 { 2 } else { 1 }, rest)
    } else {
        rest.to_vec()
    };
    let mut builder = Bouncer::builder()
        .ban_capacity(1024)
        .revocation_capacity(64)
        .tickets(64)
        .budgets(bouncer_io::Budgets::off())
        .persistence(Box::new(Bytes(Some(bytes))));
    if mode & 1 != 0 && !framed {
        builder = builder.mac_key([mode; 32]);
    }
    if mode & 2 != 0 {
        builder = builder.on_load_failure(LoadFailure::LoadEmpty);
    }
    if let Ok(b) = builder.try_build() {
        let _ = b.door("192.0.2.1".parse().unwrap());
        let _ = b.health();
    }
});
