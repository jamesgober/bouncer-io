//! A valid snapshot followed by an arbitrary journal: replay stops at the
//! first bad batch and the bouncer starts, never panics. With bit 1 of the
//! first byte set, the rest is framed as batches of the snapshot's epoch
//! (magic, length, CRC), so mutations reach the record decoder.

#![no_main]

mod frame;

use std::sync::{Arc, Mutex, OnceLock};

use bouncer_io::{Bouncer, PersistError, Persistence};
use libfuzzer_sys::fuzz_target;

#[derive(Clone, Default)]
struct Store(Arc<Mutex<(Option<Vec<u8>>, Vec<u8>)>>);

impl Persistence for Store {
    fn load(&mut self) -> Result<Option<Vec<u8>>, PersistError> {
        Ok(self.0.lock().unwrap().0.clone())
    }
    fn journal(&mut self) -> Result<Vec<u8>, PersistError> {
        Ok(self.0.lock().unwrap().1.clone())
    }
    fn append(&mut self, r: &[u8]) -> Result<(), PersistError> {
        self.0.lock().unwrap().1.extend_from_slice(r);
        Ok(())
    }
    fn sync(&mut self) -> Result<(), PersistError> {
        Ok(())
    }
    fn replace_snapshot(&mut self, s: &[u8]) -> Result<(), PersistError> {
        let mut g = self.0.lock().unwrap();
        g.0 = Some(s.to_vec());
        g.1.clear();
        Ok(())
    }
}

/// Small tables, so each run is cheap.
fn small() -> bouncer_io::BouncerBuilder {
    Bouncer::builder()
        .ban_capacity(1024)
        .revocation_capacity(64)
        .tickets(64)
        .budgets(bouncer_io::Budgets::off())
}

/// A snapshot with a few bans in it, and a journal batch to learn from.
fn seed() -> &'static (Vec<u8>, Vec<u8>) {
    static SEED: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    SEED.get_or_init(|| {
        let store = Store::default();
        let b = small()
            .persistence(Box::new(store.clone()))
            .try_build()
            .unwrap();
        b.ban("192.0.2.1".parse::<std::net::IpAddr>().unwrap())
            .unwrap();
        b.flush().unwrap();
        drop(b);
        let g = store.0.lock().unwrap();
        (g.0.clone().unwrap(), g.1.clone())
    })
}

fuzz_target!(|data: &[u8]| {
    let (snapshot, batch) = seed();
    let store = Store::default();
    {
        let mut g = store.0.lock().unwrap();
        g.0 = Some(snapshot.clone());
        let mode = data.first().copied().unwrap_or(0);
        let rest = data.get(1..).unwrap_or(&[]);
        let tail = if mode & 2 != 0 {
            frame::batches(frame::snapshot_epoch(snapshot), rest)
        } else {
            data.to_vec()
        };
        // Half the inputs start with a valid batch.
        g.1 = if mode & 1 == 1 {
            [batch.as_slice(), &tail].concat()
        } else {
            tail
        };
    }
    if let Ok(b) = small().persistence(Box::new(store)).try_build() {
        let _ = b.door("192.0.2.2".parse().unwrap());
    }
});
