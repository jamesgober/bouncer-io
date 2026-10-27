//! Prefix text parsing: never panics, never accepts more than 64 bytes, and
//! everything accepted prints back to the same prefix.

#![no_main]

use bouncer_io::Cidr;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    let loose = Cidr::parse(text);
    let strict = Cidr::parse_strict(text);
    if let Ok(c) = strict {
        assert_eq!(loose, Ok(c), "strict accepted what loose refused: {text:?}");
    }
    if let Ok(c) = loose {
        assert!(text.len() <= 64, "accepted {} bytes", text.len());
        let printed = c.to_string();
        assert_eq!(
            Cidr::parse_strict(&printed),
            Ok(c),
            "round trip of {text:?} via {printed:?}"
        );
    }
});
