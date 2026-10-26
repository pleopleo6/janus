//! Strict parser for `ServerHello`: never panics, and accepted inputs are canonical
//! (re-encoding gives back the exact input, so the transcript hash of the
//! received bytes and of the parsed message cannot differ).
#![no_main]

use janus_core::messages::ServerHello;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(msg) = ServerHello::decode(data) {
        assert_eq!(msg.encode(), data, "non-canonical encoding accepted");
    }
});
