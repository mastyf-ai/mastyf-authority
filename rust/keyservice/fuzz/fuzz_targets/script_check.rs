#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| mastyf_keyservice::fuzzing::script_check(data));
