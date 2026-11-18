#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| wicket_fuzz::vault_ref::run(data));
