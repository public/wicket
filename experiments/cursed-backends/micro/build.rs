//! fbparse.h from a cursed-http checkout at the pinned commit (CURSED_HTTP_DIR), built twice: the x86-64
//! baseline (SSE2) and -mavx2, so both can be timed against httparse in one process.
fn main() {
    let dir = std::env::var("CURSED_HTTP_DIR").expect("CURSED_HTTP_DIR: a cursed-http checkout at 5e10ca8");
    println!("cargo:rerun-if-env-changed=CURSED_HTTP_DIR");
    println!("cargo:rerun-if-changed=fb.c");
    for (name, flags) in [("fb_sse2", &[][..]), ("fb_avx2", &["-mavx2"][..])] {
        let mut b = cc::Build::new();
        b.file("fb.c").include(format!("{dir}/include")).opt_level(3).define("FB_NAME", name).warnings(false);
        for f in flags {
            b.flag(f);
        }
        b.compile(name);
    }
}
