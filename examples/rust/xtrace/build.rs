use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/net.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("net.skel.rs");

    let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");
    // // Command `clang -I{} ../../../vmlinux.h/include/x86_64 -I /tmp/.tmpxFQ6Iy/bpf/src -fno-stack-protector -D__TARGET_ARCH_x86 -g -O2 -target bpf -c src/bpf/net.bpf.c -o /tmp/.tmpiRrfZe/net.o`
    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-I"),
            Path::new("../../../vmlinux.h/include").join(arch).as_os_str(),
        ])
        .build_and_generate(&out)
        .expect("bpf compilation failed");
    println!("cargo:rerun-if-changed={}", SRC);
}
