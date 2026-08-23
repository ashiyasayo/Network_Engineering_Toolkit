//! 只在 `native-dpdk` feature 啟用時尋找 SDK 並編譯 C shim。

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/shim.c");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    if env::var_os("CARGO_FEATURE_NATIVE_DPDK").is_none() {
        return;
    }
    let flags = pkg_config_flags("--cflags");
    let libraries = pkg_config_flags("--libs");
    let mut build = cc::Build::new();
    build.file("src/shim.c").warnings(true);
    for flag in flags {
        if let Some(include) = flag.strip_prefix("-I") {
            build.include(PathBuf::from(include));
        } else {
            build.flag(&flag);
        }
    }
    build.compile("nettool_dpdk_shim");
    for flag in libraries {
        if let Some(path) = flag.strip_prefix("-L") {
            println!("cargo:rustc-link-search=native={path}");
        } else if let Some(library) = flag.strip_prefix("-l") {
            println!("cargo:rustc-link-lib={library}");
        } else if flag == "-pthread" {
            println!("cargo:rustc-link-lib=pthread");
        } else if let Some(option) = flag.strip_prefix("-Wl,") {
            println!("cargo:rustc-link-arg=-Wl,{option}");
        }
    }
}

fn pkg_config_flags(option: &str) -> Vec<String> {
    let output = Command::new("pkg-config")
        .args([option, "libdpdk"])
        .output()
        .unwrap_or_else(|error| panic!("native-dpdk requires pkg-config: {error}"));
    assert!(
        output.status.success(),
        "native-dpdk requires a discoverable libdpdk SDK: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout)
        .expect("pkg-config output must be UTF-8")
        .split_whitespace()
        .map(ToOwned::to_owned)
        .collect()
}
