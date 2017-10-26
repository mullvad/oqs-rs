// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate bindgen;

use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = env::var("OUT_DIR").map(PathBuf::from).unwrap();

    let oqs_dir = env::var("OQS_DIR")
        .map(PathBuf::from)
        .expect("Set the environment variable OQS_DIR to the absolute path to your liboqs dir");
    let oqs_include_dir = oqs_dir.join("include");

    println!("cargo:rustc-link-lib=oqs");
    println!("cargo:rustc-link-lib=sodium");
    println!(
        "cargo:rustc-link-search=native={}",
        oqs_dir.to_string_lossy()
    );

    let _ = bindgen::builder()
        .header(format!("{}/oqs/kex.h", oqs_include_dir.to_string_lossy()))
        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
        .link_static("oqs")
        .use_core()
        .ctypes_prefix("::libc")
        .whitelist_recursively(false)
        .whitelisted_type("OQS_KEX.*")
        .whitelisted_function("OQS_KEX_.*")
        .raw_line("use ::rand::OQS_RAND;")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("kex.rs"))
        .unwrap();

    let _ = bindgen::builder()
        .header(format!("{}/oqs/rand.h", oqs_include_dir.to_string_lossy()))
        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
        .link_static("oqs")
        .use_core()
        .ctypes_prefix("::libc")
        .whitelisted_type("OQS_RAND.*")
        .whitelisted_function("OQS_RAND_.*")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("rand.rs"))
        .unwrap();

    let _ = bindgen::builder()
        .header(format!(
            "{}/oqs/common.h",
            oqs_include_dir.to_string_lossy()
        ))
        .clang_arg(format!("-I{}", oqs_include_dir.to_string_lossy()))
        .link_static("oqs")
        .use_core()
        .ctypes_prefix("::libc")
        .whitelisted_var("OQS_.*")
        .whitelisted_function("OQS_.*")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("common.rs"))
        .unwrap();
}
