// SPDX-License-Identifier: CC0-1.0

#![forbid(unsafe_code)]
//! `refresh-region-data`: fetch newer Regional availability data with your own AWS credentials,
//! or say which data is in use (`--status`). See `service_common::availability_cli`.
//!
//! Run it with `cargo run -p service-common --bin refresh-region-data -- --help`. The emulator
//! never runs it: nothing is fetched unless you start this program.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(service_common::availability_cli::main(&args));
}
