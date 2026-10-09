# midnight-offline-derive
Cardano CLI tool for offline derivation of 33-byte public-key

COMPILE:
  steps to compile (targetting out-dated CPU running unknown linux using zero dynamic libraries) : 
$/cargo check
$/CC_x86_64_unknown_linux_musl=musl-gcc cargo build --release --target x86_64-unknown-linux-mus


EXECUTE stand-alone binary:
$/target/x86_64-unknown-linux-musl/release/midnight-offline-derive
