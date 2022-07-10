<!-- SPDX-License-Identifier: Apache-2.0 -->
# Performance notes

## Frontend
Invokation for maximally optimized server:
```sh
$ RUSTFLAGS="-C target-cpu=native" RUST_LOG=belvi=debug cargo run --release --bin belvi_frontend /tmp/certs/
```
