# ZkVM demo

How to run the demo:

```
# Install the required version of Rust (see ./rust-toolchain)
rustup install nightly-2019-08-19

# Install the database tool
cargo install diesel_cli --no-default-features --features sqlite

# Setup database
diesel database reset

# Run the app
cargo run
```