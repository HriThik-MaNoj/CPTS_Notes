```python
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && source $HOME/.cargo/env && sudo apt update && sudo apt install -y build-essential gcc pkg-config libssl-dev && git clone https://github.com/RustScan/RustScan.git && cd RustScan && cargo build --release && sudo mv target/release/rustscan /usr/local/bin/
```
