# Cipher 🔐

Encrypt/Decrypt your files and folder with AES-256. Built with Rust 🦀 for security 🔐 and speed ⚡️.

## Installation

```bash
curl -L https://raw.githubusercontent.com/ClemDev2000/cipher/main/download-latest.sh | sh
```

## Examples

Encrypt a file:

```bash
./cipher encrypt -i file.txt -o file.enc
```

Decrypt a file:

```bash
./cipher decrypt -i file.enc -o file.txt
```

Encrypt and delete the original file:

```bash
./cipher encrypt -i file.txt -o file.enc --delete
```

Encrypt a directory:

```bash
./cipher encrypt -i my_dir -o my_dire_enc
# output my_dire_enc.tar.enc
```

To encrypt a directory, `cipher` will always append `.tar.enc` at the end of the output (`-o`) option.

To ensure the decryption is done correctly. **DO NOT** remove the `.tar.enc` extension.

## Build from source

> To build the project on your computer ensure you have [Rust](https://www.rust-lang.org/tools/install) installed.

Clone the repo:

```bash
git clone https://github.com/ClemDev2000/cipher
```

Build in release mode:

```bash
cargo build --release
```

Execute the binary:

```bash
./target/release/cipher
```
