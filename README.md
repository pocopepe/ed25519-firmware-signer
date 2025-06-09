# ed25519-firmware-signer

A robust command-line utility for signing and verifying firmware binaries using the Ed25519 cryptographic algorithm. Designed for integrity verification in embedded systems and secure boot processes.

-----

## Features

  * **Key Pair Generation:** Securely generate Ed25519 signing (private) and public key pairs. Includes checks to prevent accidental overwrites of existing keys.
  * **Firmware Signing:** Create Ed25519 signatures for binary firmware files.
  * **Signature Verification:** Validate firmware binaries against their corresponding signatures and public keys.
  * **Flexible Path Handling:** Supports explicit path specification for firmware, keys, and signatures, along with intelligent defaults.
  * **Dedicated Test Mode:** Provides a specialized mode for managing and executing test scenarios within a structured directory layout.

-----

## Installation

To build and install `ed25519-firmware-signer`, you'll need the [Rust programming language](https://www.rust-lang.org/tools/install) and its package manager, Cargo.

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/your-username/ed25519-firmware-signer.git
    cd ed25519-firmware-signer
    ```

2.  **Build the project:**

    ```bash
    cargo build --release
    ```

    The compiled executable will be located at `target/release/fwsign`.

3.  **Adding to PATH (Linux):**
    For system-wide access, you can move the `fwsign` executable to a directory already included in your system's `PATH`, such as `/usr/local/bin`.

    ```bash
    sudo mv target/release/fwsign /usr/local/bin/
    ```

    After moving, you should be able to run `fwsign` from any directory in your terminal. You can test this by typing `fwsign --help`.

-----

## Usage

`fwsign` is a command-line tool with distinct operations (key generation, signing, verification) and arguments.

### General Command Structure

```bash
fwsign [OPERATION_OPTIONS] [TEST_MODE_COMMAND]
```

### Operations

  * `--gen-keys`, `-g`: Generate a new Ed25519 key pair.
  * `--sign`, `-s`: Sign a firmware binary.
  * `--verify`, `-v`: Verify a firmware signature.

### Default File Locations

Unless explicitly specified with `--path`, `--key`, `--keypath`, or `--signature_path`, `fwsign` looks for or saves files in the **current working directory**. If **test mode** is active, these defaults are relative to the specified test subdirectory.

  * **Private Key:** `signing_key.bin`
  * **Public Key:** `public_key.bin`
  * **Firmware Binary (in Test Mode):** `test.bin` (only in test mode, otherwise `--path` is required).
  * **Signature:** `firmware.sig`

-----

### 1\. Key Generation (`-g`)

Generates a new `signing_key.bin` (private) and `public_key.bin` in the base directory.

  * **Behavior:**
      * If no key files exist, new ones are generated normally.
      * If only `signing_key.bin` exists (and `public_key.bin` is missing), `public_key.bin` will be regenerated from the existing private key.
      * If both `signing_key.bin` and `public_key.bin` exist, the tool will **warn** you and ask for **confirmation** before overwriting them, as old keys cannot be retrieved.

**Example:**

```bash
# Generate keys in the current directory
fwsign -g

# Generate keys within 'test/test0' (requires test_mode feature)
# The 't' is an alias for 'test' subcommand.
cargo run --features test_mode -- -g t test0
```

-----

### 2\. Firmware Signing (`-s`)

Signs a firmware binary using a private key and outputs a signature file.

  * **Firmware Binary:**
      * In **normal mode**, use `--path <firmware_binary_path>` to specify the firmware to sign.
      * In **test mode**, if `--path` is omitted, it defaults to `test.bin` within the test subdirectory.
  * **Private Key:**
      * Use `--key <private_key_path>` for a specific key.
      * If omitted, it defaults to `signing_key.bin` in the base directory. If `signing_key.bin` does not exist, a new key pair will be generated automatically before signing.
  * **Output Signature:** By default, the signature is saved to `firmware.sig` in the base directory.

**Examples:**

```bash
# Sign 'my_firmware.bin' in the current directory
# Requires 'signing_key.bin' to exist in the current directory or be automatically generated.
fwsign -s --path my_firmware.bin

# Sign 'test.bin' within 'test/test0' using keys in that directory (requires test_mode feature)
# Assumes 'test/test0/test.bin' and 'test/test0/signing_key.bin' exist or will be generated.
cargo run --features test_mode -- -s t test0
```

-----

### 3\. Signature Verification (`-v`)

Verifies a firmware binary against its signature and a public key.

  * **Firmware Binary:**
      * In **normal mode**, use `--path <firmware_binary_path>`.
      * In **test mode**, if `--path` is omitted, it defaults to `test.bin` within the test subdirectory.
  * **Signature:**
      * Use `--signature_path <signature_file_path>`.
      * In **test mode**, if omitted, it defaults to `firmware.sig` within the test subdirectory.
  * **Public Key:**
      * Use `--keypath <public_key_path>` for a specific key.
      * If omitted, it defaults to `public_key.bin` in the base directory.

**Examples:**

```bash
# Verify 'my_firmware.bin' with 'firmware.sig' and 'public_key.bin' in the current directory
fwsign -v --path my_firmware.bin --signature_path firmware.sig

# Verify 'test.bin' within 'test/test0' (requires test_mode feature)
# Assumes 'test/test0/test.bin', 'test/test0/firmware.sig', and 'test/test0/public_key.bin' exist.
cargo run --features test_mode -- -v t test0
```

-----

### 4\. Test Mode (`test <folder_name>` or `t <folder_name>`)

The `test_mode` feature (enabled during compilation via `cargo run --features test_mode` or `cargo build --features test_mode`) provides a convenient way to manage test scenarios. It sets the base directory for all file operations (keys, firmware, signatures) to `test/<folder_name>`.

  * **Activation:** Activated by adding `test <folder_name>` or its alias `t <folder_name>` after your main operation flag (`-g`, `-s`, `-v`).
  * **Default Binary Name:** When in test mode and signing (`-s`) or verifying (`-v`), if `--path` is omitted, `fwsign` will default to using `test.bin` inside the specified test folder.
  * **Implicit Key/Signature Paths:** Key files (`signing_key.bin`, `public_key.bin`) and signature files (`firmware.sig`) are also sought/saved within the specified `test/<folder_name>` directory.

**Example Usage (as shown above):**

```bash
# Generate keys in test/my_project_test_case/
cargo run --features test_mode -- -g t my_project_test_case

# Sign the default 'test.bin' in test/my_project_test_case/
cargo run --features test_mode -- -s t my_project_test_case

# Verify the default files in test/my_project_test_case/
cargo run --features test_mode -- -v t my_project_test_case
```

-----

## Key Management Considerations

  * **Key Pair Integrity:** Always ensure your private keys are stored securely. Compromise of a private key allows for unauthorized firmware signing.
  * **Public Key Distribution:** The public key can be safely distributed with your firmware or embedded in devices to facilitate verification.
  * **Key Overwrite Warning:** The `--gen-keys` operation now includes a confirmation prompt if existing keys are detected, preventing accidental loss of active keys.

-----

## Contributing

Contributions are welcome\! Please feel free to open issues or submit pull requests.

-----

## License

This project is licensed under the [MIT License](https://www.google.com/search?q=LICENSE) - see the `LICENSE` file for details.