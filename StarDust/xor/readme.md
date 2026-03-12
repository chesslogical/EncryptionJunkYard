
\# XOR File Obfuscator



\*\*Simple command-line tool to XOR a file with a repeating key file\*\*  

Reversibly obfuscate (or de-obfuscate) any file by XORing its bytes with the bytes of a key file that loops indefinitely.



Since XOR is its own inverse, running the tool twice with the \*\*same key file\*\* restores the original content.



\## Features



\- Atomic in-place replacement (using temporary file + rename)

\- Efficient buffered I/O (64 KiB chunks)

\- Repeating key stream (loops from start when key file ends)

\- Default key: `key.key` next to the executable

\- Modern Rust (edition 2024, Rust 1.94+)



\## Security / Usage Notes



\*\*This is obfuscation, not encryption.\*\*  

XOR with a known or guessable key provides \*\*no real security\*\* against anyone who knows (or can guess) you're using XOR + a key file.



Use cases:

\- Quick reversible scrambling of test data / non-sensitive files

\- Simple one-time pad style processing when key is truly secret and as long as the data

\- Educational / prototyping purposes



For actual cryptography, use proper authenticated encryption (e.g. AES-GCM, XChaCha20-Poly1305).



\## Requirements



\- Rust 1.94 or newer



\## Installation



1\. Clone the repository:

&nbsp;  ```bash

&nbsp;  git clone https://github.com/yourusername/xor.git

&nbsp;  cd xor

&nbsp;  ```



2\. Build and install globally (recommended):

&nbsp;  ```bash

&nbsp;  cargo install --path .

&nbsp;  ```



&nbsp;  Or just build the release binary:

&nbsp;  ```bash

&nbsp;  cargo build --release

&nbsp;  ```

&nbsp;  → Binary will be at `target/release/xor.exe` (Windows) or `target/release/xor` (Unix-like)



\## Usage



Basic usage (uses default `key.key` next to the executable):



```bash

xor path/to/yourfile.bin

```



With custom key file:



```bash

xor important-data.txt --key my-secret-key.bin

```



Full help:



```text

Simple XOR file obfuscator using a repeating key file



Usage: xor \[OPTIONS] <FILE>



Arguments:

&nbsp; <FILE>  Input file to transform (will be overwritten atomically)



Options:

&nbsp; -k, --key <KEY\_FILE>    Path to key file (default: key.key next to executable)

&nbsp; -h, --help              Print help

&nbsp; -V, --version           Print version

```



\### Examples



```bash

\# Obfuscate a file (using default key)

xor document.pdf



\# Obfuscate with specific key

xor large-video.mp4 --key super-long-key.bin



\# Restore original (run again with same key)

xor document.pdf --key my-secret-key.bin

```



\*\*Warning\*\*: The file is \*\*overwritten in place\*\*. Always work on a copy if the content is important!



\## Building from Source



```bash

git clone https://github.com/yourusername/xor.git

cd xor

cargo build --release

```



\## Dependencies (as of March 2026)



\- clap ^4.5 (CLI parsing with derive macros)

\- tempfile ^3.26 (atomic file replacement)



\## Contributing



Pull requests welcome!



Ideas for improvements:

\- Progress bar for large files (e.g. via `indicatif`)

\- Support for multiple input files

\- `--decrypt` flag (just a synonym, since XOR is symmetric)

\- Option to use hex/base64-encoded key instead of file

\- Dry-run / backup original file



Please run `cargo fmt` and `cargo clippy --fix --allow-dirty` before submitting.



\## License



MIT OR Apache-2.0 (your choice)



Made in Secaucus, NJ with Rust — Mark

```



Feel free to customize:

\- Replace the GitHub URL with your actual repo (or remove if private)

\- Add badges later (crates.io version, build status, etc.) if you publish it

\- Change license if you prefer something else



Let me know if you'd like:

\- A shorter version

\- More emphasis on security warnings

\- Addition of example screenshots / before-after diagram

\- Integration instructions with your `stardust-keygen` tool (e.g. "generate key with stardust-keygen then xor files")



Happy coding!

