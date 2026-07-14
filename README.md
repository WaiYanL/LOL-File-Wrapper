# <img src="icon.png" width="45" valign="middle"> LOL File Wrapper

A secure, desktop-based file archiving and encryption tool built with Python and PySide6 for GUI. 

LOL File Wrapper allows you to pack single or multiple files into a custom archive (defaulting to `.lol`). It also features AES-256 encryption to ensure your data remains completely private.

## Features
* **Multi-File Bundling:** Pack multiple files into a single archive.
* **Encryption:** Secures your archive using AES-256-CTR and PBKDF2HMAC key derivation.
* **Built-in Compression:** Uses zlib to shrink file sizes before packing, saving disk space (although it is not very good in file compression).
* **Custom Extensions:** Output files default to `.lol`, but you can specify any custom extension.
* **Lossless Unpacking:** Restores your files exactly as they were with zero data loss.

## Security
* **Algorithm:** AES-256 in CTR mode.
* **Key Derivation:** PBKDF2HMAC using SHA-256 with 200,000 iterations to protect against brute-force attacks.
* **Salting:** Unique 16-byte random salts and nonces are generated for every encrypted payload.
* **Metadata Protection:** Original filenames are obfuscated using a custom Xorshift cipher before being written to the JSON header.

> **⚠️ WARNING:** There is no "forgot password" option. If you encrypt an archive and forget your passphrase, your data is impossible to recover. Use at your own risk.

## Prerequisites
Most of the libraries used in this project are part of the Python Standard Library and do not require installation. 

You only need Python 3.9+ and the following external packages:
* `PySide6`
* `cryptography`
  

You can install these libraries using:
* `pip install pyside6`
* `pip install cryptography`

## How to Run the Script

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/WaiYanL/lol-file-wrapper.git
   cd lol-file-wrapper
   python3 file_wrapper.py
