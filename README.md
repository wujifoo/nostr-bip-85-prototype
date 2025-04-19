# Nostr BIP-85 Key Derivation Tool

## Sovereign Anonymous Identities

One of the earliest memes was [on the internet nobody knows you're a dog](https://en.wikipedia.org/wiki/On_the_Internet,_nobody_knows_you're_a_dog). Online identity privacy commonly (1) degrades to zero in a corporate owned world, (2) bot whackamole.

What has lacked in social media and identity in general is a simple way to airgap identities easily with most systems still tying you back to one email address (and in more recent years) or cell phone number. The latter is very difficult to avoid and even more difficult without KYC. What an individual SHOULD be able to do is have freedom of expression between (for example).

- A professional "work" identity
- A personal social media identity
- A soccer club or hobby-related identity
- A religious identity
- Political discussion identity
- Local community identity
- Any other context-specific persona

### So what?
In Nostr, the solution is the user creates multiple unrelated npubs. The "catch" is that the individual can't carry good reputation from one identity to another or link them in some other (constrained) way at a later time. To do so with 2 or 3 npubs, if they wanted to prove a connection, they can do this with signed Nostr notes textually confirming a relationship (like an affidavit).

The fundamental improvement here is moving from a trust-based model ("believe me when I say these accounts are connected") to a verification-based model ("I can mathematically prove these accounts are connected without revealing anything else"). This creates a much stronger foundation for pseudonymous identity systems. Another disadvantage of the attestation posts is: if A attests to B and B attests to C, you've created a public chain connecting all three. The BIP-85 approach exposes no more information than it needs to. 

For a deeper comparison and usecases, see:
- [USE-CASES.md](USE-CASES.md): Real-world use cases and examples
- [PROOF-README.md](PROOF-README.md): Complete documentation of the proof tools

### What happens?
This experiment for the Nostr network allows a user with a master key (nsec) to derive child nsecs that may be used anonymously that can be: (1) recreated by the master, (2) proven to be derived from the master without exposing the master's identity.    

### Project tools
1. A command-line utility for deterministically deriving multiple Nostr identities from a single master key using BIP-85.
2. Utilities to provide cryptographic (zero knowledge) proofs of the relationship between Nostr identities.


## Key Features

1. **BIP-85 Key Derivation**: Deterministically derive multiple Nostr keys from a single master key
2. **Multiple Key Formats**: Support for various formats (nsec1/bech32, nsec:HEX, raw hex)
3. **Ownership Proof Tools**: Two different approaches to prove ownership of derived keys:
   - `simple_proof.py`: Straightforward tool that proves multiple derived keys come from the same master
   - `nostr-zk-proof.py`: Challenge-response verification with zero-knowledge properties
   

## TODO

1. Explore if derived keys can be made with a password for each (like you can with BIP-85) instead of indexes.a
2. If this is useful it could be applied to nsec extensions or apps like amber or nsec.app. I guess it could also be useful directly in a client(?). 
 
## Derivation Tool Overview

This tool allows Nostr users to:

1. Generate a master Nostr key pair
2. Derive multiple child identities from the master key using BIP-85
3. Manage these identities securely with encrypted storage
4. Export keys in Nostr-compatible formats (npub/nsec)

## Installation

### Prerequisites

- Python 3.7+ (tested with Python 3.13)
- pip

### Install from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/nostr-bip-85-prototype.git
cd nostr-bip-85-prototype

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x nostr-derive.py

# Optional: Create a symlink for easier access
ln -s $(pwd)/nostr-derive.py /usr/local/bin/nostr-derive
```

## Usage

You can use this tool in two main ways:

1. **With Encrypted Storage**: Store your master key and derived identities securely
2. **Without Storage**: Derive keys on-the-fly without storing anything

### General Options

```bash
# Enable debug output
nostr-derive --debug [command]
```

### Initialize a Master Key

```bash
# Create a new master key (you'll be prompted for a password)
nostr-derive init

# Import an existing key
nostr-derive init --nsec nsec1...

# Skip storing the key
nostr-derive init --nsec nsec1... --no-store
```

### Create a Derived Identity

```bash
# Create an identity with a label
nostr-derive create --label "Work Identity"

# Create an identity with a specific index
nostr-derive create --label "Social Media" --index 42

# Derive directly from a master key without storing
nostr-derive create --nsec nsec1... --index 1 --no-store
```

### List All Identities

```bash
# List all your derived identities
nostr-derive list
```

### Export an Identity

```bash
# Export a specific identity (public key only by default)
nostr-derive export --label "Work Identity"

# Export including the private key
nostr-derive export --label "Work Identity" --show-private

# Re-derive a key without using the keystore
nostr-derive export --nsec nsec1... --index 42 --show-private
```

## Features

- **BIP-85 Derivation**: Deterministically derive multiple keys from a single master key
- **Multiple Storage Options**: Use with or without encrypted storage
- **Key Format Support**: Import/export keys in multiple formats (nsec1 bech32, nsec:HEX, or raw hex)
- **Robust Encoding**: Multiple fallback methods to ensure proper encoding of keys
- **Debug Mode**: Detailed debug output with the `--debug` flag
- **Ownership Proof Tools**: Advanced tools for proving relationships between keys:
  - `simple_proof.py`: Creates straightforward proofs that multiple keys are derived from the same master key
    - Useful for demonstrating identity relationships to trusted parties
    - Generates JSON proof files that show the master npub and derived npub/nsec pairs
    - Example: `python simple_proof.py --master-nsec nsec1... --indices 1,2,3 --output proof.json`
  
  - `nostr-zk-proof.py`: Implements a challenge-response protocol with zero-knowledge properties
    - More privacy-preserving approach for selective disclosure
    - Proves ownership without revealing all relationships
    - Three-step process: setup, prove, verify
    - Example: 
      ```
      python nostr-zk-proof.py setup --output-dir ~/.nostr-zk
      python nostr-zk-proof.py prove --master-nsec nsec1... --derived-npub npub1... --index 1 --output proof.json
      python nostr-zk-proof.py verify --proof-file proof.json
      ```
  
  For detailed documentation of these tools, see [PROOF-README.md](PROOF-README.md)
  For real-world use cases and examples, see [USE-CASES.md](USE-CASES.md)

## Security Features

- All private keys are stored encrypted using a password
- Strong PBKDF2 key derivation for encryption
- Secure file permissions for the keystore
- Memory safety considerations
- BIP-85 derivation ensures deterministic keys that can be recovered from the master key

## Dependencies

- `bip-utils`: For reliable bech32 encoding
- `nostr`: For Nostr key formatting
- `cryptography`: For secure storage
- `secp256k1`: For key operations
- `bech32`: For encoding/decoding
- `ecdsa`: For key operations (fallback)
- `click`: For the CLI interface

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
