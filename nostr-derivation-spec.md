# Nostr BIP-85 Key Derivation Tool Specification

## Overview

This document specifies a command-line utility that implements BIP-85 derivation for Nostr keys. The tool allows a user with a master Nostr key pair to deterministically derive child key pairs for different contexts, creating separate identities that cannot be linked by external observers.

## Core Functionality

1. Generate a master Nostr key pair if one doesn't exist
2. Derive child Nostr key pairs using BIP-85
3. Label and store derived identities securely
4. Export keys in Nostr-compatible formats (npub/nsec)

## Technical Requirements

### Dependencies

- `bip85`: For BIP-85 key derivation
- `secp256k1`: For key operations
- `nostr-python`: For Nostr key formatting
- `cryptography`: For secure storage
- `click`: For CLI interface

### Implementation Details

#### 1. Key Generation and Derivation

The master key is a standard secp256k1 private key (the same curve used in Bitcoin and Nostr). BIP-85 is used to derive child entropy from this master key, which is then used to create new Nostr key pairs.

```python
def derive_child_key(master_nsec, index, label):
    """
    Derive a child key from the master key using BIP-85
    
    Args:
        master_nsec: The master private key in bech32 nsec format
        index: A unique index number for this child key
        label: A human-readable label for this identity
        
    Returns:
        tuple: (child_nsec, child_npub) in bech32 format
    """
```

#### 2. Key Storage

Store the master key and derived keys securely using encryption. Each derived key should be associated with its label and index.

```python
def store_key_secure(key_data, password):
    """
    Securely store key information with password protection
    
    Args:
        key_data: Dictionary with key information
        password: User password for encryption
    """
```

#### 3. Nostr Formatting

Convert between raw keys and Nostr's bech32 format (npub/nsec).

```python
def to_nostr_format(private_key):
    """
    Convert raw private key to Nostr nsec and npub formats
    
    Args:
        private_key: Raw bytes of the private key
        
    Returns:
        tuple: (nsec, npub) strings in bech32 format
    """
```

## CLI Interface

The tool should provide the following commands:

### Initialize Master Key

```
nostr-derive init [--force]
```

- Creates a new master key if none exists
- `--force` overwrites an existing key (with appropriate warnings)
- Prompts for a password to protect the key storage

### Create Derived Identity

```
nostr-derive create --label "Work Identity" [--index 1]
```

- Derives a new Nostr key pair using the given label and index
- If no index is provided, uses the next available index
- Displays the new npub/nsec pair and stores it securely

### List Identities

```
nostr-derive list
```

- Lists all derived identities with their labels and public keys (npub)
- Does not display private keys for security

### Export Identity

```
nostr-derive export --label "Work Identity" [--show-private]
```

- Exports a specific identity
- `--show-private` option reveals the private key (nsec)
- Warns the user about private key exposure

## Security Considerations

1. **Secure Storage**: All private keys must be stored encrypted
2. **Password Protection**: Strong password requirements for key encryption
3. **Memory Handling**: Clear sensitive information from memory after use
4. **Backup Instructions**: Provide users with instructions for securely backing up their master key

## Example Usage Flow

```
# Initialize a new master key
$ nostr-derive init
Creating new master key...
Enter password to protect your keys: ********
Master key created successfully!
Your master public key (npub): npub1qqqqqq...

# Create a work identity
$ nostr-derive create --label "Work Identity"
Enter password: ********
Created new identity "Work Identity"
Public key (npub): npub1abcdef...

# Create a social media identity
$ nostr-derive create --label "Social Media"
Enter password: ********
Created new identity "Social Media"
Public key (npub): npub1ghijkl...

# List all identities
$ nostr-derive list
Enter password: ********
Available identities:
1. Work Identity (npub1abcdef...)
2. Social Media (npub1ghijkl...)

# Export a specific identity
$ nostr-derive export --label "Work Identity" --show-private
Enter password: ********
WARNING: You are about to reveal a private key. Make sure no one is watching.
Work Identity:
  Public key (npub): npub1abcdef...
  Private key (nsec): nsec1xxxxxx...
```

## Future Extensions

1. **Nostr Client Integration**: Allow direct relay posting from derived identities
2. **Zero-Knowledge Proof Generation**: Implement ZK proofs to prove ownership of derived keys
3. **Hardware Wallet Support**: Allow master key to be stored on hardware devices
4. **Backup and Recovery**: Tools for securely backing up and restoring the key hierarchy

## Implementation Guidance

- Prioritize security over convenience
- Follow the principle of least privilege
- Provide clear warnings when exposing sensitive information
- Include comprehensive testing, especially for the cryptographic components
- Document the derivation path clearly so it can be reimplemented if needed
