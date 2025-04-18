#!/usr/bin/env python3
"""
nostr-ownership-proof.py: Tool for generating and verifying proofs of ownership
for keys derived using nostr-derive.py

This script allows a master key holder to prove ownership of derived keys
without revealing the master private key.
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import argparse
from typing import Dict, Tuple, Optional, List, Any

try:
    from bip_utils import Bech32Encoder, Bech32Decoder
    from nostr.key import PrivateKey
    import secp256k1
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error: Missing required libraries.")
    print("Please install required packages: pip install bip-utils nostr secp256k1 cryptography")
    sys.exit(1)

# Constants
DERIVATION_PATH = "BIP85 Deterministic Entropy"
NOSTR_APP_STRING = "bip-nostr-key"

def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to hex string"""
    return b.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str  # Add leading zero if odd length
    return bytes.fromhex(hex_str)

def decode_nostr_key(key: str) -> Optional[bytes]:
    """
    Decode a Nostr key (public or private) from bech32 format to raw bytes
    
    Args:
        key: The Nostr key in bech32 format (npub1... or nsec1...)
        
    Returns:
        bytes: Raw key bytes or None if decoding fails
    """
    try:
        # Try using bip_utils
        hrp, data = Bech32Decoder.Decode(key)
        return data
    except Exception:
        try:
            # Try with nostr library
            if key.startswith("nsec"):
                from nostr.key import PrivateKey
                privkey = PrivateKey.from_nsec(key)
                return hex_to_bytes(privkey.hex())
            elif key.startswith("npub"):
                # This is more complex as nostr doesn't expose direct npub decoding
                # For now, we'll handle this case manually
                from bech32 import bech32_decode, convertbits
                hrp, data = bech32_decode(key)
                if hrp != "npub" or data is None:
                    return None
                decoded = convertbits(data, 5, 8, False)
                if decoded is None:
                    return None
                return bytes(decoded)
        except Exception:
            # Try manual decoding if key is in hex format
            if len(key) == 64 and all(c in '0123456789abcdefABCDEF' for c in key):
                return hex_to_bytes(key)
            # Handle nsec:hex format
            if key.startswith("nsec:") or key.startswith("npub:"):
                hex_part = key[5:]
                if len(hex_part) == 64 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                    return hex_to_bytes(hex_part)
    return None

def derive_key_bip85(master_key: bytes, index: int) -> bytes:
    """
    Derive a child key using BIP-85
    
    Args:
        master_key: 32-byte master key
        index: Child key index
        
    Returns:
        32-byte derived key
    """
    # Application parameters
    app_string = NOSTR_APP_STRING
    entropy_bytes = 32
    
    # Construct derivation data
    data = DERIVATION_PATH.encode()
    data += app_string.encode()
    data += index.to_bytes(4, byteorder='big')
    data += bytes([entropy_bytes])
    
    # HMAC-SHA512 derivation
    h = hmac.new(master_key, data, hashlib.sha512).digest()
    
    # Return first 32 bytes
    return h[:32]

def generate_public_key(private_key: bytes) -> bytes:
    """Generate public key from private key bytes"""
    try:
        # Try secp256k1 first
        privkey = secp256k1.PrivateKey(private_key)
        pubkey = privkey.pubkey.serialize()
        # Return uncompressed key
        return pubkey
    except Exception:
        try:
            # Try nostr library as fallback
            privkey_hex = bytes_to_hex(private_key)
            from nostr.key import PrivateKey
            private_key_obj = PrivateKey(privkey_hex)
            pubkey_hex = private_key_obj.public_key.hex()
            return hex_to_bytes(pubkey_hex)
        except Exception:
            # Try cryptography library as fallback
            private_value = int.from_bytes(private_key, byteorder='big')
            private_key_obj = ec.derive_private_key(private_value, ec.SECP256K1())
            public_key = private_key_obj.public_key()
            return public_key.public_bytes(
                encoding=ec.PublicFormat.CompressedPoint,
                format=ec.Encoding.X962
            )

def to_bech32(data: bytes, hrp: str) -> str:
    """Convert bytes to bech32 encoding with specified human-readable prefix"""
    try:
        # Try bip_utils first
        return Bech32Encoder.Encode(hrp, data)
    except Exception:
        try:
            # Try nostr library
            if hrp == "nsec":
                from nostr.key import PrivateKey
                private_key = PrivateKey(bytes_to_hex(data))
                return private_key.bech32()
            elif hrp == "npub":
                from nostr.key import PrivateKey
                private_key = PrivateKey(bytes_to_hex(data))
                return private_key.public_key.bech32()
        except Exception:
            # Try bech32 module
            try:
                import bech32
                data_5bit = bech32.convertbits(list(data), 8, 5, True)
                if data_5bit:
                    return bech32.bech32_encode(hrp, data_5bit)
            except Exception:
                pass
    # If all methods fail, return a placeholder
    return f"{hrp}1{bytes_to_hex(data)}"

def sign_message(private_key: bytes, message: bytes) -> bytes:
    """
    Sign a message using the private key
    
    Args:
        private_key: The private key as bytes
        message: The message to sign
        
    Returns:
        bytes: The signature
    """
    try:
        # Try secp256k1
        privkey = secp256k1.PrivateKey(private_key)
        sig = privkey.sign(message)
        return sig
    except Exception:
        try:
            # Try nostr library
            from nostr.key import PrivateKey
            private_key_obj = PrivateKey(bytes_to_hex(private_key))
            signature = private_key_obj.sign(message)
            return signature
        except Exception:
            # Try cryptography library
            private_value = int.from_bytes(private_key, byteorder='big')
            private_key_obj = ec.derive_private_key(private_value, ec.SECP256K1())
            signature = private_key_obj.sign(
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return signature

def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify a signature using the public key
    
    Args:
        public_key: The public key as bytes
        message: The message that was signed
        signature: The signature to verify
        
    Returns:
        bool: True if the signature is valid, False otherwise
    """
    try:
        # Try secp256k1
        pubkey = secp256k1.PublicKey(public_key, raw=True)
        return pubkey.verify(signature, message)
    except Exception:
        try:
            # Try nostr library
            from nostr.key import PublicKey
            public_key_obj = PublicKey(bytes_to_hex(public_key))
            return public_key_obj.verify(message, signature)
        except Exception:
            # This is more complex with cryptography library and depends on signature format
            # For now, we'll return False if both previous methods fail
            return False

def generate_ownership_proof(
    master_key: str, 
    derived_pubkey: str, 
    index: int,
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generate a proof that the owner of the master key can derive the key corresponding to derived_pubkey
    
    Args:
        master_key: The master private key in bech32 nsec format
        derived_pubkey: The derived public key to prove ownership of
        index: The derivation index used
        output_file: If provided, write the proof to this file
        
    Returns:
        dict: The proof data structure
    """
    # Decode master key
    master_key_bytes = decode_nostr_key(master_key)
    if not master_key_bytes:
        raise ValueError("Invalid master key format")
    
    # Derive public key from master key
    master_pubkey_bytes = generate_public_key(master_key_bytes)
    master_pubkey = to_bech32(master_pubkey_bytes, "npub")
    
    # Decode derived public key
    derived_pubkey_bytes = decode_nostr_key(derived_pubkey)
    if not derived_pubkey_bytes:
        raise ValueError("Invalid derived public key format")
    
    # Derive the child key using BIP-85
    derived_key_bytes = derive_key_bip85(master_key_bytes, index)
    
    # Generate public key from derived key
    computed_pubkey_bytes = generate_public_key(derived_key_bytes)
    computed_pubkey = to_bech32(computed_pubkey_bytes, "npub")
    
    # Verify that our computed key matches the claimed derived key
    if bytes_to_hex(computed_pubkey_bytes) != bytes_to_hex(derived_pubkey_bytes):
        raise ValueError(f"Derived key mismatch. Master key cannot derive the specified npub with index {index}")
    
    # Create a message to sign
    # This message will include data that proves the relationship
    message = f"Proof that {master_pubkey} can derive {derived_pubkey} with index {index}".encode()
    
    # Sign using master key
    master_signature = sign_message(master_key_bytes, message)
    
    # Sign using derived key
    derived_signature = sign_message(derived_key_bytes, message)
    
    # Construct the proof
    proof = {
        "master_pubkey": master_pubkey,
        "derived_pubkey": derived_pubkey,
        "derivation_index": index,
        "message": message.decode(),
        "master_signature": base64.b64encode(master_signature).decode(),
        "derived_signature": base64.b64encode(derived_signature).decode(),
        "verification_method": "dual-signature",
    }
    
    # Save proof to file if requested
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(proof, f, indent=2)
        print(f"Proof saved to {output_file}")
    
    return proof

def verify_ownership_proof(proof_file: str) -> bool:
    """
    Verify a proof of ownership
    
    Args:
        proof_file: Path to the proof file
        
    Returns:
        bool: True if the proof is valid, False otherwise
    """
    # Read the proof file
    with open(proof_file, 'r') as f:
        proof = json.load(f)
    
    # Extract proof components
    master_pubkey = proof["master_pubkey"]
    derived_pubkey = proof["derived_pubkey"]
    index = proof["derivation_index"]
    message = proof["message"].encode()
    master_signature = base64.b64decode(proof["master_signature"])
    derived_signature = base64.b64decode(proof["derived_signature"])
    
    # Decode public keys
    master_pubkey_bytes = decode_nostr_key(master_pubkey)
    derived_pubkey_bytes = decode_nostr_key(derived_pubkey)
    
    if not master_pubkey_bytes or not derived_pubkey_bytes:
        print("Error: Invalid public key format in proof")
        return False
    
    # Verify signatures
    master_valid = verify_signature(master_pubkey_bytes, message, master_signature)
    derived_valid = verify_signature(derived_pubkey_bytes, message, derived_signature)
    
    if not master_valid:
        print("Error: Master key signature verification failed")
        return False
    
    if not derived_valid:
        print("Error: Derived key signature verification failed")
        return False
    
    print(f"Signatures verified successfully!")
    print(f"This proves that the owner of {master_pubkey} claims ownership of {derived_pubkey} with index {index}")
    print("\nNote: This verification confirms signature validity but does not verify the BIP-85 derivation relationship.")
    print("To verify the derivation relationship, you would need a ZK-proof system as described in the specification.")
    
    return True

def main():
    parser = argparse.ArgumentParser(description="Nostr Ownership Proof Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Proof generation command
    prove_parser = subparsers.add_parser("generate", help="Generate a proof of ownership")
    prove_parser.add_argument("--master-nsec", required=True, help="Master private key in nsec format")
    prove_parser.add_argument("--derived-npub", required=True, help="Derived public key in npub format")
    prove_parser.add_argument("--index", required=True, type=int, help="Derivation index")
    prove_parser.add_argument("--output", help="Output file to save the proof")
    
    # Verification command
    verify_parser = subparsers.add_parser("verify", help="Verify a proof of ownership")
    verify_parser.add_argument("--proof-file", required=True, help="Path to the proof file")
    
    args = parser.parse_args()
    
    if args.command == "generate":
        try:
            proof = generate_ownership_proof(
                args.master_nsec, 
                args.derived_npub, 
                args.index,
                args.output
            )
            if not args.output:
                print(json.dumps(proof, indent=2))
        except Exception as e:
            print(f"Error generating proof: {e}")
            sys.exit(1)
    
    elif args.command == "verify":
        try:
            result = verify_ownership_proof(args.proof_file)
            if not result:
                print("Proof verification FAILED")
                sys.exit(1)
            print("Proof verification SUCCEEDED")
        except Exception as e:
            print(f"Error verifying proof: {e}")
            sys.exit(1)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()