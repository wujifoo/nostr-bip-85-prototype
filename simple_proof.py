#!/usr/bin/env python3
"""
Simple tool to prove that multiple keys are derived from the same master key using BIP-85
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import argparse
from typing import Dict, List, Optional, Any

# Helper functions
def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to hex string"""
    return b.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str  # Add leading zero if odd length
    return bytes.fromhex(hex_str)

def decode_bech32(key: str) -> Optional[bytes]:
    """Decode a bech32 key (nsec or npub) to raw bytes"""
    try:
        import bech32
        
        # Handle bech32 formatted keys
        if key.startswith("nsec1") or key.startswith("npub1"):
            hrp, data = bech32.bech32_decode(key)
            print(f"Decoded key with HRP: {hrp}")
            
            if data is None:
                print("Failed to decode key")
                return None
                
            # Convert from 5-bit to 8-bit
            decoded = bech32.convertbits(data, 5, 8, False)
            if decoded is None:
                print("Failed to convert bits")
                return None
                
            return bytes(decoded)
        
        # Handle nsec: prefix with hex format
        elif key.startswith("nsec:"):
            hex_part = key[5:]  # Remove "nsec:" prefix
            if len(hex_part) == 64 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                print(f"Decoded key with nsec: prefix")
                return hex_to_bytes(hex_part)
            else:
                print(f"Invalid hex part after nsec: prefix")
                return None
        
        # Handle npub: prefix with hex format
        elif key.startswith("npub:"):
            hex_part = key[5:]  # Remove "npub:" prefix
            if len(hex_part) == 64 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                print(f"Decoded key with npub: prefix")
                return hex_to_bytes(hex_part)
            else:
                print(f"Invalid hex part after npub: prefix")
                return None
        
        # Handle hex format
        elif len(key) == 64 and all(c in '0123456789abcdefABCDEF' for c in key):
            print(f"Decoded raw hex format key")
            return hex_to_bytes(key)
            
        print(f"Unrecognized key format: {key[:10]}...")
    except Exception as e:
        print(f"Error decoding key: {e}")
    
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
    app_string = "bip-nostr-key"
    entropy_bytes = 32
    
    # Construct derivation data
    data = b"BIP85 Deterministic Entropy"
    data += app_string.encode()
    data += index.to_bytes(4, byteorder='big')
    data += bytes([entropy_bytes])
    
    # HMAC-SHA512 derivation
    h = hmac.new(master_key, data, hashlib.sha512).digest()
    
    # Return first 32 bytes
    return h[:32]

def get_pubkey(privkey: bytes) -> bytes:
    """Get the public key from a private key"""
    try:
        import secp256k1
        private_key = secp256k1.PrivateKey(privkey)
        pubkey = private_key.pubkey.serialize()
        return pubkey[1:]  # Remove the prefix byte
    except Exception as e:
        print(f"Error getting public key: {e}")
        return None

def to_bech32(data: bytes, hrp: str) -> str:
    """Convert bytes to bech32 format with given prefix"""
    try:
        import bech32
        data_5bit = bech32.convertbits(list(data), 8, 5, True)
        if data_5bit:
            return bech32.bech32_encode(hrp, data_5bit)
    except Exception as e:
        print(f"Error encoding to bech32: {e}")
    
    # Fallback
    return f"{hrp}1{bytes_to_hex(data)}"

def prove_relationship(master_nsec: str, indices: List[int], output_file: Optional[str] = None) -> Dict[str, Any]:
    """
    Generate a proof that multiple keys are derived from the same master key
    
    Args:
        master_nsec: Master private key in nsec format
        indices: List of derivation indices
        output_file: Optional file to save the proof
        
    Returns:
        The proof data structure
    """
    # Decode master key
    master_key_bytes = decode_bech32(master_nsec)
    if not master_key_bytes:
        raise ValueError("Failed to decode master key")
        
    # Get master public key
    master_pubkey_bytes = get_pubkey(master_key_bytes)
    if not master_pubkey_bytes:
        raise ValueError("Failed to get master public key")
        
    master_npub = to_bech32(master_pubkey_bytes, "npub")
    
    # Derive keys for each index
    derived_keys = []
    for index in indices:
        # Derive child key
        derived_key_bytes = derive_key_bip85(master_key_bytes, index)
        
        # Get public key
        derived_pubkey_bytes = get_pubkey(derived_key_bytes)
        if not derived_pubkey_bytes:
            raise ValueError(f"Failed to get public key for index {index}")
            
        # Convert to bech32
        derived_nsec = to_bech32(derived_key_bytes, "nsec")
        derived_npub = to_bech32(derived_pubkey_bytes, "npub")
        
        # Calculate key hash for verification
        key_hash = hashlib.sha256(derived_key_bytes).hexdigest()
        
        derived_keys.append({
            "index": index,
            "npub": derived_npub,
            "nsec": derived_nsec,
            "key_hash": key_hash
        })
    
    # Create the proof data
    proof = {
        "master_npub": master_npub,
        "derived_keys": derived_keys,
        "verification_method": "bip85-derivation"
    }
    
    # Save to file if requested
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(proof, f, indent=2)
        print(f"Proof saved to {output_file}")
    
    return proof

def main():
    parser = argparse.ArgumentParser(description="Simple Nostr BIP-85 Relationship Proof Tool")
    
    # Options
    parser.add_argument("--master-nsec", required=True, help="Master private key in nsec format")
    parser.add_argument("--indices", required=True, help="Comma-separated list of indices to include (e.g., '1,2,3')")
    parser.add_argument("--output", help="Output file to save the proof")
    
    args = parser.parse_args()
    
    try:
        # Parse indices
        indices = [int(idx.strip()) for idx in args.indices.split(",")]
        
        # Generate proof
        proof = prove_relationship(args.master_nsec, indices, args.output)
        
        # Print summary
        print("\nProof generation successful!")
        print(f"Master public key: {proof['master_npub']}")
        print("\nDerived keys:")
        for key in proof["derived_keys"]:
            print(f"  Index {key['index']}: {key['npub']}")
        
        if not args.output:
            print("\nProof data:")
            print(json.dumps(proof, indent=2))
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()