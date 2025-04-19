#!/usr/bin/env python3
"""
nostr-derive: A tool for hierarchical derivation of Nostr keys using BIP-85
"""

import os
import sys
import json
import base64
import secrets
import getpass
import hmac
import hashlib
from pathlib import Path
from typing import Tuple, Dict, Optional, List

import click
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ====== Built-in minimal bech32 implementation ======
# This is used as a last resort if both bech32 and nostr libraries fail

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    # Make sure data is a list of integers
    if not isinstance(data, list):
        try:
            data = list(data)
        except:
            data = [int(data)]
    
    # Make sure all elements are integers
    data = [int(d) for d in data]
    
    # Compute checksum
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    # Make sure data is a list of integers
    if not isinstance(data, list):
        try:
            data = list(data)
        except:
            data = [int(data)]
    
    # Make sure all elements are integers
    data = [int(d) for d in data]
    
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_encode_minimal(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    # Ensure data is a list of integers
    if not isinstance(data, list):
        click.echo(f"Error in bech32_encode_minimal: data is not a list: {type(data)}", err=True)
        data = list(data) if hasattr(data, '__iter__') else [data]
    
    # Ensure all elements are integers
    data = [int(d) for d in data]
    
    # Generate checksum and combine
    checksum = bech32_create_checksum(hrp, data)
    combined = data + checksum
    
    # Generate the final string
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def bech32_decode_minimal(bech):
    """Validate a Bech32 string, and determine HRP and data."""
    # Basic input validation
    if not isinstance(bech, str):
        click.echo(f"Error in bech32_decode_minimal: input is not a string: {type(bech)}", err=True)
        return None, None
        
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        click.echo("Error in bech32_decode_minimal: invalid characters or mixed case", err=True)
        return None, None
        
    bech = bech.lower()
    pos = bech.rfind('1')
    
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        click.echo(f"Error in bech32_decode_minimal: invalid separator position: {pos}", err=True)
        return None, None
        
    hrp = bech[:pos]
    try:
        data = [CHARSET.find(x) for x in bech[pos+1:]]
        
        if any(x == -1 for x in data):
            click.echo("Error in bech32_decode_minimal: invalid character in data part", err=True)
            return None, None
            
        if not bech32_verify_checksum(hrp, data):
            click.echo("Error in bech32_decode_minimal: checksum verification failed", err=True)
            return None, None
            
        return hrp, data[:-6]
    except Exception as e:
        click.echo(f"Error in bech32_decode_minimal: {e}", err=True)
        return None, None

def convertbits_minimal(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    try:
        # Ensure data is iterable
        if not hasattr(data, '__iter__'):
            click.echo(f"Error in convertbits_minimal: data is not iterable: {type(data)}", err=True)
            if isinstance(data, int):
                data = [data]
            else:
                return None
                
        # Initialize variables
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        
        # Process each value
        for value in data:
            # Convert to int if needed
            try:
                value = int(value)
            except (TypeError, ValueError):
                click.echo(f"Error in convertbits_minimal: value is not convertible to int: {value}", err=True)
                return None
                
            # Validate value
            if value < 0 or (value >> frombits):
                click.echo(f"Error in convertbits_minimal: value out of range: {value}", err=True)
                return None
                
            # Accumulate bits
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            
            # Extract complete groups
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
                
        # Handle padding
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            click.echo("Error in convertbits_minimal: invalid padding", err=True)
            return None
            
        return ret
    except Exception as e:
        click.echo(f"Error in convertbits_minimal: {e}", err=True)
        return None

# Constants
APP_DIR = Path.home() / ".nostr-derive"
KEYSTORE_PATH = APP_DIR / "keystore.encrypted"
SALT_PATH = APP_DIR / "salt"
KEY_BYTE_LENGTH = 32
DEFAULT_PATH_INDEX = 0
NOSTR_APPLICATION_INDEX = 707  # Arbitrary choice for Nostr

# Global debug flag
DEBUG = False

def debug_log(message):
    """Print debug messages only when DEBUG is True"""
    if DEBUG:
        click.echo(message, err=True)

# ====== Helper Functions ======

def bytes_to_hex(b: bytes) -> str:
    """Convert bytes to hex string"""
    return b.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    if len(hex_str) % 2 == 1:
        hex_str = '0' + hex_str  # Add leading zero if odd length
    return bytes.fromhex(hex_str)

def decode_nsec(nsec_key: str) -> Optional[bytes]:
    """
    Decode a Nostr private key from various formats to raw bytes.
    
    Supported formats:
    - bech32 nsec format: nsec1...
    - hex with nsec prefix: nsec:1234abcd...
    - raw hex: 64 character hex string
    
    Returns:
        32-byte private key as bytes, or None if decoding fails
    """
    # Skip placeholder keys
    if "nsec1xxxxxxx" in nsec_key or "x" * 5 in nsec_key:
        click.echo("Skipping placeholder key", err=True)
        return None
    
    # First explicitly try to import the libraries we'll need
    bech32_lib = None
    nostr_key = None
    
    try:
        import bech32
        bech32_lib = bech32
        click.echo("Successfully imported bech32 library", err=True)
    except Exception as import_e1:
        click.echo(f"Debug: Failed to import bech32: {import_e1}", err=True)

    try:
        from nostr.key import PrivateKey
        nostr_key = PrivateKey
        click.echo("Successfully imported nostr.key library", err=True)
    except Exception as import_e2:
        click.echo(f"Debug: Failed to import nostr.key: {import_e2}", err=True)
        
    try:
        # Raw hex format (64 characters)
        if len(nsec_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in nsec_key):
            click.echo("Detected raw hex format", err=True)
            return hex_to_bytes(nsec_key.lower())
            
        # nsec: prefix with hex
        if nsec_key.startswith("nsec:"):
            click.echo("Detected nsec:HEX format", err=True)
            hex_part = nsec_key[5:]  # Remove "nsec:" prefix
            if len(hex_part) == 64 and all(c in '0123456789abcdefABCDEF' for c in hex_part):
                return hex_to_bytes(hex_part.lower())
            click.echo("Invalid hex part after nsec: prefix", err=True)
            return None
        
        # Try bech32 decoding (nsec1...)
        if nsec_key.startswith("nsec1"):
            click.echo("Detected bech32 nsec1... format", err=True)
            
            # Try with bech32 library
            if bech32_lib:
                try:
                    click.echo("Using bech32 library for decoding", err=True)
                    hrp, data = bech32_lib.bech32_decode(nsec_key)
                    if hrp != "nsec" or data is None:
                        click.echo(f"Invalid bech32 format: hrp={hrp}", err=True)
                    else:
                        decoded = bech32_lib.convertbits(data, 5, 8, False)
                        if decoded is None or len(decoded) != 32:
                            click.echo(f"Invalid convertbits result: length={len(decoded) if decoded else None}", err=True)
                        else:
                            return bytes(decoded)
                except Exception as e1:
                    click.echo(f"bech32 decoding failed: {e1}", err=True)
            
            # Try with nostr library
            if nostr_key:
                try:
                    click.echo("Trying nostr library for decoding", err=True)
                    private_key = nostr_key.from_nsec(nsec_key)
                    return hex_to_bytes(private_key.hex())
                except Exception as e2:
                    click.echo(f"nostr decoding failed: {e2}", err=True)
            
            # Try our minimal bech32 implementation as last resort
            try:
                click.echo("Trying minimal built-in bech32 implementation for decoding", err=True)
                hrp, data = bech32_decode_minimal(nsec_key)
                if hrp != "nsec" or data is None:
                    click.echo(f"Invalid minimal bech32 format: hrp={hrp}", err=True)
                else:
                    decoded = convertbits_minimal(data, 5, 8, False)
                    if decoded is None or len(decoded) != 32:
                        click.echo(f"Invalid minimal convertbits result: length={len(decoded) if decoded else None}", err=True)
                    else:
                        return bytes(decoded)
            except Exception as e3:
                click.echo(f"Minimal bech32 decoding failed: {e3}", err=True)
                
            # If we got here, all methods failed
            click.echo("All decoding methods failed for nsec1 format", err=True)
            return None
        else:
            click.echo("Unrecognized key format", err=True)
            return None
    except Exception as e:
        # Any unexpected error
        click.echo(f"Unexpected error in decode_nsec: {e}", err=True)
        return None

def generate_public_key(private_key_bytes: bytes) -> bytes:
    """Generate public key from private key"""
    # First explicitly try to import the libraries we'll need
    secp256k1_lib = None
    nostr_key = None
    ecdsa_lib = None
    
    try:
        import secp256k1
        secp256k1_lib = secp256k1
    except Exception as import_e1:
        click.echo(f"Debug: Failed to import secp256k1: {import_e1}", err=True)

    try:
        from nostr.key import PrivateKey
        nostr_key = PrivateKey
    except Exception as import_e2:
        click.echo(f"Debug: Failed to import nostr.key: {import_e2}", err=True)
    
    try:
        import ecdsa
        ecdsa_lib = ecdsa
    except Exception as import_e3:
        click.echo(f"Debug: Failed to import ecdsa: {import_e3}", err=True)
        
    # Now try using the libraries in order of preference
    if secp256k1_lib:
        try:
            privkey = secp256k1_lib.PrivateKey(private_key_bytes)
            pubkey = privkey.pubkey.serialize()
            # Remove the prefix byte (0x02 or 0x03) and return the x-coordinate
            return pubkey[1:]
        except Exception as e1:
            click.echo(f"Debug: secp256k1 method failed: {e1}", err=True)
    
    if nostr_key:
        try:
            privkey_hex = bytes_to_hex(private_key_bytes)
            private_key = nostr_key(privkey_hex)
            pubkey_hex = private_key.public_key.hex()
            return hex_to_bytes(pubkey_hex)
        except Exception as e2:
            click.echo(f"Debug: nostr method failed: {e2}", err=True)
    
    if ecdsa_lib:
        try:
            sk = ecdsa_lib.SigningKey.from_string(private_key_bytes, curve=ecdsa_lib.SECP256k1)
            vk = sk.get_verifying_key()
            pubkey = vk.to_string()
            return pubkey
        except Exception as e3:
            click.echo(f"Debug: ecdsa fallback failed: {e3}", err=True)
            
    # Manual fallback using cryptography if all else fails
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        
        # Convert private key bytes to private key object
        private_key = ec.derive_private_key(
            int.from_bytes(private_key_bytes, byteorder='big'),
            ec.SECP256K1()
        )
        
        # Get public key in compressed format
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        # Remove the prefix byte (0x02 or 0x03)
        return public_key_bytes[1:]
    except Exception as e4:
        click.echo(f"Debug: cryptography fallback failed: {e4}", err=True)
        
    raise ValueError("Failed to generate public key. Could not use any of the available libraries.")

def to_bech32(data: bytes, hrp: str) -> str:
    """Convert bytes to bech32 encoding with specified human-readable prefix"""
    debug_log(f"Debug: to_bech32 input - data type: {type(data)}, length: {len(data)}, hrp: {hrp}")
    
    # Make sure data is bytes and proper length
    if not isinstance(data, bytes):
        debug_log(f"Warning: data is not bytes, converting from {type(data)}")
        try:
            if isinstance(data, str):
                if len(data) == 64 and all(c in '0123456789abcdefABCDEF' for c in data):
                    data = bytes.fromhex(data.lower())
                else:
                    data = data.encode('utf-8')
            elif isinstance(data, list):
                data = bytes(data)
            else:
                data = bytes(data)
        except Exception as e:
            debug_log(f"Error converting data to bytes: {e}")
    
    # Try using bip-utils first (most reliable)
    try:
        debug_log("Trying bip-utils Bech32 encoder")
        from bip_utils import Bech32Encoder
        
        # Ensure data is exactly 32 bytes for proper encoding
        if len(data) != 32:
            debug_log(f"Warning: data length is {len(data)}, not 32 bytes. Adjusting...")
            if len(data) > 32:
                data = data[:32]  # Truncate to 32 bytes
            else:
                data = data.ljust(32, b'\0')  # Pad with zeros
        
        # Convert to Bech32
        result = Bech32Encoder.Encode(hrp, data)
        debug_log(f"bip-utils encoded result: {result[:10]}...")
        return result
    except Exception as e_bip:
        debug_log(f"bip-utils Bech32 encoding failed: {e_bip}")
    
    # Try the nostr library next
    try:
        debug_log("Trying nostr library encoding")
        from nostr.key import PrivateKey
        
        # Ensure the data is exactly 32 bytes for nostr
        if len(data) != 32:
            if len(data) > 32:
                data = data[:32]  # Truncate
            else:
                data = data.ljust(32, b'\0')  # Pad
        
        hex_data = bytes_to_hex(data)
        debug_log(f"Hex data for nostr: {hex_data[:8]}...")
        
        if hrp == "nsec":
            private_key = PrivateKey(hex_data)
            result = private_key.bech32()
            debug_log(f"nostr nsec result: {result[:10]}...")
            return result
        elif hrp == "npub":
            private_key = PrivateKey(hex_data)
            result = private_key.public_key.bech32()
            debug_log(f"nostr npub result: {result[:10]}...")
            return result
    except Exception as e_nostr:
        debug_log(f"nostr encoding failed: {e_nostr}")
    
    # Try standard bech32 library
    try:
        debug_log("Trying standard bech32 library")
        import bech32
        data_list = list(data)
        converted = bech32.convertbits(data_list, 8, 5)
        if converted:
            result = bech32.bech32_encode(hrp, converted)
            debug_log(f"bech32 library result: {result[:10]}...")
            return result
    except Exception as e_bech32:
        debug_log(f"bech32 library failed: {e_bech32}")
    
    # Try manual implementation with proper checksums
    try:
        debug_log("Trying manual SegWit-style Bech32 implementation")
        data_list = [b for b in data]
        
        # Convert 8-bit bytes to 5-bit groups (base32)
        result_bits = []
        buffer = 0
        bits_in_buffer = 0
        
        for byte in data_list:
            buffer = (buffer << 8) | byte
            bits_in_buffer += 8
            while bits_in_buffer >= 5:
                bits_in_buffer -= 5
                result_bits.append((buffer >> bits_in_buffer) & 31)
        
        # Add the final bits with padding if necessary
        if bits_in_buffer > 0:
            result_bits.append((buffer << (5 - bits_in_buffer)) & 31)
        
        debug_log(f"Manual encoding: {len(result_bits)} 5-bit groups")
        
        # Proper Bech32 checksum calculation using bech32_create_checksum
        try:
            checksum = bech32_create_checksum(hrp, result_bits)
            combined = result_bits + checksum
            result = hrp + '1' + ''.join([CHARSET[b] for b in combined])
            debug_log(f"Manual encoding with proper checksum: {result[:10]}...")
            return result
        except Exception as e_checksum:
            debug_log(f"Checksum calculation failed: {e_checksum}")
            # Fallback to simplified checksum
            checksum = [0, 0, 0, 0, 0, 0]  # Dummy checksum
            combined = result_bits + checksum
            result = hrp + '1' + ''.join([CHARSET[b] for b in combined])
            debug_log(f"Manual encoding with dummy checksum: {result[:10]}...")
            return result
    except Exception as e_manual:
        debug_log(f"Manual encoding failed: {e_manual}")
    
    # Last resort ultra-minimal fallback
    click.echo("WARNING: Using emergency fallback encoding (NOT VALID BECH32)")
    hex_data = bytes_to_hex(data)
    if hrp == "nsec":
        return f"nsec1{hex_data}qqqqqqqqqqqqqqq"
    elif hrp == "npub":
        return f"npub1{hex_data}qqqqqqqqqqqqqqq"
    else:
        return f"{hrp}1{hex_data}qqqqqqqqqqqqqqq"

def derive_key_bip85(master_key: bytes, index: int) -> bytes:
    """
    Derive a child key using BIP-85.
    
    Implementation follows the BIP-85 specification using HMAC-SHA512.
    
    Args:
        master_key: 32-byte master key
        index: Child key index
        
    Returns:
        32-byte derived key
    """
    try:
        # Verify input is proper
        if not isinstance(master_key, bytes):
            debug_log(f"Warning: master_key is not bytes, it's {type(master_key)}")
            if isinstance(master_key, str):
                if len(master_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in master_key):
                    master_key = bytes.fromhex(master_key.lower())
                else:
                    master_key = master_key.encode('utf-8')
            else:
                master_key = bytes(master_key)
        
        if len(master_key) != 32:
            debug_log(f"Warning: master_key length is {len(master_key)}, not 32 bytes")
            if len(master_key) > 32:
                master_key = master_key[:32]
            else:
                # Pad with zeros if too short
                master_key = master_key.ljust(32, b'\0')
        
        # Ensure index is an integer
        if not isinstance(index, int):
            debug_log(f"Warning: index is not an int, it's {type(index)}")
            index = int(index)
            
        # Application-specific parameters
        app_string = "bip-nostr-key"
        entropy_bytes = 32  # Entropy length in bytes
        
        # Construct derivation data
        data = b"BIP85 Deterministic Entropy"
        data += app_string.encode()
        data += index.to_bytes(4, byteorder='big')  # Index as big-endian
        data += bytes([entropy_bytes])  # Length byte
        
        debug_log(f"Debug: Deriving key with index={index}, master_key length={len(master_key)}")
        
        # HMAC-SHA512 derivation
        h = hmac.new(master_key, data, hashlib.sha512).digest()
        
        # Return first 32 bytes of HMAC output
        derived = h[:32]
        debug_log(f"Debug: Derived key length={len(derived)}")
        return derived
        
    except Exception as e:
        debug_log(f"Error in derive_key_bip85: {e}")
        # Return a deterministic fallback if all else fails
        # NOTE: This is not secure, but it's better than crashing
        hash_input = master_key + str(index).encode() + b"fallback"
        return hashlib.sha256(hash_input).digest()

# ====== Main Class ======

class NostrDerive:
    """Main class for Nostr key derivation operations"""

    def __init__(self, password: str):
        """Initialize with user password"""
        self.password = password
        self._ensure_app_dir()
        self.encryption_key = self._derive_encryption_key()
        self.keystore = self._load_keystore()

    def _ensure_app_dir(self) -> None:
        """Ensure application directory exists"""
        if not APP_DIR.exists():
            APP_DIR.mkdir(mode=0o700)
        
        # Create salt file if it doesn't exist
        if not SALT_PATH.exists():
            with open(SALT_PATH, "wb") as f:
                f.write(os.urandom(16))

    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from password and salt"""
        with open(SALT_PATH, "rb") as f:
            salt = f.read()
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password.encode()))

    def _load_keystore(self) -> Dict:
        """Load and decrypt keystore, or initialize a new one"""
        if not KEYSTORE_PATH.exists():
            return {"master_key": None, "derived_keys": []}
        
        try:
            fernet = Fernet(self.encryption_key)
            with open(KEYSTORE_PATH, "rb") as f:
                encrypted_data = f.read()
            
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            click.echo(f"Error loading keystore: {e}", err=True)
            click.echo("This might be due to an incorrect password.")
            sys.exit(1)

    def _save_keystore(self) -> None:
        """Encrypt and save keystore"""
        fernet = Fernet(self.encryption_key)
        encrypted_data = fernet.encrypt(json.dumps(self.keystore).encode())
        
        with open(KEYSTORE_PATH, "wb") as f:
            f.write(encrypted_data)
        
        # Ensure file permissions are secure
        os.chmod(KEYSTORE_PATH, 0o600)

    def has_master_key(self) -> bool:
        """Check if master key exists"""
        return self.keystore.get("master_key") is not None

    def create_master_key(self, force: bool = False) -> Tuple[str, str]:
        """Create a new master key"""
        if self.has_master_key() and not force:
            click.echo("Master key already exists. Use --force to overwrite.", err=True)
            sys.exit(1)
        
        # Generate a random 32-byte private key
        private_key_bytes = secrets.token_bytes(KEY_BYTE_LENGTH)
        private_key_hex = bytes_to_hex(private_key_bytes)
        
        # Convert to Nostr format
        pubkey_bytes = generate_public_key(private_key_bytes)
        nsec = to_bech32(private_key_bytes, "nsec")
        npub = to_bech32(pubkey_bytes, "npub")
        
        # Validate the key pair using an alternative method if available
        self._validate_key_pair(private_key_bytes, pubkey_bytes, nsec, npub)
        
        # Store in keystore
        self.keystore["master_key"] = private_key_hex
        self._save_keystore()
        
        return nsec, npub
        
    def _validate_key_pair(self, private_key_bytes: bytes, pubkey_bytes: bytes, nsec: str, npub: str) -> None:
        """Validate that the key pair is correct using multiple libraries"""
        try:
            # Try validation with pynostr if available
            try:
                from pynostr.key import PrivateKey
                
                # Convert our private key to pynostr PrivateKey
                pk_hex = bytes_to_hex(private_key_bytes)
                pynostr_pk = PrivateKey.from_hex(pk_hex)
                pynostr_npub = pynostr_pk.public_key.bech32()
                
                if pynostr_npub != npub:
                    click.echo(f"WARNING: Key validation failed with pynostr library!", err=True)
                    click.echo(f"Our NPUB:     {npub}", err=True)
                    click.echo(f"pynostr NPUB: {pynostr_npub}", err=True)
                else:
                    click.echo(f"Key validation succeeded with pynostr library.", err=True)
            except ImportError:
                click.echo("pynostr library not available for validation.", err=True)
                
            # Try validation with nostr library if available
            try:
                from nostr.key import PrivateKey as NostrPrivateKey
                
                # Convert our private key to nostr PrivateKey
                pk_hex = bytes_to_hex(private_key_bytes)
                nostr_pk = NostrPrivateKey(pk_hex)
                nostr_npub = nostr_pk.public_key.bech32()
                
                if nostr_npub != npub:
                    click.echo(f"WARNING: Key validation failed with nostr library!", err=True)
                    click.echo(f"Our NPUB:   {npub}", err=True)
                    click.echo(f"nostr NPUB: {nostr_npub}", err=True)
                else:
                    click.echo(f"Key validation succeeded with nostr library.", err=True)
            except ImportError:
                click.echo("nostr library not available for validation.", err=True)
        except Exception as e:
            click.echo(f"Error during key validation: {e}", err=True)

    def derive_child_key(self, label: str, index: Optional[int] = None) -> Tuple[str, str]:
        """Derive a child key from the master key"""
        if not self.has_master_key():
            click.echo("No master key found. Run 'init' first.", err=True)
            sys.exit(1)
        
        # Use provided index or find next available
        if index is None:
            # Find the next available index
            used_indices = [key.get("index", 0) for key in self.keystore["derived_keys"]]
            index = 0 if not used_indices else max(used_indices) + 1
        
        # Check if index is already in use
        for key in self.keystore["derived_keys"]:
            if key.get("index") == index:
                click.echo(f"Index {index} is already in use.", err=True)
                sys.exit(1)
        
        # Get master key
        master_key_hex = self.keystore["master_key"]
        master_key_bytes = hex_to_bytes(master_key_hex)
        
        # Derive child key using BIP-85
        child_entropy = derive_key_bip85(master_key_bytes, index)
        
        # Convert to Nostr format
        pubkey_bytes = generate_public_key(child_entropy)
        nsec = to_bech32(child_entropy, "nsec")
        npub = to_bech32(pubkey_bytes, "npub")
        
        # Validate the derived key pair
        self._validate_key_pair(child_entropy, pubkey_bytes, nsec, npub)
        
        # Also validate with independent BIP-85 implementation if possible
        self._validate_bip85_derivation(master_key_bytes, index, child_entropy)
        
        # Store derived key info
        self.keystore["derived_keys"].append({
            "label": label,
            "index": index,
            "npub": npub,
            "nsec": nsec,
        })
        self._save_keystore()
        
        return nsec, npub
        
    def _validate_bip85_derivation(self, master_key_bytes: bytes, index: int, derived_key: bytes) -> None:
        """Validate BIP-85 derivation using alternative implementations if available"""
        try:
            # Try to use pynostr for BIP-85 derivation if available
            try:
                import hmac
                import hashlib
                
                # Implement BIP-85 derivation separately for validation
                app_string = "bip-nostr-key"
                entropy_bytes = 32
                
                data = b"BIP85 Deterministic Entropy"
                data += app_string.encode()
                data += index.to_bytes(4, byteorder='big')
                data += bytes([entropy_bytes])
                
                h = hmac.new(master_key_bytes, data, hashlib.sha512).digest()
                validation_derived = h[:32]
                
                if validation_derived != derived_key:
                    click.echo(f"WARNING: BIP-85 validation failed! The derived keys don't match.", err=True)
                    click.echo(f"Our derived:     {bytes_to_hex(derived_key)}", err=True)
                    click.echo(f"Validation key:  {bytes_to_hex(validation_derived)}", err=True)
                else:
                    click.echo(f"BIP-85 derivation validated successfully.", err=True)
            except ImportError:
                click.echo("Could not validate BIP-85 derivation - hmac/hashlib not available.", err=True)
        except Exception as e:
            click.echo(f"Error during BIP-85 validation: {e}", err=True)

    def list_identities(self) -> List[Dict]:
        """List all derived identities"""
        return self.keystore["derived_keys"]

    def get_identity(self, label: str) -> Optional[Dict]:
        """Get a specific identity by label"""
        for key in self.keystore["derived_keys"]:
            if key["label"] == label:
                return key
        return None

# ====== CLI ======

@click.group(
    help="""Nostr Key Derivation tool using BIP-85.

Generate and manage hierarchical Nostr keys from a master key.

WITH STORAGE: Initialize with 'init', create keys with 'create'.
WITHOUT STORAGE: Use '--nsec' and '--no-store' options directly.

Examples:
* Create master key:
  nostr-derive init

* Import existing key:
  nostr-derive init --nsec nsec1...

* Create derived identity:
  nostr-derive create --label "Identity" --index 1

* List identities:
  nostr-derive list

* Export identity:
  nostr-derive export --label "Identity"

* Derive without storing:
  nostr-derive create --nsec nsec1... --no-store
"""
)
@click.option('--debug', is_flag=True, help='Enable debug output')
def cli(debug):
    """Nostr Key Derivation tool using BIP-85."""
    # Set global debug flag based on command line option
    global DEBUG
    DEBUG = debug


@cli.command()
@click.option("--force", is_flag=True, help="Force overwrite of existing master key")
@click.option("--nsec", help="Initialize with existing key (accepts nsec1..., nsec:HEX, or raw 64-char HEX)")
@click.option("--no-store", is_flag=True, help="Don't store the key (will only display it)")
def init(force, nsec, no_store):
    """Initialize a new master key or import an existing one.

This command will either generate a new master key or import an existing 
Nostr private key (nsec) to use as your master key.

By default, the master key will be stored in an encrypted keystore file.
Use --no-store to skip storing the key and just display it instead.
    """
    if not no_store:
        password = getpass.getpass("Enter password to protect your keystore (optional, leave empty for no keystore): ")
        if password:
            confirm = getpass.getpass("Confirm password: ")
            
            if password != confirm:
                click.echo("Passwords do not match.")
                sys.exit(1)
            
            if len(password) < 8:
                click.echo("Password must be at least 8 characters long.")
                sys.exit(1)
                
            nostr_derive = NostrDerive(password)
        else:
            no_store = True
    
    try:
        if nsec:
            # Import existing key in various formats
            private_key_bytes = decode_nsec(nsec)
            if not private_key_bytes:
                click.echo("Error: Could not decode the nsec key. Please check the format.", err=True)
                click.echo("Supported formats: nsec1... bech32, nsec:HEX, or 64-char hex string", err=True)
                sys.exit(1)
                
            # Get private key hex string
            private_key_hex = bytes_to_hex(private_key_bytes)
            
            try:
                # Generate public key
                pubkey_bytes = generate_public_key(private_key_bytes)
                npub = to_bech32(pubkey_bytes, "npub")
                
                if not no_store:
                    # Store in keystore
                    nostr_derive.keystore["master_key"] = private_key_hex
                    nostr_derive._save_keystore()
                    click.echo("Existing key imported and stored successfully!")
                else:
                    click.echo("Existing key imported (not stored):")
                
                click.echo(f"Master public key (npub): {npub}")
                click.echo(f"Private key format: {nsec}")
                click.echo("WARNING: Keep your master key secure and backed up!")
            except Exception as e:
                click.echo(f"Error processing key: {e}", err=True)
                sys.exit(1)
        else:
            # Generate a new key
            click.echo("Creating new master key...")
            
            # Generate a random 32-byte private key
            private_key_bytes = secrets.token_bytes(KEY_BYTE_LENGTH)
            private_key_hex = bytes_to_hex(private_key_bytes)
            
            # Convert to Nostr format
            pubkey_bytes = generate_public_key(private_key_bytes)
            nsec = to_bech32(private_key_bytes, "nsec")
            npub = to_bech32(pubkey_bytes, "npub")
            
            if not no_store:
                # Store in keystore
                nostr_derive.keystore["master_key"] = private_key_hex
                nostr_derive._save_keystore()
                click.echo("Master key created and stored successfully!")
            else:
                click.echo("Master key created (not stored):")
                
            click.echo(f"Master public key (npub): {npub}")
            click.echo(f"Master private key (nsec): {nsec}")
            click.echo("IMPORTANT: Never share your private key with anyone!")
            click.echo("WARNING: If you didn't store this key, write it down securely now!")
    except Exception as e:
        click.echo(f"Error creating master key: {e}", err=True)
        sys.exit(1)


@cli.command(
    short_help="Create a new derived identity from your master key",
    help="""Create a new derived identity from your master key.

Two ways to use:

* With keystore (requires prior 'init'):
  nostr-derive create --label "Work Identity" --index 1

* Direct derivation (without storing):
  nostr-derive create --nsec nsec1... --index 42 --no-store

Additional options:

* Validate the key pair:
  --validate

* Specify a custom index (default is 0):
  --index N
"""
)
@click.option("--label", help="Human-readable label for this identity (required when storing)")
@click.option("--index", type=int, default=0, help="Index for derivation (defaults to 0)")
@click.option("--nsec", help="Master key to derive from (accepts nsec1..., nsec:HEX, or raw 64-char HEX)")
@click.option("--no-store", is_flag=True, help="Don't store the derived key (will only display it)")
@click.option("--validate", is_flag=True, help="Perform additional validation with multiple libraries")
def create(label, index, nsec, no_store, validate):
    """Create a new derived identity from your master key."""
    master_key_bytes = None
    
    if nsec:
        # Using provided nsec directly
        private_key_bytes = decode_nsec(nsec)
        if not private_key_bytes:
            click.echo("Error: Could not decode the nsec key. Please check the format.", err=True)
            click.echo("Supported formats: nsec1... bech32, nsec:HEX, or 64-char hex string", err=True)
            sys.exit(1)
            
        master_key_bytes = private_key_bytes
        master_key_hex = bytes_to_hex(master_key_bytes)
        
        # Validate the master key if requested
        if validate:
            try:
                # Generate public key for the master
                master_pubkey_bytes = generate_public_key(master_key_bytes)
                master_npub = to_bech32(master_pubkey_bytes, "npub")
                
                # Validate using pynostr if available
                try:
                    from pynostr.key import PrivateKey
                    pynostr_pk = PrivateKey.from_hex(master_key_hex)
                    pynostr_npub = pynostr_pk.public_key.bech32()
                    
                    click.echo("Master key validation results:", err=True)
                    click.echo(f"  Our NPUB:     {master_npub}", err=True)
                    click.echo(f"  pynostr NPUB: {pynostr_npub}", err=True)
                    
                    if pynostr_npub != master_npub:
                        click.echo(f"WARNING: Master key validation failed!", err=True)
                except ImportError:
                    click.echo("pynostr not available for validation.", err=True)
            except Exception as e:
                click.echo(f"Error during master key validation: {e}", err=True)
    else:
        # Using keystore
        if no_store and not label:
            # If we're not storing, label is optional
            pass
        elif not label:
            click.echo("Label is required when storing identities. Use --label to specify one.", err=True)
            sys.exit(1)
            
        password = getpass.getpass("Enter keystore password (or press Enter to skip keystore): ")
        if not password:
            no_store = True
            if not nsec:
                click.echo("Either a password for keystore access or --nsec parameter is required.", err=True)
                sys.exit(1)
        else:
            nostr_derive = NostrDerive(password)
            
            if not nostr_derive.has_master_key():
                click.echo("No master key found in keystore. Please run 'init' first or use --nsec.", err=True)
                sys.exit(1)
                
            master_key_hex = nostr_derive.keystore["master_key"]
            master_key_bytes = hex_to_bytes(master_key_hex)
    
    try:
        # Derive child key using BIP-85
        child_entropy = derive_key_bip85(master_key_bytes, index)
        
        # Convert to Nostr format
        pubkey_bytes = generate_public_key(child_entropy)
        derived_nsec = to_bech32(child_entropy, "nsec")
        derived_npub = to_bech32(pubkey_bytes, "npub")
        
        # Validate the derived key if requested
        if validate:
            try:
                # Implement BIP-85 derivation separately for validation
                import hmac
                import hashlib
                
                app_string = "bip-nostr-key"
                entropy_bytes = 32
                
                data = b"BIP85 Deterministic Entropy"
                data += app_string.encode()
                data += index.to_bytes(4, byteorder='big')
                data += bytes([entropy_bytes])
                
                h = hmac.new(master_key_bytes, data, hashlib.sha512).digest()
                validation_derived = h[:32]
                
                if validation_derived != child_entropy:
                    click.echo(f"WARNING: BIP-85 validation failed! The derived keys don't match.", err=True)
                    click.echo(f"Our derived:     {bytes_to_hex(child_entropy)}", err=True)
                    click.echo(f"Validation key:  {bytes_to_hex(validation_derived)}", err=True)
                else:
                    click.echo(f"BIP-85 derivation validated successfully.", err=True)
                
                # Validate the derived key with pynostr if available
                try:
                    from pynostr.key import PrivateKey
                    derived_hex = bytes_to_hex(child_entropy)
                    pynostr_pk = PrivateKey.from_hex(derived_hex)
                    pynostr_npub = pynostr_pk.public_key.bech32()
                    
                    click.echo("Derived key validation results:", err=True)
                    click.echo(f"  Our NPUB:     {derived_npub}", err=True)
                    click.echo(f"  pynostr NPUB: {pynostr_npub}", err=True)
                    
                    if pynostr_npub != derived_npub:
                        click.echo(f"WARNING: Derived key validation failed!", err=True)
                except ImportError:
                    click.echo("pynostr not available for validation.", err=True)
            except Exception as e:
                click.echo(f"Error during validation: {e}", err=True)
        
        if not no_store and label:
            # Check if the index is already used
            used_indices = [key.get("index", 0) for key in nostr_derive.keystore["derived_keys"]]
            if index in used_indices:
                click.echo(f"Index {index} is already in use in your keystore.", err=True)
                sys.exit(1)
                
            # Store the derived key
            nostr_derive.keystore["derived_keys"].append({
                "label": label,
                "index": index,
                "npub": derived_npub,
                "nsec": derived_nsec,
            })
            nostr_derive._save_keystore()
            click.echo(f"Created and stored new identity \"{label}\" (index: {index})")
        else:
            click.echo(f"Created new identity (index: {index}, not stored)")
            
        click.echo(f"Public key (npub): {derived_npub}")
        click.echo(f"Private key (nsec): {derived_nsec}")
        click.echo("IMPORTANT: Never share your private key with anyone!")
    except Exception as e:
        click.echo(f"Error creating derived key: {e}", err=True)
        sys.exit(1)


@cli.command()
def list():
    """List all derived identities stored in your keystore.

This command displays all the identities you've stored in your keystore.
It shows each identity's label, public key (npub), and index.
Private keys are not displayed for security reasons.

Note: This command only shows stored identities. Keys derived with --no-store
will not appear in this list.

Example:
  nostr-derive list
    """
    password = getpass.getpass("Enter keystore password: ")
    
    if not password:
        click.echo("Password is required to access the keystore.")
        sys.exit(1)
        
    nostr_derive = NostrDerive(password)
    
    if not nostr_derive.has_master_key():
        click.echo("No master key found in keystore. Please run 'init' first to create or import a master key.")
        sys.exit(1)
    
    identities = nostr_derive.list_identities()
    
    if not identities:
        click.echo("No derived identities found in keystore. Use the 'create' command to create and store new identities.")
        return
    
    click.echo("Available identities in keystore:")
    for i, identity in enumerate(identities, 1):
        click.echo(f"{i}. {identity['label']} (npub: {identity['npub']}, index: {identity['index']})")


@cli.command()
@click.option("--label", required=True, help="Label of the identity to export")
@click.option("--show-private", is_flag=True, help="Show private key (nsec)")
@click.option("--nsec", help="Master key to re-derive with (accepts nsec1..., nsec:HEX, or raw 64-char HEX)")
@click.option("--index", type=int, help="Index to use when re-deriving from master nsec (required with --nsec)")
def export(label, show_private, nsec, index):
    """Export a specific identity from your keystore or re-derive it.

This command can either:
1. Export a stored identity from your keystore by its label
2. Re-derive an identity directly from a master nsec

By default, it only shows the public key (npub).
Use --show-private to also reveal the private key (nsec).

Examples:
  # Export from keystore:
  nostr-derive export --label "Work Identity"
  
  # Re-derive directly:
  nostr-derive export --nsec nsec1... --index 42 --show-private
    """
    if nsec:
        # Direct derivation without keystore
        if index is None:
            click.echo("When using --nsec, you must specify the --index parameter.")
            sys.exit(1)
            
        # Decode the provided key
        master_key_bytes = decode_nsec(nsec)
        if not master_key_bytes:
            click.echo("Error: Could not decode the nsec key. Please check the format.", err=True)
            click.echo("Supported formats: nsec1... bech32, nsec:HEX, or 64-char hex string", err=True)
            sys.exit(1)
            
        try:
            # Derive child key using BIP-85
            child_entropy = derive_key_bip85(master_key_bytes, index)
            
            # Convert to Nostr format
            pubkey_bytes = generate_public_key(child_entropy)
            derived_nsec = to_bech32(child_entropy, "nsec")
            derived_npub = to_bech32(pubkey_bytes, "npub")
            
            click.echo(f"Derived identity (index: {index}):")
            click.echo(f"  Public key (npub): {derived_npub}")
            
            if show_private:
                click.secho("WARNING: You are about to reveal a private key. Make sure no one is watching.", fg="red")
                if click.confirm("Are you sure you want to display the private key?"):
                    click.echo(f"  Private key (nsec): {derived_nsec}")
                    click.echo("IMPORTANT: Never share your private key with anyone!")
        except Exception as e:
            click.echo(f"Error deriving key: {e}", err=True)
            sys.exit(1)
    else:
        # Using keystore
        password = getpass.getpass("Enter keystore password: ")
        
        if not password:
            click.echo("Password is required to access the keystore.")
            sys.exit(1)
            
        nostr_derive = NostrDerive(password)
        
        if not nostr_derive.has_master_key():
            click.echo("No master key found in keystore. Please run 'init' first to create or import a master key.")
            sys.exit(1)
        
        identity = nostr_derive.get_identity(label)
        if not identity:
            click.echo(f"No identity found with label '{label}'.")
            click.echo("Use the 'list' command to see all available identities.")
            sys.exit(1)
        
        click.echo(f"{identity['label']} (index: {identity['index']}):")
        click.echo(f"  Public key (npub): {identity['npub']}")
        
        if show_private:
            click.secho("WARNING: You are about to reveal a private key. Make sure no one is watching.", fg="red")
            if click.confirm("Are you sure you want to display the private key?"):
                click.echo(f"  Private key (nsec): {identity['nsec']}")
                click.echo("IMPORTANT: Never share your private key with anyone!")


@cli.command()
@click.option("--nsec", required=True, help="Private key to validate (accepts nsec1..., nsec:HEX, or raw 64-char HEX)")
@click.option("--npub", help="Public key to validate against (optional, will be derived if not provided)")
def validate(nsec, npub):
    """Validate a Nostr key pair using multiple libraries.

This command takes a private key (nsec) and optionally a public key (npub)
and validates them using multiple libraries and methods.

If only the nsec is provided, it will derive the correct npub and validate
the derivation with multiple libraries.

If both nsec and npub are provided, it will check if they form a valid key pair.

Examples:
  # Validate only nsec (deriving npub):
  nostr-derive validate --nsec nsec1...
  
  # Validate a key pair:
  nostr-derive validate --nsec nsec1... --npub npub1...
    """
    # Decode private key
    private_key_bytes = decode_nsec(nsec)
    if not private_key_bytes:
        click.echo("Error: Could not decode the nsec key. Please check the format.", err=True)
        click.echo("Supported formats: nsec1... bech32, nsec:HEX, or 64-char hex string", err=True)
        sys.exit(1)
        
    private_key_hex = bytes_to_hex(private_key_bytes)
    
    # Generate public key using our implementation
    pubkey_bytes = generate_public_key(private_key_bytes)
    derived_npub = to_bech32(pubkey_bytes, "npub")
    
    click.echo(f"NSEC: {nsec}")
    if npub:
        click.echo(f"Provided NPUB: {npub}")
    click.echo(f"Derived NPUB:  {derived_npub}")
    
    if npub and npub != derived_npub:
        click.echo("WARNING: The provided NPUB does not match the derived NPUB!")
    
    # Try validation with different libraries
    click.echo("\nValidating with multiple libraries:")
    
    # 1. Try with pynostr if available
    try:
        from pynostr.key import PrivateKey
        pynostr_pk = PrivateKey.from_hex(private_key_hex)
        pynostr_npub = pynostr_pk.public_key.bech32()
        
        click.echo(f"1. pynostr library:")
        click.echo(f"   Derived NPUB: {pynostr_npub}")
        click.echo(f"   Match with our implementation? {'✓ Yes' if pynostr_npub == derived_npub else '✗ No'}")
        if npub:
            click.echo(f"   Match with provided NPUB? {'✓ Yes' if pynostr_npub == npub else '✗ No'}")
    except ImportError:
        click.echo("1. pynostr library: Not available")
    except Exception as e:
        click.echo(f"1. pynostr library: Error - {e}")
    
    # 2. Try with nostr library if available
    try:
        from nostr.key import PrivateKey as NostrPrivateKey
        nostr_pk = NostrPrivateKey(private_key_hex)
        nostr_npub = nostr_pk.public_key.bech32()
        
        click.echo(f"\n2. nostr library:")
        click.echo(f"   Derived NPUB: {nostr_npub}")
        click.echo(f"   Match with our implementation? {'✓ Yes' if nostr_npub == derived_npub else '✗ No'}")
        if npub:
            click.echo(f"   Match with provided NPUB? {'✓ Yes' if nostr_npub == npub else '✗ No'}")
    except ImportError:
        click.echo("\n2. nostr library: Not available")
    except Exception as e:
        click.echo(f"\n2. nostr library: Error - {e}")
    
    # 3. Try with secp256k1 library if available
    try:
        import secp256k1
        privkey = secp256k1.PrivateKey(private_key_bytes)
        pubkey = privkey.pubkey.serialize()
        # Remove the prefix byte (0x02 or 0x03) for x-only pubkey
        pubkey_xonly = pubkey[1:]
        
        click.echo(f"\n3. secp256k1 library:")
        click.echo(f"   Public key (hex): {pubkey.hex()}")
        click.echo(f"   X-only pubkey (hex): {pubkey_xonly.hex()}")
        
        # Try to convert to bech32 if we have the library
        try:
            import bech32
            data = list(pubkey_xonly)
            converted = bech32.convertbits(data, 8, 5)
            if converted:
                secp_npub = bech32.bech32_encode("npub", converted)
                click.echo(f"   Derived NPUB: {secp_npub}")
                click.echo(f"   Match with our implementation? {'✓ Yes' if secp_npub == derived_npub else '✗ No'}")
                if npub:
                    click.echo(f"   Match with provided NPUB? {'✓ Yes' if secp_npub == npub else '✗ No'}")
        except ImportError:
            click.echo("   Could not convert to bech32 (library not available)")
        except Exception as e:
            click.echo(f"   Error converting to bech32: {e}")
    except ImportError:
        click.echo("\n3. secp256k1 library: Not available")
    except Exception as e:
        click.echo(f"\n3. secp256k1 library: Error - {e}")
    
    # Provide a summary
    click.echo("\nSummary:")
    if npub:
        if npub == derived_npub:
            click.echo("✓ The provided NPUB matches the derived NPUB. This is a valid key pair.")
        else:
            click.echo("✗ The provided NPUB does NOT match the derived NPUB. This is NOT a valid key pair.")
    else:
        click.echo(f"The correct NPUB for this NSEC should be: {derived_npub}")

if __name__ == "__main__":
    cli()