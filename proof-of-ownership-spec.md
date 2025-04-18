# Nobel Prize Verification Scenario

Anonymous public entity npub1 is derived from anonymous private entity npub0 creates a new invention of significance. At a later stage this invention is recognized as important and a Nobel Peace Prize is to be awarded to the inventor. The Nobel committee asks npub1 to provide proof of the true inventor so an award can be presented to themselves or a nominee. npub0 prefers to remain anonymous. 

## Background

npub0: The master identity (remains completely anonymous but they might have initial SN :) )
npub1: The inventor identity (publicly known for the invention)
The invention: A significant breakthrough worthy of the Nobel Prize
Challenge: Prove authentic ownership without revealing the master identity

## Using Zero-Knowledge Proofs

Zero-knowledge proofs are ideal here because they allow npub0 to prove they control npub1 without revealing any information about their master key or creating any public link between identities.
Here's how it would unfold:

### 1. Initial Claim

The Nobel Committee contacts npub1 about the award
npub1 indicates they wish to remain anonymous but will prove authentic ownership


### 2. Establishing the Verification Process

The Nobel Committee and npub1 agree on a zero-knowledge protocol
They select a specialized cryptographer as a neutral third party to verify the proof


### 3. The Proof Generation

npub0 creates a zero-knowledge proof demonstrating they can derive npub1's private key
The proof shows the relationship between keys without revealing the master key
This proof is constructed as a zk-SNARK (Zero-Knowledge Succinct Non-Interactive Argument of Knowledge)


### 4. Verification

The cryptographer verifies the mathematical proof
The Nobel Committee confirms the authenticity
The entire process leaves no public record connecting npub0 and npub1


### 5. Award Ceremony

npub0 has options:
a) Remain completely anonymous and decline physical attendance
b) Send a named proxy (no cryptographic connection to npub0)
c) Attend in disguise or via remote video with voice/appearance alteration



## Advantages of Zero-Knowledge Proofs

*Mathematical certainty:* Provides cryptographic guarantees rather than trust-based verification
*No information leakage:* Reveals absolutely nothing about the master key
*Non-interactive:* Can be verified without ongoing communication
*No permanent links:* Creates no public association between identities
*Widely accepted:* Has strong cryptographic foundations trusted by experts

## Comparison to Other Options

### Designated Verifier Proofs

Pro: Only the Nobel Committee could verify the proof
Con: Requires more trust in the Committee not to share details
Con: Less standardized than zk-proofs

### Blind Signatures

Pro: Potentially simpler to implement
Con: Generally used for different purposes (like e-cash)
Con: Might leak more information than a proper zk-proof

Zero-knowledge proofs offer the strongest theoretical guarantees and the cleanest solution to this scenario, providing mathematical certainty without compromising anonymity.


# Nostr ZK-SNARK Ownership Proof Specification

## Overview

This specification outlines a Python script (or set of scripts) that enables a master Nostr key holder (npub0) to generate a zero-knowledge proof demonstrating ownership of a derived key (npub1) without revealing the master key or creating any public link between identities.

## System Requirements

The script will utilize ZK-SNARKs (Zero-Knowledge Succinct Non-interactive Arguments of Knowledge) to create cryptographic proofs that can be verified by third parties.

## Core Components

### 1. Circuit Definition

A circuit that proves the following statement without revealing any sensitive information:
- "I know the private key corresponding to npub0"
- "Using npub0's private key and BIP-85 derivation with index X, I can derive npub1"

### 2. Proof Generation

A tool that allows npub0 to generate a proof that can be shared with verifiers.

### 3. Proof Verification

A separate verification tool that allows third parties to verify the proof without gaining any knowledge about the relationship between npub0 and npub1.

## Technical Specification

### Dependencies

- `pysnark` or `zokrates`: For ZK-SNARK implementation
- `secp256k1`: For elliptic curve operations
- `bip85`: For key derivation
- `nostr-python`: For Nostr key formatting

### Circuit Design

The ZK-SNARK circuit should prove the following relationship:

1. The prover knows the private key (sk0) corresponding to npub0
2. A deterministic derivation process using BIP-85 with a specific index leads from sk0 to sk1
3. sk1 corresponds to the public key npub1

```
Circuit inputs:
- Public inputs: npub0, npub1, derivation_index
- Private inputs: sk0 (master private key)

Circuit logic:
1. Verify that sk0 corresponds to npub0 using secp256k1
2. Derive child entropy using BIP-85 derivation path with derivation_index
3. Compute child private key sk1 from the derived entropy
4. Derive public key from sk1
5. Verify that derived public key matches npub1
```

### Implementation Details

#### 1. Setup Script

```python
def setup(circuit_file):
    """
    Generate proving and verification keys for the ZK-SNARK circuit
    
    Args:
        circuit_file: Path to the circuit definition file
        
    Returns:
        tuple: (proving_key, verification_key)
    """
```

#### 2. Proof Generation Script

```python
def generate_proof(master_nsec, derived_npub, derivation_index, proving_key):
    """
    Generate a ZK-SNARK proof that master_nsec is the master key
    that can derive the key corresponding to derived_npub
    
    Args:
        master_nsec: The master private key in bech32 nsec format
        derived_npub: The derived public key to prove ownership of
        derivation_index: The BIP-85 derivation index used
        proving_key: The proving key generated during setup
        
    Returns:
        dict: The proof data structure
    """
```

#### 3. Verification Script

```python
def verify_proof(master_npub, derived_npub, derivation_index, proof, verification_key):
    """
    Verify a ZK-SNARK proof that the owner of master_npub can derive
    the key corresponding to derived_npub
    
    Args:
        master_npub: The master public key in bech32 npub format
        derived_npub: The derived public key being proven
        derivation_index: The BIP-85 derivation index claimed
        proof: The ZK-SNARK proof to verify
        verification_key: The verification key from setup
        
    Returns:
        bool: True if the proof is valid, False otherwise
    """
```

### Command-line Interface

The system should be implemented as a set of command-line tools:

#### Setup Tool

```
nostr-zk-setup [--output-dir DIR]
```

- Generates the ZK-SNARK proving and verification keys
- Stores them in the specified directory

#### Proof Generation Tool

```
nostr-zk-prove --master-nsec NSEC --derived-npub NPUB --index INDEX [--output-file FILE]
```

- Takes the master private key, derived public key, and derivation index
- Generates a proof file that can be shared

#### Verification Tool

```
nostr-zk-verify --master-npub NPUB --derived-npub NPUB --index INDEX --proof-file FILE
```

- Takes the master public key, derived public key, derivation index, and proof
- Outputs whether the proof is valid or not

## Security Considerations

1. **Key Protection**:
   - Never expose the master private key (sk0)
   - Ensure memory is cleared after proof generation

2. **Information Leakage**:
   - Ensure the proof contains no information about the private keys
   - Prevent side-channel attacks during proof generation

3. **Trusted Setup**:
   - Consider the implications of the ZK-SNARK trusted setup phase
   - Document the trust assumptions clearly

## Usage Flow Example

### Setup Phase (done once)

```bash
$ nostr-zk-setup --output-dir ~/.nostr-zk
Generating circuit...
Performing trusted setup...
Keys generated and saved to ~/.nostr-zk/
```

### Proof Generation (done by npub0)

```bash
$ nostr-zk-prove --master-nsec nsec1... --derived-npub npub1... --index 1 --output-file proof.json
Reading master key...
Generating proof...
Proof saved to proof.json
```

### Verification (done by third party)

```bash
$ nostr-zk-verify --master-npub npub0... --derived-npub npub1... --index 1 --proof-file proof.json
Reading proof...
Verification result: VALID
The proof correctly demonstrates that the owner of npub0... controls npub1...
```

## Implementation Guidelines

1. **Circuit Optimization**:
   - Optimize the circuit for minimal complexity
   - Consider using existing libraries for elliptic curve operations

2. **Error Handling**:
   - Provide clear error messages without leaking sensitive information
   - Validate all inputs thoroughly

3. **Documentation**:
   - Include detailed documentation about the cryptographic principles
   - Explain security assumptions and limitations

4. **Testing**:
   - Create comprehensive test cases
   - Include edge cases and potential attack scenarios

## Extensions and Future Work

1. **Multiple Key Proofs**:
   - Extend to prove ownership of multiple derived keys simultaneously

2. **Alternative Proof Systems**:
   - Consider alternative zero-knowledge systems like Bulletproofs or STARKs

3. **Integration with Nostr Clients**:
   - Develop plugins for popular Nostr clients

4. **Web Interface**:
   - Create a web-based verification tool for non-technical users

## Note on Proving Systems

This specification suggests using ZK-SNARKs, but the implementer should evaluate:

1. **ZK-SNARKs**: Require trusted setup but have small proof sizes
2. **Bulletproofs**: No trusted setup but larger proofs
3. **STARKs**: No trusted setup, quantum-resistant, but much larger proofs

The choice depends on the specific requirements for proof size, verification speed, and trust assumptions.
