# Nostr BIP-85 Identity Derivation and ZK-Proofs: Use Cases

This document explores use cases for hierarchical identity management with BIP-85 derivation and zero-knowledge proofs in the Nostr ecosystem.

## Introduction

The combination of BIP-85 hierarchical deterministic key derivation with zero-knowledge proofs creates powerful possibilities for privacy-preserving identity management in Nostr. By allowing users to derive multiple pseudonymous identities from a single master key and selectively prove relationships when necessary, we can build systems that balance privacy with trust.

## Core Concept

- **Master Identity**: A primary npub/nsec pair that controls derived identities
- **Derived Identities**: Multiple npub/nsec pairs generated deterministically from the master
- **Zero-Knowledge Proofs**: Cryptographic proofs that demonstrate ownership without revealing relationships

## Our Implementation

This project provides practical tools for implementing these concepts:

1. **nostr-derive.py**: A tool for creating and managing hierarchical derived keys using BIP-85
2. **simple_proof.py**: A straightforward proof tool that shows multiple keys are derived from the same master
3. **nostr-zk-proof.py**: A zero-knowledge proof implementation that provides stronger privacy guarantees

These tools enable all the use cases described in this document and can be directly used with any Nostr client.

## Categorized Use Cases

### Identity Management

1. **Contextual Identities**
   - Maintain separate identities for work, family, political discussions, hobbies
   - Automatically select appropriate identity based on context
   - Prevent social context collapse while simplifying key management

2. **Identity Recovery**
   - After a key compromise, create a new derived identity
   - Prove continuity with the compromised identity using the master key
   - Transfer reputation and connections without starting over

3. **Graduated Disclosure**
   - Reveal different aspects of identity to different audiences
   - Progressive trust building with selective disclosure
   - Maintain separation where needed while proving connections where beneficial

4. **Backup Identities**
   - Pre-generate backup identities with established derivation paths
   - Easily prove ownership if a primary identity is compromised
   - Maintain continuous presence even after key loss

### Reputation Systems

1. **Reputation Portability**
   - Move reputation across platforms without exposing full identity
   - Connect professional achievements to pseudonymous identities when needed
   - Establish trust in new communities using existing reputation

2. **Selective Endorsement**
   - Allow one identity to vouch for another without revealing connection to all
   - Create reputation webs with selective visibility
   - Enable trust networks that preserve privacy

3. **Anonymous Expert Verification**
   - Prove expertise (academic credentials, professional certifications)
   - Contribute authoritative knowledge while maintaining pseudonymity
   - Enable trust in specialized knowledge without personal exposure

4. **Whistleblower Protection**
   - Prove institutional affiliation without exposure
   - Demonstrate insider knowledge authenticity
   - Create verifiable but protected channels for sensitive information

### Financial Applications

1. **Private Guarantees**
   - Provide financial backing to derived identities
   - Guarantee loans or contracts without public disclosure
   - Enable reputation-based finance without full identity exposure

2. **Selective Credit History**
   - Share relevant financial history without linking all accounts
   - Build credit pseudonymously with verifiable history
   - Enable trustless lending based on provable but private history

3. **Fund Recovery**
   - Prove ownership of funds tied to compromised keys
   - Establish clear recovery paths for digital assets
   - Prevent permanent loss due to key compromise

4. **Inheritance Planning**
   - Create provable inheritance paths for digital identities
   - Allow controlled transfer of identity-linked assets
   - Enable digital estate planning with cryptographic guarantees

### Access Control

1. **Delegated Access**
   - Grant platform access to derived identities
   - Manage permissions hierarchically
   - Enable organizational access control with individual privacy

2. **Temporary Identities**
   - Create provable but time-limited identities
   - Enable guest access with verification
   - Support ephemeral but authentic participation

3. **Emergency Access**
   - Establish recovery paths for critical systems
   - Create break-glass procedures with cryptographic verification
   - Support disaster recovery while maintaining security

## Additional ZK-SNARK Applications for Nostr

1. **Proof of Geographic Region**
   - Demonstrate you're from a specific region without revealing exact location
   - Enable regional content or services while preserving privacy
   - Support geo-fencing without precise tracking

2. **Age Verification**
   - Prove you're over a certain age without revealing birth date
   - Access age-restricted content privately
   - Comply with age requirements without identity disclosure

3. **Organizational Membership**
   - Prove membership in an organization without revealing which specific member
   - Speak as a verified insider without personal exposure
   - Maintain group accountability with individual privacy

4. **Income Qualification**
   - Prove income meets requirements without revealing exact amount
   - Access income-based services privately
   - Qualify for offerings without financial disclosure

5. **Voting Rights**
   - Prove eligibility to vote without revealing identity
   - Participate in governance systems with privacy
   - Enable anonymous but verified participation

6. **Content Authentication**
   - Prove content comes from the same creator without linking all content
   - Build reputation for quality without exposing complete history
   - Maintain creative continuity with privacy

7. **Selective History**
   - Prove account age/history without revealing all activities
   - Demonstrate longevity and consistency selectively
   - Share relevant history without complete transparency

## Real-World Examples

### Contextual Social Circles
**Scenario:** Alex is a software developer (npub1), a political activist (npub2), and a member of a support group for a personal health condition (npub3). Alex uses different derived keys for each context, managed by a single master key.

```bash
# Alex creates a master key
$ python nostr-derive.py init
# Created master key with a password and received nsec/npub pair

# Alex creates different identities for different contexts
$ python nostr-derive.py create --label "Developer Identity" --index 1
# Created developer identity (npub1)
Public key (npub): npub1dev...
Private key (nsec): nsec1dev...

$ python nostr-derive.py create --label "Political Activist" --index 2
# Created activist identity (npub2)
Public key (npub): npub1pol...
Private key (nsec): nsec1pol...

$ python nostr-derive.py create --label "Health Support Group" --index 3
# Created health support identity (npub3)
Public key (npub): npub1health...
Private key (nsec): nsec1health...

# Alex can list all identities from keystore
$ python nostr-derive.py list
# [Prompts for password]
Available identities in keystore:
1. Developer Identity (npub: npub1dev..., index: 1)
2. Political Activist (npub: npub1pol..., index: 2)
3. Health Support Group (npub: npub1health..., index: 3)

# If Alex needed to prove that two identities are related (e.g., to transfer reputation)
# Alex can generate a proof using the simple_proof.py tool:
$ python simple_proof.py --master-nsec nsec1master... --indices 1,2 --output related_identities.json

# This proof can be shared with trusted parties to verify the relationship
# without publicly exposing the connection between the identities
```

**Analysis:** Using different derived keys for different social contexts maintains privacy while avoiding the complexity of managing entirely separate identities. This prevents Alex's professional contacts from seeing political posts or health discussions, while allowing seamless management of all identities.

### Transitive Reputation
**Scenario:** Jian has built a stellar reputation as a freelance designer (npub3) over years. They now want to start offering programming services (npub6) while keeping the identities separate. Jian can use ZK-proofs to show potential programming clients that npub6 is connected to the reputable npub3 without revealing their complete identity.

```bash
# First, Jian created these identities using the nostr-derive.py tool
$ python nostr-derive.py init
# Created master key with a password and received nsec/npub pair

$ python nostr-derive.py create --label "Designer Identity" --index 3
# Created designer identity (npub3)
Public key (npub): npub1design...
Private key (nsec): nsec1design...

$ python nostr-derive.py create --label "Programmer Identity" --index 6
# Created programmer identity (npub6)
Public key (npub): npub1prog...
Private key (nsec): nsec1prog...

# When a new client asks for proof of reputation, Jian has two options:

# Option 1: Using our simplified proof tool (recommended)
$ python simple_proof.py --master-nsec nsec1master... --indices 3,6 --output reputation-proof.json

# Client receives the proof file and can see that both identities are linked
# The proof shows both keys are derived from the same master key:
# {
#   "master_npub": "npub1master...",
#   "derived_keys": [
#     {
#       "index": 3,
#       "npub": "npub1design...",
#       "nsec": "nsec1design...",
#       "key_hash": "..."
#     },
#     {
#       "index": 6,
#       "npub": "npub1prog...",
#       "nsec": "nsec1prog...",
#       "key_hash": "..."
#     }
#   ],
#   "verification_method": "bip85-derivation"
# }

# Option 2: For zero-knowledge proofs (more privacy preserving)
# First, generate the setup parameters (one-time operation)
$ python nostr-zk-proof.py setup --output-dir ~/.nostr-zk

# Generate a zero-knowledge proof for a single key
$ python nostr-zk-proof.py prove --master-nsec nsec1master... --derived-npub npub1prog... --index 6 --output reputation-proof.json

# The client can verify the proof without learning the master private key
$ python nostr-zk-proof.py verify --proof-file reputation-proof.json
# Proof verification: 5/5 valid responses (100.0%)
# The proof successfully demonstrates that the owner of npub1master...
# claims ownership of npub1prog... with index 6
# Proof verification SUCCEEDED

# The ZK proof has several advantages over the simple proof:
# 1. It does not reveal the NSECs of the derived keys
# 2. It uses a challenge-response protocol for stronger verification
# 3. It's more suitable for selective disclosure situations
```

**Analysis:** This enables reputation to flow between identities without revealing their connection publicly. The selective disclosure aspect is key: the master identity can prove that specific identities are related without exposing all other identities.

### Financial Guarantees
**Scenario:** Taylor wants to take out a loan using their pseudonymous identity (npub4), but lacks credit history. Using ZK-proofs, Taylor can have their established identity (npub0) cryptographically guarantee the loan without publicly revealing the connection between the identities.

```bash
# Taylor first created these identities
$ python nostr-derive.py init
# Created master key (npub0) with password

$ python nostr-derive.py create --label "Main Financial Identity" --index 0
# Created main identity 
Public key (npub): npub1master...

$ python nostr-derive.py create --label "Pseudonymous Borrower" --index 4
# Created pseudonymous identity (npub4)
Public key (npub): npub1borrow...

# Taylor creates a ZK proof for the loan provider
$ python nostr-zk-proof.py prove --master-nsec nsec1master... --derived-npub npub1borrow... --index 4 --output loan_guarantee.json

# The loan provider verifies the proof
$ python nostr-zk-proof.py verify --proof-file loan_guarantee.json
# Verification confirms that the well-established identity is backing the loan
# without revealing the relationship publicly
```

**Analysis:** This has interesting implications for pseudonymous finance. A master identity could back derived identities for loans or contracts without revealing the full financial picture, enabling financial services without traditional KYC.

### Cross-Platform Reputation Portability
**Scenario:** Morgan has a high reputation on a rideshare platform (npub3) and wants to use an apartment rental platform (npub5) where trust is essential. Morgan can cryptographically prove to the rental platform that their new account is backed by the same person with an excellent reputation elsewhere.

```bash
# Morgan has derived identities for different platforms
$ python nostr-derive.py create --label "Rideshare Profile" --index 3
# Created rideshare identity with excellent reputation
Public key (npub): npub1ride...

$ python nostr-derive.py create --label "Apartment Rental" --index 5
# Created new rental platform identity
Public key (npub): npub1rent...

# Morgan can provide a zero-knowledge proof to the rental platform 
# to verify the connection to the trusted rideshare account
$ python nostr-zk-proof.py prove --master-nsec nsec1master... --derived-npub npub1ride... --index 3 --output rideshare_proof.json

# The rental platform can verify that Morgan's identity is backed by 
# the same master key that controls the reputable rideshare account
$ python nostr-zk-proof.py verify --proof-file rideshare_proof.json
```

**Analysis:** This solves a major problem in decentralized systems: starting from zero reputation on each new platform. Being able to selectively port reputation between platforms without full identity disclosure creates trust without sacrificing privacy.

### Identity Recovery
**Scenario:** Riley's social media identity (npub2) is compromised when their private key is stolen. Riley creates a new identity (npub7) and uses their master key to cryptographically prove to their network that this new identity is the legitimate continuation of their previous one.

```bash
# Riley had a master key and derived identities
$ python nostr-derive.py list
# Shows multiple identities including the compromised one (index 2)

# Riley creates a new identity after the compromise
$ python nostr-derive.py create --label "New Social Identity" --index 7
# Created new identity (npub7)
Public key (npub): npub1new...

# Riley needs to prove to friends and followers that both the compromised 
# and new identities are controlled by the same person
$ python simple_proof.py --master-nsec nsec1master... --indices 2,7 --output recovery_proof.json

# Riley shares this proof with close contacts privately, or
# uses the ZK proof for more selective disclosure
$ python nostr-zk-proof.py prove --master-nsec nsec1master... --derived-npub npub1new... --index 7 --output recovery_zk.json

# Contacts can verify the proofs
$ python nostr-zk-proof.py verify --proof-file recovery_zk.json
# The verification confirms the new identity comes from the same master key
```

**Analysis:** This addresses a significant vulnerability in current digital identity systems. The master key acts as a recovery mechanism without requiring centralized authority intervention, allowing people to recover from key compromise without losing their entire digital history.

## Conclusion

The combination of BIP-85 derivation and zero-knowledge proofs enables a new model of digital identity management that balances privacy with accountability. By allowing selective disclosure of relationships between identities, we can build systems that preserve privacy by default while enabling trust where needed.

The tools provided in this project are ready to use:

```bash
# Install the requirements
pip install -r requirements.txt

# Create a master key
python nostr-derive.py init

# Create derived identities
python nostr-derive.py create --label "Primary Identity" --index 0
python nostr-derive.py create --label "Anonymous Blog" --index 1

# Create proofs as needed
python simple_proof.py --master-nsec nsec1master... --indices 0,1 --output proof.json
python nostr-zk-proof.py prove --master-nsec nsec1master... --derived-npub npub1blog... --index 1 --output zk_proof.json
```

The most transformative aspect is enabling reputation without persistent identity - allowing individuals to maintain privacy while still benefiting from their established reputation when needed. This approach strikes a balance between anonymity and accountability that could help create a more trust-based but privacy-preserving internet.