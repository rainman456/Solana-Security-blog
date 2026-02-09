# 🛡️ Solana Security: The "Broken vs. Secure" Cookbook

> **An Educational Deep-Dive for the SuperteamNG Security Bounty.** > Transforming Solana security from abstract theory into side-by-side, practical implementation.

**[Explore the Live Blog →](https://rainman456.github.io/Solana-Security-blog/)**

---

## 👋 Welcome

This repository is designed to be a high-signal resource for the Solana ecosystem. Rather than just listing vulnerabilities, we provide a **binary learning experience**:

1. **The Exploit:** A program stripped of its defenses to show *how* it breaks.
2. **The Shield:** The same logic hardened using **Anchor** constraints and **Pinocchio** manual validations.

**Key Highlights for Evaluation:**

* **Dual-Framework:** We compare the "Macro Magic" of Anchor with the "Bare-Metal" safety of Pinocchio.
* **Traceable Tests:** Every vulnerability includes an `exploit.ts` to prove the bug and a `verify.ts` to prove the fix.
* **Educational Narrative:** This isn't just code; it's a blog-first resource designed for developers and non-technical stakeholders alike.

---

## 🏗️ Project Architecture

The repository is organized by vulnerability "modules." Each module is a self-contained Solana workspace.

```text
.
├── examples/
│   ├── 01-missing-signer-check/      # Side-by-side: Anchor & Pinocchio
│   ├── 02-incorrect-pda-validation/  # Prevention of PDA spoofing
│   ├── 03-arithmetic-overflow/       # Safe math vs. Checked math
│   ├── 04-reentrancy-risk/           # State management & CPI ordering
│   ├── 05-unsafe-account-closure/    # Preventing "Zombie" accounts
│   ├── 06-missing-mint-validation/   # Token-land security basics
│   ├── 07-arbitrary-cpi-validation/  # Program ID verification
│   └── 08-toctou-race-condition/     # Time-of-check to Time-of-use risks
├── tests/                            # Shared test utilities
└── [Blog Files]                      # Jekyll source for the visual guide

```

---

## 🔒 The Vulnerability Matrix

| Module | Vulnerability | Severity | Anchor Defense | Pinocchio Defense |
| --- | --- | --- | --- | --- |
| **01** | **Missing Signer Check** | 🔴 High | `Signer<'info>` | `account.is_signer()` |
| **02** | **Incorrect PDA Validation** | 🔴 Critical | `seeds / bump` constraints | `find_program_address` |
| **03** | **Arithmetic Overflow** | 🟡 High | `checked_add/sub/mul` | `checked_*` methods |
| **04** | **Cross-Program Reentrancy** | 🔴 Critical | CEI Pattern | CEI Pattern + Guards |
| **05** | **Unsafe Account Closure** | 🟡 High | `close = target` | Manual 3-step closure |
| **06** | **Missing Mint Validation** | 🔴 High | Token constraints | Manual mint checks |
| **07** | **Arbitrary CPI Validation** | 🔴 Critical | Program ID constraints | Manual program checks |
| **08** | **TOCTOU Race Condition** | 🔴 Critical | Atomic state updates | Single-tx validation |

---

## 🚀 Quick Start for Auditors & Developers

### 1. Explore the Structure

Each vulnerability in `/examples` contains both **Anchor** and **Pinocchio** implementations:

```
01-missing-signer-check/
├── anchor/
│   ├── vulnerable/    # Broken implementation
│   └── secure/        # Fixed implementation
├── pinocchio/
│   ├── vulnerable/
│   └── secure/
└── tests/             # TypeScript exploit & verification tests
```

### 2. Run the Tests

Each example includes `exploit.ts` (demonstrates the vulnerability) and `verify.ts` (proves the fix):

```bash
cd examples/01-missing-signer-check/tests/anchor
npm install or bun install 
npm test  or bun test # Runs both exploit and verification tests
```

### 3. Read the Deep Dive

Our [Live Blog](https://rainman456.github.io/Solana-Security-blog/) provides detailed technical breakdowns, real-world case studies, and mental models for each vulnerability.

---

## 🎓 What's Covered

This cookbook demonstrates **8 critical Solana security vulnerabilities** through working code examples:

1.  **Missing Signer Check** - Authorization bypass through unverified signatures
2.  **Incorrect PDA Validation** - Account spoofing via improper seed verification
3.  **Arithmetic Overflow** - Integer wraparound exploits in financial calculations
4.  **Cross-Program Reentrancy** - State manipulation through CPI callbacks
5.  **Unsafe Account Closure** - Zombie account revival attacks
6.  **Missing Mint Validation** - Token authenticity bypass
7.  **Arbitrary CPI Validation** - Malicious program invocation
8.  **TOCTOU Race Condition** - Time-of-check to time-of-use exploits

Each vulnerability includes:
-   **Vulnerable** and **Secure** implementations in both Anchor and Pinocchio
-   **TypeScript tests** demonstrating exploits and verifying fixes
-   **Detailed blog posts** with real-world case studies and mental models

## 🎓 Why This Matters

Solana's account model is powerful but unforgiving. Small mistakes in account validation, signer verification, or state management can lead to critical exploits. This repository serves as a **security checklist** for developers and auditors to identify and prevent common vulnerabilities before deployment.

---

## 🤝 Contributing & License

This is an open-source educational project. All code is licensed under **MIT**.

**Build on Solana. Build Securely.**

---

