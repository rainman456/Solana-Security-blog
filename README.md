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
| **01** | **Missing Signer** | 🔴 Critical | `Signer<'info>` | `account.is_signer()` |
| **02** | **PDA Spoofing** | 🔴 Critical | `seeds / bump` | `find_program_address` |
| **03** | **Overflows** | 🟡 High | `checked_add` | `checked_ops` |
| **04** | **Re-entrancy** | 🔴 Critical | State-Locks | Account ordering |
| **05** | **Zombie Accounts** | 🟡 High | `close = target` | Manual Lamport drain |

---

## 🚀 Quick Start for Auditors & Developers

### 1. Browse the Code

Navigate to any folder in `/examples`. You will find a `vulnerable` and a `secure` directory. Read the `lib.rs` files side-by-side to see the diff.

### 2. Run the Proof-of-Concept

To see the exploit in action:

```bash
cd examples/01-missing-signer-check/anchor
anchor test

```

*The test suite is designed to fail the "Exploit" test on the vulnerable program and pass all tests on the secure program.*

### 3. Read the Deep Dive

Our [Live Blog](https://rainman456.github.io/Solana-Security-blog/) provides a technical breakdown of *why* these patterns matter and how to spot them during a peer review.

---

## 🎓 Why This Matters

Solana’s account model is powerful but unforgiving. Small mistakes in account ownership or signer verification lead to million-dollar exploits. This project serves as a **Pre-Audit Checklist** for developers to ensure their programs aren't just functional, but battle-hardened.

---

## 🤝 Contributing & License

This is an open-source educational project. All code is licensed under **MIT**.

**Build on Solana. Build Securely.**

---

