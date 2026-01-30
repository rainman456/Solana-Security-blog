# Solana Security Examples: Vulnerable vs Secure Code

> A comprehensive educational resource demonstrating common security vulnerabilities in Solana programs and how to fix them properly.

## 📚 Overview

This repository contains real-world security vulnerability examples for Solana program development, with side-by-side comparisons of **vulnerable** and **secure** implementations. Each example includes detailed explanations of:

- **What went wrong**: The security vulnerability and why it's dangerous
- **How to fix it**: The correct implementation with security best practices
- **Attack scenarios**: Real-world exploitation possibilities
- **Testing**: Demonstrations of both the exploit and the fix

## 🎯 Purpose

Security remains one of the biggest challenges in Solana development. Many exploits don't come from complex attacks but from simple mistakes:
- Missing account validation
- Incorrect authority checks
- Unsafe arithmetic operations
- Misunderstood CPI behavior
- Missing PDA verification
- Improper state management

This repository makes security concepts **practical and obvious**, especially for developers learning Anchor or Pinocchio.

## 🏗️ Repository Structure

```
solana-security-examples/
│
├── 01-missing-signer-check/
│   ├── vulnerable/          # Broken implementation
│   ├── secure/              # Fixed implementation
│   └── README.md            # Detailed explanation
│
├── 02-missing-owner-check/
│   ├── vulnerable/
│   ├── secure/
│   └── README.md
│
├── 03-arithmetic-overflow/
│   ├── vulnerable/
│   ├── secure/
│   └── README.md
│
├── 04-pda-verification/
│   ├── vulnerable/
│   ├── secure/
│   └── README.md
│
├── 05-type-cosplay/
│   ├── vulnerable/
│   ├── secure/
│   └── README.md
│
├── 06-reinitialization-attack/
│   ├── vulnerable/
│   ├── secure/
│   └── README.md
│
├── 07-arbitrary-cpi/
│   ├── vulnerable/
│   ├── secure/
│   └── README.md
│
└── security-guide.md        # Comprehensive security guide
```

## 🔒 Security Vulnerabilities Covered

### 1. Missing Signer Check
**Severity**: 🔴 Critical

Anyone can execute privileged operations without proper authorization.

**Example**: A withdrawal function that doesn't verify the signer is the account owner.

### 2. Missing Owner Check
**Severity**: 🔴 Critical

Accepting accounts owned by arbitrary programs, allowing attackers to provide fake data.

**Example**: Accepting a token account from any program, not just the SPL Token program.

### 3. Arithmetic Overflow/Underflow
**Severity**: 🟡 High

Unchecked math operations can overflow or underflow, leading to incorrect calculations.

**Example**: Token minting without checking for overflow, allowing infinite token creation.

### 4. Missing PDA Verification
**Severity**: 🔴 Critical

Not verifying that a PDA was derived correctly allows attackers to substitute fake accounts.

**Example**: Accepting any account as a vault without verifying its seeds.

### 5. Type Cosplay
**Severity**: 🔴 Critical

Not validating account discriminators allows attackers to pass wrong account types.

**Example**: Passing a wallet account instead of a vault state account.

### 6. Reinitialization Attack
**Severity**: 🟡 High

Allowing accounts to be reinitialized can reset critical state.

**Example**: Reinitializing a vault to reset its owner field.

### 7. Arbitrary CPI
**Severity**: 🔴 Critical

Not validating the program ID in cross-program invocations allows malicious program execution.

**Example**: Calling arbitrary programs through CPI without verification.

## 🛠️ Framework Coverage

This repository demonstrates security patterns in both:

- **Anchor**: High-level framework with built-in safety features
- **Pinocchio**: Zero-dependency library for compute-optimized programs

Each vulnerability shows how the frameworks handle (or fail to handle) security differently.

## 📖 How to Use This Repository

### For Learning
1. Start with the `security-guide.md` for foundational concepts
2. Read each vulnerability's README in order (01 → 07)
3. Study the vulnerable code first to understand the mistake
4. Compare with the secure version to see the fix
5. Run the tests (if provided) to see the exploit in action

### For Reference
- Use as a checklist when reviewing code
- Reference specific patterns when implementing similar features
- Share with your team during security audits

### For Building
- Copy secure patterns into your own programs
- Adapt the validation logic to your specific use case
- Use the comments as documentation templates

## 🧪 Testing

Each example includes test scenarios demonstrating:
1. **Exploit test**: Shows how the vulnerability can be exploited
2. **Fix verification**: Confirms the secure version prevents the exploit

Run tests with:
```bash
# For Anchor examples
cd 01-missing-signer-check/secure
anchor test

# For Pinocchio examples
cd 01-missing-signer-check/secure
cargo test-sbf
```

## 🎓 Educational Content

This repository includes:
- **Inline comments**: Every line of security-critical code is explained
- **Detailed READMEs**: Each vulnerability has a deep-dive explanation
- **Visual diagrams**: Attack vectors and data flows
- **Comparison tables**: Anchor vs Pinocchio approaches

## ⚠️ Important Notes

- **Do not deploy vulnerable code**: These examples are for education only
- **Always test**: Security vulnerabilities can be subtle
- **Stay updated**: Security best practices evolve
- **Get audited**: Complex programs should undergo professional audits

## 🤝 Contributing

This is an open-source educational resource. Contributions are welcome:
- Additional vulnerability examples
- Improved explanations
- Test cases
- Documentation improvements

## 📚 Additional Resources

- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Anchor Security Guidelines](https://www.anchor-lang.com/docs/security)
- [Pinocchio Documentation](https://github.com/anza-xyz/pinocchio)
- [Neodyme Solana Security Workshop](https://workshop.neodyme.io/)

## 📝 License

This repository is licensed under the MIT License. Use it freely for education and reference.

## 🙏 Acknowledgments

Built for the Solana developer community to make security knowledge accessible and practical.

---

**Remember**: Security is not optional. Every line of code that handles value or authority must be carefully reviewed and tested.