# 🔐 Solana Security Cookbook

> **Learn Solana security by breaking things (safely), then fixing them.**

So you want to build on Solana? Great! But here's the thing - one missing line of code can cost millions. This isn't theory - it's happened. A lot.

This cookbook covers the 5 security bugs that keep showing up in audits. For each one, you get vulnerable code, secure code, and tests that actually exploit the vulnerability. Both **Anchor** and **Pinocchio** versions included.

[![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://your-username.github.io/solana-security-cookbook/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What's Inside

Five vulnerabilities that have actually drained protocols:

1. **Missing Signer Check** - Forgot to verify who signed? Anyone can drain anyone's wallet.
2. **Incorrect PDA Validation** - Wrong seeds = attacker controls your "secure" accounts
3. **Arithmetic Overflow** - Numbers wrap around. 255 + 1 = 0. Oops.
4. **Reentrancy in CPI** - Update state after calling another program? Get rekt.
5. **Unsafe Account Closure** - Zombie accounts can come back to haunt you.

## 🚀 Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.75.0+
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) 1.18.0+
- [Anchor](https://www.anchor-lang.com/docs/installation) 0.30.0+
- [Bun](https://bun.sh/) (for running tests)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/solana-security-cookbook.git
cd solana-security-cookbook

# Install dependencies
bun install

# Run a test to see a vulnerability in action
bun test tests/01-missing-signer-check.test.ts
```

## 📚 Repository Structure

```
solana-security-cookbook/
├── _posts/                          # Blog posts (Jekyll)
│   ├── 2025-01-27-missing-signer-check.md
│   ├── 2025-01-27-incorrect-pda-validation.md
│   ├── 2025-01-27-arithmetic-overflow.md
│   ├── 2025-01-27-reentrancy-risk.md
│   └── 2025-01-27-unsafe-account-closure.md
│
├── examples/                        # Code examples
│   ├── 01-missing-signer-check/
│   │   ├── anchor/
│   │   │   ├── vulnerable/         # Exploitable version
│   │   │   └── secure/             # Fixed version
│   │   ├── pinocchio/
│   │   │   ├── vulnerable/
│   │   │   └── secure/
│   │   └── tests/
│   │       └── test.ts
│   └── ... (02-05 follow same structure)
│
├── tests/                           # Test suites
│   ├── 01-missing-signer-check.test.ts
│   └── ... (02-05)
│
└── docs/                            # Additional documentation
    └── security-guide.md
```

## 🧪 Running Tests

Each vulnerability has a dedicated test suite that demonstrates:
- ✅ How the vulnerable version can be exploited
- ✅ How the secure version prevents the exploit

```bash
# Run all tests
bun test

# Run specific vulnerability test
bun test:missing-signer
bun test:pda-validation
bun test:overflow
bun test:reentrancy
bun test:account-closure
```

## 🏗️ Building Examples

### Anchor Programs

```bash
cd examples/01-missing-signer-check/anchor/vulnerable
anchor build

cd ../secure
anchor build
```

### Pinocchio Programs

```bash
cd examples/01-missing-signer-check/pinocchio/vulnerable
cargo build-sbf

cd ../secure
cargo build-sbf
```

## 🎓 Learning Path

### For Beginners

1. Start with the [blog posts](https://your-username.github.io/solana-security-cookbook/) - they use everyday analogies
2. Read the vulnerable code to understand the flaw
3. Compare with the secure version to see the fix
4. Run the tests to see the exploit in action

### For Experienced Developers

1. Jump straight to the code examples
2. Study the Anchor vs Pinocchio differences
3. Review the test suites for attack vectors
4. Apply the patterns to your own programs

## 🔍 Vulnerability Deep Dive

### 1. Missing Signer Check

**The Problem:** Forgetting to verify transaction signatures allows anyone to impersonate anyone.

**Everyday Analogy:** Like a bank teller giving money to anyone who knows your account number, without checking ID.

**The Fix:**
- **Anchor:** Use `Signer<'info>` instead of `AccountInfo<'info>`
- **Pinocchio:** Manually check `account.is_signer()`

[Read full blog post →](https://your-username.github.io/solana-security-cookbook/missing-signer-check)

### 2. Incorrect PDA Validation

**The Problem:** Not properly validating Program Derived Addresses allows attackers to substitute malicious accounts.

**Everyday Analogy:** Like accepting a fake ID because you didn't check the hologram.

**The Fix:**
- **Anchor:** Use `seeds` and `bump` constraints
- **Pinocchio:** Manually derive and validate PDAs

[Read full blog post →](https://your-username.github.io/solana-security-cookbook/incorrect-pda-validation)

### 3. Arithmetic Overflow

**The Problem:** Integer overflow/underflow in release mode can cause unexpected behavior.

**Everyday Analogy:** Like an odometer rolling over from 999,999 to 000,000.

**The Fix:**
- Enable overflow checks or use `checked_*` arithmetic methods

[Read full blog post →](https://your-username.github.io/solana-security-cookbook/arithmetic-overflow)

### 4. Reentrancy Risk in CPI

**The Problem:** Updating state after cross-program invocations allows reentrancy attacks.

**Everyday Analogy:** Like updating your bank balance after already handing over the cash.

**The Fix:**
- Always update state before making CPI calls

[Read full blog post →](https://your-username.github.io/solana-security-cookbook/reentrancy-risk)

### 5. Unsafe Account Closure

**The Problem:** Improperly closing accounts can lead to revival attacks and rent reclamation exploits.

**Everyday Analogy:** Like canceling a credit card but not destroying it - someone could reactivate it.

**The Fix:**
- **Anchor:** Use the `close` constraint
- **Pinocchio:** Manually zero data and transfer lamports

[Read full blog post →](https://your-username.github.io/solana-security-cookbook/unsafe-account-closure)

## 🆚 Anchor vs Pinocchio

| Feature | Anchor | Pinocchio |
|---------|--------|-----------|
| **Dependencies** | Many (anchor-lang, etc.) | Zero external deps |
| **Account Type** | `AccountInfo` | `AccountView` |
| **Public Key Type** | `Pubkey` | `Address` |
| **Signer Check** | `Signer<'info>` (automatic) | `is_signer()` (manual) |
| **PDA Validation** | `seeds` + `bump` constraints | Manual derivation |
| **Compute Units** | Higher | Lower (20-50% savings) |
| **Binary Size** | Larger | Smaller |
| **Development Speed** | Faster (abstractions) | Slower (manual work) |
| **Best For** | Rapid development | Production optimization |

## 📖 Additional Resources

- [Pinocchio Documentation](https://docs.rs/pinocchio)
- [Anchor Documentation](https://www.anchor-lang.com/)
- [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- [Neodyme Security Blog](https://blog.neodyme.io/)
- [Cantina Solana Security Guide](https://cantina.xyz/blog/securing-solana-a-developers-guide)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

The vulnerable code examples in this repository are for **educational purposes only**. Never deploy vulnerable code to production. Always conduct thorough security audits before deploying smart contracts.

## 🙏 Acknowledgments

- [Anchor Framework](https://www.anchor-lang.com/) for the excellent Solana development framework
- [Pinocchio](https://github.com/anza-xyz/pinocchio) for the zero-dependency optimization library
- [Neodyme](https://neodyme.io/) for their security research
- The Solana developer community for continuous security improvements

---

**Built with ❤️ for the Solana community**

[View Blog](https://your-username.github.io/solana-security-cookbook/) | [Report Issue](https://github.com/your-username/solana-security-cookbook/issues) | [Contribute](CONTRIBUTING.md)
