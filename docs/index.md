---
layout: home
title: Solana Security Cookbook
---

# 🔐 Solana Security Cookbook

**Learn to write secure Solana programs through real vulnerabilities and working code examples.**

---

## Welcome

Building on Solana? Security should be your top priority. This cookbook teaches critical vulnerabilities in Solana smart contract development through a binary learning experience:

1. **The Exploit:** A program stripped of its defenses to show how it breaks.
2. **The Shield:** The same logic hardened using Anchor constraints and Pinocchio manual validations.

What you'll find here:

- **Real code examples** - Vulnerable and secure versions side-by-side
- **Working exploits** - Tests that demonstrate actual attacks
- **Clear explanations** - Complex concepts explained through everyday analogies
- **Two frameworks** - Both Anchor and Pinocchio implementations

## The Vulnerability Collection

<div class="vulnerability-grid">
  {% for post in site.posts %}
    {% include security-card.html post=post %}
  {% endfor %}
</div>

---

## Why This Cookbook?

### Learn by Doing

Every vulnerability includes:
- Vulnerable code you can compile
- Secure version showing the fix
- TypeScript tests demonstrating the exploit
- Step-by-step explanations

### Two Frameworks, One Goal

Compare Anchor (high-level, rapid development) with Pinocchio (zero-dependency, optimized):

| Feature | Anchor | Pinocchio |
|---------|--------|-----------|
| Signer Check | `Signer<'info>` | `is_signer()` |
| PDA Validation | Automatic | Manual |
| Compute Units | Higher | 20-50% lower |
| Development | Faster | More control |

### Real-World Impact

These aren't theoretical vulnerabilities. They've caused millions in losses across DeFi protocols, critical exploits in production programs, and loss of user trust in vulnerable projects.

Learn to prevent them before they cost you.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/rainman456/Solana-Security-blog.git
cd Solana-Security-blog/cookbook-gem
```

### 2. Explore the Structure

Each vulnerability in `examples/` contains both Anchor and Pinocchio implementations:

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

### 3. Run the Tests

```bash
cd examples/01-missing-signer-check/tests/anchor
npm install
npm test  # Runs both exploit and verification tests
```

The tests demonstrate the vulnerability in action and prove the fix works.

---

## Who Is This For?

**Beginners:** New to Solana development and want to understand security from day one. Start by reading the blog posts in order, running the tests, and comparing the code.

**Experienced Developers:** Already building on Solana and want to audit your existing code or optimize with Pinocchio. Jump to the code examples, study the test suites, and apply the patterns.

**Security Auditors:** Reviewing Solana programs and need reference implementations with comprehensive test coverage. Explore the vulnerable versions, understand attack vectors, and verify fixes.

---

## Learning Path

1. **Read** - Start with a vulnerability blog post
2. **Understand** - Study the vulnerable code
3. **Compare** - See how the secure version fixes it
4. **Test** - Run the exploit demonstration
5. **Apply** - Use the patterns in your own programs

---

## What Makes This Different?

**Beginner-Friendly Analogies:** Complex security concepts explained through everyday situations. Missing signer checks are like bank tellers not checking ID. PDA validation is like checking the hologram on an ID card. Arithmetic overflow is like an odometer rolling over.

**Working Code, Not Theory:** Every example compiles and runs. You can build the vulnerable programs, build the secure programs, run tests that demonstrate exploits, and modify code to experiment.

**Framework Comparison:** See the same vulnerability in both Anchor and Pinocchio. Understand the tradeoffs, choose the right tool for your project, and learn optimization techniques.

---



## Ready to Secure Your Solana Programs?

<div class="cta-buttons">
  <a href="{{ '/identity & access control/2025/01/27/missing-signer-check.html' | relative_url }}" class="btn btn-primary">Start Learning →</a>
  <a href="https://github.com/rainman456/Solana-Security-blog" class="btn btn-secondary">View on GitHub</a>
</div>

---

## Resources

- 📖 [Pinocchio Documentation](https://docs.rs/pinocchio)
- 📖 [Anchor Documentation](https://www.anchor-lang.com/)
- 🔒 [Solana Security Best Practices](https://docs.solana.com/developing/programming-model/security)
- 🛡️ [Neodyme Security Blog](https://blog.neodyme.io/)
- 🔐 [Cantina Security Guide](https://cantina.xyz/blog/securing-solana-a-developers-guide)

---

<div class="disclaimer">
  <strong>⚠️ Disclaimer:</strong> The vulnerable code examples are for educational purposes only. Never deploy vulnerable code to production. Always conduct thorough security audits before deploying smart contracts.
</div>

---

**Built with ❤️ for the Solana community**
