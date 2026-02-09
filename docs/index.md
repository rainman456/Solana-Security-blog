---
layout: home
title: Solana Security Cookbook
---

# 🔐 Solana Security Cookbook

**Learn to write secure Solana programs through real vulnerabilities and working code examples.**

---

## Welcome! 👋

Building on Solana? Security should be your top priority. This cookbook teaches you **critical vulnerabilities** in Solana smart contract development through a **binary learning experience**:

1. **The Exploit:** A program stripped of its defenses to show *how* it breaks.
2. **The Shield:** The same logic hardened using **Anchor** constraints and **Pinocchio** manual validations.

We provide:

- 🎯 **Real code examples** - See vulnerable and secure versions side-by-side
- 🧪 **Working exploits** - Run tests that demonstrate actual attacks
- 📚 **Beginner-friendly explanations** - Understand complex concepts through everyday analogies
- ⚡ **Two frameworks** - Learn both Anchor and Pinocchio approaches

## The Vulnerability Collection

<div class="vulnerability-grid">
  {% for post in site.posts %}
    {% include security-card.html post=post %}
  {% endfor %}
</div>

---

## Why This Cookbook?

### 🎓 Learn by Doing

Every vulnerability includes:
- ✅ Vulnerable code you can compile
- ✅ Secure version showing the fix
- ✅ TypeScript tests demonstrating the exploit
- ✅ Step-by-step explanations

### 🆚 Two Frameworks, One Goal

Compare **Anchor** (high-level, rapid development) with **Pinocchio** (zero-dependency, optimized):

| Feature | Anchor | Pinocchio |
|---------|--------|-----------|
| Signer Check | `Signer<'info>` | `is_signer()` |
| PDA Validation | Automatic | Manual |
| Compute Units | Higher | 20-50% lower |
| Development | Faster | More control |

### 📊 Real-World Impact

These aren't theoretical vulnerabilities. They've caused:
- 💰 **Millions in losses** across DeFi protocols
- 🚨 **Critical exploits** in production programs
- 😰 **Loss of user trust** in vulnerable projects

**Learn to prevent them before they cost you.**

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/rainman456/Solana-Security-blog .git
cd examples


```

**Output:**
```
❌ Vulnerable: Bob can steal Alice's money
  💰 Alice deposits: 10 SOL
  💸 Bob attempts to withdraw: 5 SOL
  ⚠️  Bob is NOT Alice!
  ❌ ATTACK SUCCEEDED - Bob stole 5 SOL

✅ Secure: Bob's attack is blocked
  🛡️  Secure program checks: Did Alice sign?
  ✅ Alice didn't sign → Transaction rejected
  ✅ ATTACK BLOCKED!
```

---

## Who Is This For?

### 🌱 Beginners
- New to Solana development
- Want to understand security from day one
- Prefer learning through examples and analogies

**Start here:** Read the blog posts in order, run the tests, compare the code.

### 🚀 Experienced Developers
- Already building on Solana
- Want to audit your existing code
- Need to optimize with Pinocchio

**Start here:** Jump to the code examples, study the test suites, apply the patterns.

### 🔍 Security Auditors
- Reviewing Solana programs
- Need reference implementations
- Want comprehensive test coverage

**Start here:** Explore the vulnerable versions, understand attack vectors, verify fixes.

---

## Learning Path

1. **Read** - Start with a vulnerability blog post
2. **Understand** - Study the vulnerable code
3. **Compare** - See how the secure version fixes it
4. **Test** - Run the exploit demonstration
5. **Apply** - Use the patterns in your own programs

---

## What Makes This Different?

### ✅ Beginner-Friendly Analogies

Complex security concepts explained through everyday situations:
- Missing signer check = Bank teller not checking ID
- PDA validation = Checking hologram on an ID card
- Arithmetic overflow = Odometer rolling over
- Reentrancy = Updating bank balance after handing over cash
- Account closure = Canceling a credit card but not destroying it

### ✅ Working Code, Not Theory

Every example compiles and runs. You can:
- Build the vulnerable programs
- Build the secure programs
- Run tests that demonstrate exploits
- Modify code to experiment

### ✅ Framework Comparison

See the same vulnerability in both Anchor and Pinocchio:
- Understand the tradeoffs
- Choose the right tool for your project
- Learn optimization techniques

---



## Ready to Secure Your Solana Programs?

<div class="cta-buttons">
  <a href="{{ '/identity & access control/2025/01/27/missing-signer-check.html' | relative_url }}" class="btn btn-primary">Start Learning →</a>
  <a href="https://github.com/your-username/solana-security-cookbook" class="btn btn-secondary">View on GitHub</a>
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
