---
layout: post
title: "The Solana Security Lab: Master Index"
date: 2025-01-28
category: "Guide"
difficulty: "All Levels"
checklist: 
  - "Have you read all 5 modules?"
  - "Did you memorize the 'Golden Rule' for each?"
---

## Welcome to the Lab 🧪

This is your comprehensive guide to the most dangerous pitfalls in Solana development. Each module below breaks down a specific vulnerability using the **Anatomy of an Exploit** system:
1. **The Scenario**: Real-world analogy.
2. **The Code**: Vulnerable vs Secure side-by-side.
3. **The Diagram**: Visual logic flow.
4. **The Fix**: Pinocchio & Anchor best practices.

## 🗂️ The Modules

### 🔐 Identity & Access Control
**"Who are you, and are you allowed to do this?"**
- [**The Missing Signer Check**](./missing-signer-check)  
  *The "Open Back Door" vulnerability.*
- [**Incorrect PDA Validation**](./incorrect-pda-validation)  
  *The "Fake ID" vulnerability.*

### 🧮 Data Integrity
**"Are the numbers real?"**
- [**Integer Arithmetic Overflow**](./arithmetic-overflow)  
  *The "Odometer Reset" vulnerability.*
- [**Unsafe Account Closure**](./unsafe-account-closure)  
  *The "Zombie Account" vulnerability.*

### 🔄 External Interactions
**"Can I trust this phone call?"**
- [**Cross-Program Reentrancy**](./reentrancy-risk)  
  *The "Paranoid Cashier" check.*

---

## 🛡️ The Ultimate Audit Checklist

Before you deploy your program to Mainnet, ask these 5 questions. If the answer is "No" or "I don't know," **do not deploy**.

1. **Signer**: "Does every sensitive instruction enforce `is_signer` on the authority?"
2. **PDA**: "Do I manually derive and verify all PDA addresses (or use Anchor seeds)?"
3. **Math**: "Is every single math operation using `.checked_add/sub`?"
4. **CPI**: "Do I update my state **BEFORE** calling any other program?"
5. **Close**: "Do I zero data and transfer lamports when closing an account?"

---

<blockquote class="pro-tip">
  <strong>Final Thought:</strong><br>
  Security is not effective if it is complicated. Complexity is the enemy of security. Keep your logic simple, your checks explicit, and your sleep peaceful.
</blockquote>
