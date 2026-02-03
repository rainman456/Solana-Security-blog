---
layout: post
title: "The Missing Signer Check"
date: 2025-01-27
category: "Identity & Access Control"
difficulty: "Beginner"
checklist: 
  - "Does every sensitive instruction use `Signer<'info>` for the authority?"
  - "Did you double check if an account `is_signer` before transferring funds?"
---

## 📖 The Scenario
Imagine you build a high-tech vault for your bank. The lock is unbreakable, the walls are titanium. But you leave the back door wide open, and anyone—even a random passerby—can simply walk in and carry out sacks of cash.

In Solana, this happens when you forget to check if an account **signed** the transaction. You might *think* `user_account` refers to the person calling the function, but without the signature check, it's just a public key anyone can spoof.

## 💡 The "Aha!" Moment
Solana accounts are just data. Just because I pass `Alice`'s public key into a function doesn't mean I *am* Alice. 

Unless the program verifies that the transaction was **signed** by the private key corresponding to that public key, the instruction is just a request from an anonymous stranger claiming to be Alice.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/missing-signer.svg" alt="Missing Signer Vulnerability Diagram">
</div>

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
Checking `AccountInfo` without validating `is_signer` allows anyone to pass ANY public key as the "authority".
{% endcapture %}

{% capture vulnerable_code %}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let user = &ctx.accounts.user;
    // ❌ Anyone can pass any public key here!
    // No proof of ownership required.
    ...
}
{% endcapture %}

{% capture secure_desc %}
Using `Signer<'info>` in Anchor automatically enforcing the check.
{% endcapture %}

{% capture secure_code %}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // ✅ Anchor checks this MUST sign
    let user: Signer<'info> = &ctx.accounts.user;
    ...
}
{% endcapture %}

{% include security-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🧠 Mental Model: The Passport
Think of a Solana Transaction as entering a country.
- **Public Key**: This is just your name written on a piece of paper. Anyone can write "Alice".
- **Signature**: This is your physical Passport with your photo and holographic seal. Only *you* can produce it.

If your program only checks the name on the paper (Public Key) and ignores the Passport (Signature), you are letting illegal immigrants raid your vault.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  If an instruction performs a sensitive action (transferring funds, changing state) on behalf of a user, that user <strong>MUST</strong> be a <code>Signer</code>.
</blockquote>