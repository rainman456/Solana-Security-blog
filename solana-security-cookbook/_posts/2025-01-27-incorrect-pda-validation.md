---
layout: post
title: "Incorrect PDA Validation"
date: 2025-01-27
category: "Identity & Access Control"
difficulty: "Intermediate"
checklist: 
  - "Are all PDAs derived using unique seeds (e.g., user pubkey)?"
  - "Does your instruction verify that the passed account matches the derived PDA?"
  - "For Anchor: Are you using the `seeds` and `bump` constraints?"
---

## 📖 The Scenario
You run a secure locker service. Each user is assigned a specific locker number based on their name (e.g., "Alice" → Locker #101).

Alice comes in to store her gold. A thief walks in behind her, claims to be "Bob", but points to Locker #101 (Alice's locker) and says "That's mine." If you don't check your ledger to confirm that "Bob" should actually have Locker #202, you might let him open Alice's locker.

## 💡 The "Aha!" Moment
A **Program Derived Address (PDA)** is purely deterministic. `Function(Seeds) = Address`.

The vulnerability happens when your program accepts a "Vault" account from the user but **fails to check** if that Vault was actually derived from the correct seeds. You trust the user's input instead of trusting the math.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/pda-validation.svg" alt="PDA Validation Vulnerability Diagram">
</div>

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
The program accepts `vault` as an argument but never verifies it matches the seeds. The attacker can pass a fake vault they created.
{% endcapture %}

{% capture vulnerable_code %}
#[account]
pub struct Withdraw<'info> {
    pub user: Signer<'info>,
    /// ❌ No seeds check!
    /// Attacker can pass ANY account here
    #[account(mut)]
    pub vault: Account<'info, Vault>,
}
{% endcapture %}

{% capture secure_desc %}
Anchor validates that `vault` MUST equal the address derived from `[b"vault", user.key]`.
{% endcapture %}

{% capture secure_code %}
#[account]
pub struct Withdraw<'info> {
    pub user: Signer<'info>,
    /// ✅ Anchor verifies address derivation
    #[account(
        mut,
        seeds = [b"vault", user.key().as_ref()],
        bump
    )]
    pub vault: Account<'info, Vault>,
}
{% endcapture %}

{% include security-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🧠 Mental Model: The Deterministic Map
Think of PDA derivation as a GPS coordinate.
- **Seeds**: "Latitude 40, Longitude -70".
- **PDA**: The exact spot on the ground.

If you don't check the coordinates, a user can hand you a map pointing to a completely different location (someone else's house) and say "This is my house." You must calculate the coordinates yourself to verify.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Never trust the client to provide the correct PDA. Always <strong>derive it yourself</strong> on-chain (or let Anchor do it) and compare it.
</blockquote>
