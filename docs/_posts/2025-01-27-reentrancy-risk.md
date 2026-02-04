---
layout: post
title: "Cross-Program Reentrancy"
date: 2025-01-27
category: "External Interactions"
difficulty: "Advanced"
checklist: 
  - "Do you update state BEFORE calling another program (CPI)?"
  - "Are you following the 'Checks-Effects-Interactions' pattern?"
  - "Be careful with 'invoke_signed' if you haven't updated balances yet."
---

## 📖 The Scenario
You are a cashier. A customer hands you a check for $100.
1. You hand them $100 cash.
2. You turn around to write "$100 withdrawn" in your ledger.

Between step 1 and 2, while your back is turned, the customer quickly hands you **the same check again**. Since you haven't written in the ledger yet, you think "Oh, they haven't withdrawn anything!" and hand them another $100. They drain your register before you write a single line.

## 💡 The "Aha!" Moment
Solana programs can call other programs (**CPI** - Cross-Program Invocation).
Crucially, when you call another program, you **pause** your execution and hand control to them.

If that other program (the "customer") is malicious, it can call **back** into your program (`withdraw`) *before* you finished updating your balances. It sees the old balance and withdraws again.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/reentrancy.svg" alt="Reentrancy Vulnerability Diagram">
</div>

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
**Interactions BEFORE Effects**: The program gives the money *before* updating its own records.
{% endcapture %}

{% capture vulnerable_code %}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // 1. Check Balance
    if ctx.accounts.vault.balance < amount { ... }

    // 2. Transfer (CPI) - DANGER ZONE 🚨
    // Control hands over to 'to' account here!
    anchor_lang::solana_program::program::invoke(...)

    // 3. Update Balance (Too late!)
    ctx.accounts.vault.balance -= amount;
}
{% endcapture %}

{% capture secure_desc %}
**Checks-Effects-Interactions**: The program updates its records *before* handing over any money.
{% endcapture %}

{% capture secure_code %}
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // 1. Check Balance
    if ctx.accounts.vault.balance < amount { ... }

    // 2. Update Balance - EFFECT ✅
    // Re-entrant calls will see this new lower balance
    ctx.accounts.vault.balance -= amount;

    // 3. Transfer (CPI) - INTERACTION 🚀
    anchor_lang::solana_program::program::invoke(...)
}
{% endcapture %}

{% include comparison-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🧠 Mental Model: The Ledger First
Always behave like a paranoid accountant.
1. **Checks**: Verify the check is valid.
2. **Effects**: Write down "Money Gone" in the ledger.
3. **Interactions**: Finally, hand over the cash.

This order (CEI) guarantees that no matter what the customer does with the cash (or if they try to trick you), your books are already closed on that transaction.

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  <strong>Checks-Effects-Interactions</strong>. Memorize it. Live it. Update your state <em>before</em> you call <code>invoke</code> or <code>invoke_signed</code>.
</blockquote>
