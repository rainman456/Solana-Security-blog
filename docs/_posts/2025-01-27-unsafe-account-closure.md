---
layout: post
title: "Unsafe Account Closure"
date: 2025-01-27
category: "Data Integrity"
difficulty: "Intermediate"
checklist: 
  - "Are you using Anchor's `close` constraint?"
  - "If manual: Did you transfer ALL lamports out?"
  - "If manual: Did you zero the data array?"
  - "If manual: Did you assign the owner to System Program?"
---

## 📖 The Scenario
You sell your house. You hand the keys to the new owner and they pay you.
But... you keep a spare key. And you leave all your furniture inside. And technically, your name is still on the deed at City Hall.

Later, you use your spare key to walk back in, claim "this is still my house," and trick a moving company into emptying it for you again.

## 💡 The "Aha!" Moment
Closing an account in Solana isn't just about draining the money. It's about **Garbage Collection**.

If you drain the lamports but leave the account **owned by your program** with its data intact, it's a "Zombie Account". Anyone can send a tiny amount of SOL to it later, revive it, and because the old data (e.g., specific user permissions) is still there, they can exploit it.

<div class="diagram-container">
  <img src="/solana-security-cookbook/assets/images/diagrams/account-closure.svg" alt="Account Closure Vulnerability Diagram">
</div>

## ⚔️ The Exploit
### Vulnerable vs Secure

{% capture vulnerable_desc %}
Manually transferring lamports looks correct, but fails to "clean up" the deed (Owner) or the contents (Data).
{% endcapture %}

{% capture vulnerable_code %}
pub fn close(ctx: Context<Close>) -> Result<()> {
    // ❌ Only moves money!
    let dest = &ctx.accounts.user;
    let vault = &ctx.accounts.vault;
    **dest.lamports.borrow_mut() += vault.lamports();
    **vault.lamports.borrow_mut() = 0;
    
    // Account is still owned by Program!
    // Data is still inside!
}
{% endcapture %}

{% capture secure_desc %}
Using Anchor's `close` constraint handles the entire "Garbage Collection" ritual for you.
{% endcapture %}

{% capture secure_code %}
#[account]
pub struct Close<'info> {
    #[account(
        mut, 
        // ✅ Magic Constraint
        // 1. Zeros data
        // 2. Transfers lamports
        // 3. Reassigns owner to System Program
        close = user
    )]
    pub vault: Account<'info, Vault>,
    pub user: SystemAccount<'info>,
}
{% endcapture %}

{% include comparison-card.html 
   vulnerable_desc=vulnerable_desc 
   vulnerable_code=vulnerable_code 
   secure_desc=secure_desc 
   secure_code=secure_code 
%}

## 🧠 Mental Model: The Burn & Salting
Closing an account effectively means destroying it forever.
1. **Empty the safe** (Transfer Lamports).
2. **Burn the contents** (Zero Data).
3. **Change the Locks** (Reassign Owner to System Program).

If you skip step 3, the account is just "dormant" under your control, waiting to be re-awakened (Revival Attack).

<blockquote class="pro-tip">
  <strong>🏆 Golden Rule:</strong><br>
  Use Anchor's <code>close = target</code> constraint whenever possible. If you must do it manually, you MUST perform all 3 steps: Empty Lamports, Zero Data, Assign to System Program.
</blockquote>
