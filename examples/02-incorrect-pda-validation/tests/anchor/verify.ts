/**
 * VERIFY TEST: PDA Validation Fix (Anchor)
 * 
 * This test verifies that the secure version properly validates PDA derivation,
 * preventing unauthorized access to other users' vaults.
 * 
 * Fix: The withdraw instruction includes seeds and bump validation in the #[account]
 * attribute, ensuring the vault PDA is derived from the user's public key.
 * 
 * Expected Result: The exploit should FAIL with a seeds constraint error.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";

describe("02-incorrect-pda-validation: Anchor Verify Fix", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const PROGRAM_ID = new PublicKey("HmbTLCmaGvZhKnn1Zfa1JVnp7vkMV4DYVxPLWBVoN65L");

    it("Prevents cross-user vault access with proper PDA validation", async () => {
        console.log("\n✅ VERIFY: PDA Validation Fix (Anchor)\n");

        const idl = await Program.fetchIdl(PROGRAM_ID, provider);
        if (!idl) {
            throw new Error("IDL not found. Make sure the secure program is deployed.");
        }
        const program = new Program(idl, PROGRAM_ID, provider);

        // Create victim and attacker wallets
        const victim = Keypair.generate();
        const attacker = Keypair.generate();

        console.log("👤 Victim:", victim.publicKey.toBase58());
        console.log("🦹 Attacker:", attacker.publicKey.toBase58());

        // Airdrop SOL
        const airdropVictim = await provider.connection.requestAirdrop(
            victim.publicKey,
            2 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(airdropVictim);

        const airdropAttacker = await provider.connection.requestAirdrop(
            attacker.publicKey,
            1 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(airdropAttacker);

        // Derive vault PDAs
        const [victimVaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), victim.publicKey.toBuffer()],
            PROGRAM_ID
        );

        console.log("🏦 Victim's Vault PDA:", victimVaultPda.toBase58());

        // Step 1: Victim initializes their vault
        console.log("\n📝 Step 1: Victim initializes vault...");
        await program.methods
            .initialize()
            .accounts({
                user: victim.publicKey,
                vault: victimVaultPda,
                systemProgram: SystemProgram.programId,
            })
            .signers([victim])
            .rpc();

        console.log("✅ Victim's vault initialized");

        // Step 2: Victim deposits funds
        const depositAmount = 1 * LAMPORTS_PER_SOL;
        console.log(`\n💰 Step 2: Victim deposits ${depositAmount / LAMPORTS_PER_SOL} SOL...`);

        await program.methods
            .deposit(new anchor.BN(depositAmount))
            .accounts({
                user: victim.publicKey,
                vault: victimVaultPda,
                systemProgram: SystemProgram.programId,
            })
            .signers([victim])
            .rpc();

        const victimVaultBalance = await provider.connection.getBalance(victimVaultPda);
        console.log(`✅ Victim's vault balance: ${victimVaultBalance / LAMPORTS_PER_SOL} SOL`);

        // Step 3: Attacker attempts to withdraw from victim's vault (should FAIL)
        const withdrawAmount = 0.5 * LAMPORTS_PER_SOL;
        console.log(`\n🛡️  Step 3: Attacker attempts to withdraw ${withdrawAmount / LAMPORTS_PER_SOL} SOL from victim's vault...`);
        console.log("⚠️  Attacker signs but passes victim's vault!");

        const victimVaultBalanceBefore = await provider.connection.getBalance(victimVaultPda);

        try {
            // ✅ SECURE: PDA validation will prevent this
            await program.methods
                .withdraw(new anchor.BN(withdrawAmount))
                .accounts({
                    user: attacker.publicKey,      // Attacker signs
                    vault: victimVaultPda,         // Victim's vault
                })
                .signers([attacker])
                .rpc();

            // If we reach here, the fix didn't work
            console.log("\n❌ VERIFICATION FAILED!");
            console.log("⚠️  The secure version should have prevented this withdrawal!");
            throw new Error("Exploit succeeded when it should have been blocked");

        } catch (error) {
            // Expected to fail
            const victimVaultBalanceAfter = await provider.connection.getBalance(victimVaultPda);

            if (victimVaultBalanceAfter === victimVaultBalanceBefore) {
                console.log("\n✅ VERIFICATION SUCCESSFUL!");
                console.log("🛡️  Cross-user vault access was blocked");
                console.log(`🏦 Victim's vault balance unchanged: ${victimVaultBalanceAfter / LAMPORTS_PER_SOL} SOL`);
                console.log("\nError message:", error.message);
                console.log("\n✅ The fix properly validates PDA derivation!");
            } else {
                throw new Error("Vault balance changed unexpectedly");
            }
        }

        // Step 4: Verify victim can still withdraw from their own vault
        console.log("\n✅ Step 4: Verifying victim can withdraw from their own vault...");

        const legitimateWithdraw = 0.3 * LAMPORTS_PER_SOL;
        await program.methods
            .withdraw(new anchor.BN(legitimateWithdraw))
            .accounts({
                user: victim.publicKey,
                vault: victimVaultPda,
            })
            .signers([victim])
            .rpc();

        const finalVaultBalance = await provider.connection.getBalance(victimVaultPda);
        console.log(`✅ Legitimate withdrawal successful`);
        console.log(`🏦 Final vault balance: ${finalVaultBalance / LAMPORTS_PER_SOL} SOL`);
        console.log("\n🎉 The secure version works correctly!");
    });
});
