/**
 * VERIFY TEST: Missing Signer Check Fix (Anchor)
 * 
 * This test verifies that the secure version properly prevents unauthorized withdrawals
 * by enforcing signer checks.
 * 
 * Fix: The withdraw instruction uses Signer<'info> instead of AccountInfo<'info>,
 * and includes a constraint to verify the vault owner matches the signer.
 * 
 * Expected Result: The exploit should FAIL with a signature verification error.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";

describe("01-missing-signer-check: Anchor Verify Fix", () => {
    // Configure the client to use the local cluster
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const PROGRAM_ID = new PublicKey("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

    it("Prevents unauthorized withdrawal with proper signer check", async () => {
        console.log("\n✅ VERIFY: Signer Check Fix (Anchor)\n");

        // Load the secure program
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

        // Airdrop SOL to victim and attacker
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

        // Derive vault PDA for victim
        const [vaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), victim.publicKey.toBuffer()],
            PROGRAM_ID
        );

        console.log("🏦 Vault PDA:", vaultPda.toBase58());

        // Step 1: Victim initializes their vault
        console.log("\n📝 Step 1: Victim initializes vault...");
        await program.methods
            .initialize()
            .accounts({
                user: victim.publicKey,
                vault: vaultPda,
                systemProgram: SystemProgram.programId,
            })
            .signers([victim])
            .rpc();

        console.log("✅ Vault initialized");

        // Step 2: Victim deposits funds
        const depositAmount = 1 * LAMPORTS_PER_SOL;
        console.log(`\n💰 Step 2: Victim deposits ${depositAmount / LAMPORTS_PER_SOL} SOL...`);

        await program.methods
            .deposit(new anchor.BN(depositAmount))
            .accounts({
                user: victim.publicKey,
                vault: vaultPda,
                systemProgram: SystemProgram.programId,
            })
            .signers([victim])
            .rpc();

        const vaultBalanceAfterDeposit = await provider.connection.getBalance(vaultPda);
        console.log(`✅ Vault balance: ${vaultBalanceAfterDeposit / LAMPORTS_PER_SOL} SOL`);

        // Step 3: Attacker attempts to withdraw (should FAIL)
        const withdrawAmount = 0.5 * LAMPORTS_PER_SOL;
        console.log(`\n🛡️  Step 3: Attacker attempts to withdraw ${withdrawAmount / LAMPORTS_PER_SOL} SOL...`);
        console.log("⚠️  Using victim's public key but attacker's signature!");

        const vaultBalanceBefore = await provider.connection.getBalance(vaultPda);

        try {
            // ✅ SECURE: The program requires 'user' to be a Signer
            // This should fail because the attacker cannot sign for the victim
            await program.methods
                .withdraw(new anchor.BN(withdrawAmount))
                .accounts({
                    user: victim.publicKey, // Victim's key
                    vault: vaultPda,
                })
                .signers([attacker]) // Attacker's signature (won't work)
                .rpc();

            // If we reach here, the fix didn't work
            console.log("\n❌ VERIFICATION FAILED!");
            console.log("⚠️  The secure version should have prevented this withdrawal!");
            throw new Error("Exploit succeeded when it should have been blocked");

        } catch (error) {
            // Expected to fail
            const vaultBalanceAfter = await provider.connection.getBalance(vaultPda);

            if (vaultBalanceAfter === vaultBalanceBefore) {
                console.log("\n✅ VERIFICATION SUCCESSFUL!");
                console.log("🛡️  Unauthorized withdrawal was blocked");
                console.log(`🏦 Vault balance unchanged: ${vaultBalanceAfter / LAMPORTS_PER_SOL} SOL`);
                console.log("\nError message:", error.message);
                console.log("\n✅ The fix properly prevents unauthorized access!");
            } else {
                throw new Error("Vault balance changed unexpectedly");
            }
        }

        // Step 4: Verify legitimate withdrawal still works
        console.log("\n✅ Step 4: Verifying legitimate withdrawal works...");

        const legitimateWithdraw = 0.3 * LAMPORTS_PER_SOL;
        await program.methods
            .withdraw(new anchor.BN(legitimateWithdraw))
            .accounts({
                user: victim.publicKey,
                vault: vaultPda,
            })
            .signers([victim]) // Victim signs their own transaction
            .rpc();

        const finalVaultBalance = await provider.connection.getBalance(vaultPda);
        console.log(`✅ Legitimate withdrawal successful`);
        console.log(`🏦 Final vault balance: ${finalVaultBalance / LAMPORTS_PER_SOL} SOL`);
        console.log("\n🎉 The secure version works correctly!");
    });
});
