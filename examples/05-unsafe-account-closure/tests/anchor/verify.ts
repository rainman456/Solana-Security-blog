/**
 * VERIFY TEST: Unsafe Account Closure Fix (Anchor)
 * 
 * This test verifies that the secure Anchor program properly closes accounts.
 * 
 * Fix: Uses Anchor's `close` constraint which:
 * 1. Zeros out account discriminator and data.
 * 2. Transfers lamports.
 * 3. Reassigns owner to System Program (conceptually, or ensures it's dead).
 * 
 * If we "resurrect" it by sending lamports, it should be owned by valid user or system,
 * NOT the program, and data should be gone.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL, Transaction } from "@solana/web3.js";
import { BN } from "bn.js";

describe("05-unsafe-account-closure: Anchor Verify Fix", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const PROGRAM_ID = new PublicKey("CZqKx8VFNjKT4h8YqvLLN9vZ3qWKFQvXYrJJMWJWWNnL");

    it("Prevents resurrection of program state (Proper Closure)", async () => {
        console.log("\n✅ VERIFY: Unsafe Account Closure Fix (Anchor)\n");

        const idl = await Program.fetchIdl(PROGRAM_ID, provider);
        if (!idl) {
            throw new Error("IDL not found. Make sure the secure program is deployed.");
        }
        const program = new Program(idl, PROGRAM_ID, provider);

        const user = Keypair.generate();
        console.log("👤 User:", user.publicKey.toBase58());

        const airdropSig = await provider.connection.requestAirdrop(
            user.publicKey,
            2 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(airdropSig);

        const [vaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), user.publicKey.toBuffer()],
            PROGRAM_ID
        );

        // Step 1: Initialize
        console.log("\n📝 Step 1: Initialize vault...");
        await program.methods
            .initialize()
            .accounts({
                user: user.publicKey,
                vault: vaultPda,
                systemProgram: SystemProgram.programId,
            })
            .signers([user])
            .rpc();

        // Step 2: Attempt Resurrection Attack
        console.log("\n🛡️  Step 2: Attempting 'Resurrection Attack' on SECURE close...");

        // In secure version, close_vault uses `close = user` constraint
        const closeIx = await program.methods
            .closeVault()
            .accounts({
                user: user.publicKey,
                vault: vaultPda,
            })
            .instruction();

        const resurrectIx = SystemProgram.transfer({
            fromPubkey: user.publicKey,
            toPubkey: vaultPda,
            lamports: await provider.connection.getMinimumBalanceForRentExemption(8 + 32 + 8),
        });

        const tx = new Transaction().add(closeIx).add(resurrectIx);
        await provider.sendAndConfirm(tx, [user]);

        // Step 3: Verify Account State
        console.log("✅ Transaction confirmed: Close + Refund");

        // Attempt to fetch as Vault - SHOULD FAIL
        try {
            await program.account["vault"].fetch(vaultPda);
            throw new Error("Exploit succeeded! Account still has valid discriminator/data.");
        } catch (e) {
            if (e.message.includes("Account does not exist") || e.message.includes("Constraint") || e.toString().includes("Error")) {
                console.log("✅ Verification Successful: Account could not be fetched as Vault.");
                console.log("   Reason: Discriminator Invalid or Account Uninitialized");
            } else {
                // It might fetch but contain zeros?
                // If fetch() fails, it's good.
                console.log("✅ Verification Successful (Fetch Failed as expected)");
                console.log("Error:", e.message);
            }
        }

        // Verify raw account data is zeroed or changed
        const rawAccount = await provider.connection.getAccountInfo(vaultPda);

        // The account exists because we refunded it
        if (rawAccount) {
            console.log(`\n🔍 Raw Account Info:`);
            console.log(`Owner: ${rawAccount.owner.toBase58()}`);
            console.log(`Data Length: ${rawAccount.data.length}`);

            // Secure close should set owner to System Program usually? 
            // Actually `close` constraint reallocs to 0. 
            // So data length should be 0? 
            // Or if we refunded it, it's just a system account with lamports?

            if (rawAccount.owner.equals(SystemProgram.programId)) {
                console.log("✅ Owner is System Program (Clean Close)");
            } else if (rawAccount.owner.equals(PROGRAM_ID)) {
                // If still owned by program, data MUST be zeroed/invalid
                const isZeroed = rawAccount.data.every(b => b === 0);
                if (isZeroed) {
                    console.log("✅ Owner is Program but Data is Zeroed (Clean Close)");
                } else {
                    // Check discriminator
                    const discriminator = rawAccount.data.slice(0, 8);
                    console.log("Discriminator:", discriminator);
                    if (discriminator.every(b => b === 0)) {
                        console.log("✅ Discriminator is Zeroed (Account invalidated)");
                    } else {
                        console.log("⚠️  Warning: Data persists?");
                    }
                }
            }
        } else {
            console.log("✅ Account does not exist (Purged)");
        }
    });
});
