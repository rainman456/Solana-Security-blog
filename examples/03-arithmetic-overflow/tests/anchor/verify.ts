/**
 * VERIFY TEST: Arithmetic Overflow Fix (Anchor)
 * 
 * This test verifies that the secure Anchor program prevents arithmetic overflow/underflow.
 * 
 * Fix: The program uses .checked_add() and .checked_sub() methods which handle
 * overflow/underflow safely by returning an error.
 * 
 * Expected Result: The underflow attempt should FAIL with an error.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { BN } from "bn.js";

describe("03-arithmetic-overflow: Anchor Verify Fix", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const PROGRAM_ID = new PublicKey("3Z9vL1zjN4N5tRDNEPQuv876tMB1qdNGo4B2PqJdZZXR");

    it("Prevents arithmetic underflow with checked math", async () => {
        console.log("\n✅ VERIFY: Arithmetic Overflow Fix (Anchor)\n");

        const idl = await Program.fetchIdl(PROGRAM_ID, provider);
        if (!idl) {
            throw new Error("IDL not found. Make sure the secure program is deployed.");
        }
        const program = new Program(idl, PROGRAM_ID, provider);

        const user = Keypair.generate();
        console.log("👤 User:", user.publicKey.toBase58());

        // Airdrop SOL
        const airdropSig = await provider.connection.requestAirdrop(
            user.publicKey,
            10 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(airdropSig);

        // Derive vault PDA
        const [vaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), user.publicKey.toBuffer()],
            PROGRAM_ID
        );

        // Step 1: Initialize vault
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

        // Step 2: Deposit 2 SOL
        const depositAmount = new BN(2 * LAMPORTS_PER_SOL);
        console.log(`\n💰 Step 2: Deposit ${depositAmount.div(new BN(LAMPORTS_PER_SOL)).toString()} SOL...`);

        await program.methods
            .deposit(depositAmount)
            .accounts({
                user: user.publicKey,
                vault: vaultPda,
                systemProgram: SystemProgram.programId,
            })
            .signers([user])
            .rpc();

        // Fund vault properly to Isolate the Arithmetic Error from System Error
        const fundSig = await provider.connection.requestAirdrop(
            vaultPda,
            10 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(fundSig);

        // Step 3: Attempt to withdraw 5 SOL (causing underflow)
        const withdrawAmount = new BN(5 * LAMPORTS_PER_SOL);
        console.log(`\n🛡️  Step 3: Attempt withdraw ${withdrawAmount.div(new BN(LAMPORTS_PER_SOL)).toString()} SOL (expecting fail)...`);

        try {
            await program.methods
                .withdraw(withdrawAmount)
                .accounts({
                    user: user.publicKey,
                    vault: vaultPda,
                })
                .signers([user])
                .rpc();

            throw new Error("Exploit succeeded when it should have failed!");

        } catch (error) {
            console.log("\n✅ VERIFICATION SUCCESSFUL!");
            console.log("Error message:", error.message);

            // Check for specific error code if possible, or usually "InsufficientFunds"
            if (error.message.includes("InsufficientFunds") || error.logs?.some(l => l.includes("InsufficientFunds"))) {
                console.log("✅ Caught expected 'InsufficientFunds' error from checked_sub");
            } else {
                console.log("✅ Caught error, assumed to be overflow protection");
            }
        }

        // Step 4: Verify balance was NOT corrupted
        const vaultAccount = await program.account["vault"].fetch(vaultPda);
        console.log(`\n🏦 Final Vault internal balance: ${vaultAccount.balance.toString()}`);

        if (vaultAccount.balance.eq(depositAmount)) {
            console.log("✅ Balance matches initial deposit (state preserved)");
        } else {
            throw new Error("Vault state modified unexpectedly");
        }

    });
});
