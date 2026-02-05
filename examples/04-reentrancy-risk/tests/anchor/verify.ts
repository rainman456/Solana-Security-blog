/**
 * VERIFY TEST: Reentrancy Risk Fix (Anchor)
 * 
 * This test verifies that the secure Anchor program functions correctly with the fix.
 * 
 * Fix: The secure program updates the state (balance) BEFORE performing the CPI (Transfer).
 * This "Checks-Effects-Interactions" pattern prevents reentrancy attacks because
 * the balance is already effectively lowered before the external code runs.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { BN } from "bn.js";

describe("04-reentrancy-risk: Anchor Verify Fix", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const PROGRAM_ID = new PublicKey("9vK8vvwYXN2vVrxKPPzVqWKFQvXYrJJMWJWWNnLqFqBZ");

    it("Executes the secure withdraw function (Checks-Effects-Interactions)", async () => {
        console.log("\n✅ VERIFY: Reentrancy Risk Fix (Anchor)\n");

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
            2 * LAMPORTS_PER_SOL
        );
        await provider.connection.confirmTransaction(airdropSig);

        // Derive vault PDA
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

        // Step 2: Deposit 1 SOL
        const depositAmount = new BN(1 * LAMPORTS_PER_SOL);
        console.log(`\n💰 Step 2: Deposit 1 SOL...`);
        await program.methods
            .deposit(depositAmount)
            .accounts({
                user: user.publicKey,
                vault: vaultPda,
                systemProgram: SystemProgram.programId,
            })
            .signers([user])
            .rpc();

        // Step 3: Withdraw 0.5 SOL
        const withdrawAmount = new BN(0.5 * LAMPORTS_PER_SOL);
        console.log(`\n🛡️  Step 3: Withdraw 0.5 SOL...`);
        console.log("✅ Secure Pattern: State updated BEFORE transfer.");

        await program.methods
            .withdraw(withdrawAmount)
            .accounts({
                user: user.publicKey,
                vault: vaultPda,
            })
            .signers([user])
            .rpc();

        const vaultAccount = await program.account["vault"].fetch(vaultPda);
        console.log(`\n✅ Withdrawal successful`);
        console.log(`🏦 Final Vault internal balance: ${vaultAccount.balance.toString()}`);

        const expectedBalance = new BN(0.5 * LAMPORTS_PER_SOL);
        if (vaultAccount.balance.eq(expectedBalance)) {
            console.log("✅ State correctly updated.");
        } else {
            throw new Error("State update incorrect");
        }
    });
});
