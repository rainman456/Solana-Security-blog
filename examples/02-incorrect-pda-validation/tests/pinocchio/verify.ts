/**
 * VERIFY TEST: PDA Validation Fix (Pinocchio)
 * 
 * This test verifies that the secure Pinocchio program properly validates PDA derivation,
 * preventing unauthorized access to other users' vaults.
 * 
 * Fix: The withdraw function includes PDA validation that checks if the provided vault
 * matches the PDA derived from the user's public key. If not, it returns InvalidSeeds error.
 * 
 * Expected Result: The exploit should FAIL with InvalidSeeds error.
 */

import {
    Connection,
    Keypair,
    PublicKey,
    SystemProgram,
    Transaction,
    TransactionInstruction,
    LAMPORTS_PER_SOL,
    sendAndConfirmTransaction,
} from "@solana/web3.js";

describe("02-incorrect-pda-validation: Pinocchio Verify Fix", () => {
    const connection = new Connection("http://localhost:8899", "confirmed");
    const PROGRAM_ID = new PublicKey("HmbTLCmaGvZhKnn1Zfa1JVnp7vkMV4DYVxPLWBVoN65L");

    // Instruction discriminators
    const INITIALIZE_DISCRIMINATOR = 0;
    const DEPOSIT_DISCRIMINATOR = 1;
    const WITHDRAW_DISCRIMINATOR = 2;

    it("Prevents cross-user vault access with proper PDA validation", async () => {
        console.log("\n✅ VERIFY: PDA Validation Fix (Pinocchio)\n");

        // Create victim and attacker wallets
        const victim = Keypair.generate();
        const attacker = Keypair.generate();

        console.log("👤 Victim:", victim.publicKey.toBase58());
        console.log("🦹 Attacker:", attacker.publicKey.toBase58());

        // Airdrop SOL
        const airdropVictim = await connection.requestAirdrop(
            victim.publicKey,
            2 * LAMPORTS_PER_SOL
        );
        await connection.confirmTransaction(airdropVictim);

        const airdropAttacker = await connection.requestAirdrop(
            attacker.publicKey,
            1 * LAMPORTS_PER_SOL
        );
        await connection.confirmTransaction(airdropAttacker);

        // Derive vault PDAs
        const [victimVaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), victim.publicKey.toBuffer()],
            PROGRAM_ID
        );

        console.log("🏦 Victim's Vault PDA:", victimVaultPda.toBase58());

        // Step 1: Victim initializes their vault
        console.log("\n📝 Step 1: Victim initializes vault...");

        const initializeIx = new TransactionInstruction({
            keys: [
                { pubkey: victim.publicKey, isSigner: true, isWritable: true },
                { pubkey: victimVaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([INITIALIZE_DISCRIMINATOR]),
        });

        const initTx = new Transaction().add(initializeIx);
        await sendAndConfirmTransaction(connection, initTx, [victim]);
        console.log("✅ Victim's vault initialized");

        // Step 2: Victim deposits funds
        const depositAmount = 1 * LAMPORTS_PER_SOL;
        console.log(`\n💰 Step 2: Victim deposits ${depositAmount / LAMPORTS_PER_SOL} SOL...`);

        const depositData = Buffer.alloc(9);
        depositData.writeUInt8(DEPOSIT_DISCRIMINATOR, 0);
        depositData.writeBigUInt64LE(BigInt(depositAmount), 1);

        const depositIx = new TransactionInstruction({
            keys: [
                { pubkey: victim.publicKey, isSigner: true, isWritable: true },
                { pubkey: victimVaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: depositData,
        });

        const depositTx = new Transaction().add(depositIx);
        await sendAndConfirmTransaction(connection, depositTx, [victim]);

        const victimVaultBalance = await connection.getBalance(victimVaultPda);
        console.log(`✅ Victim's vault balance: ${victimVaultBalance / LAMPORTS_PER_SOL} SOL`);

        // Step 3: Attacker attempts to withdraw from victim's vault (should FAIL)
        const withdrawAmount = 0.5 * LAMPORTS_PER_SOL;
        console.log(`\n🛡️  Step 3: Attacker attempts to withdraw ${withdrawAmount / LAMPORTS_PER_SOL} SOL from victim's vault...`);
        console.log("⚠️  Attacker signs but passes victim's vault!");

        const victimVaultBalanceBefore = await connection.getBalance(victimVaultPda);

        try {
            const withdrawData = Buffer.alloc(9);
            withdrawData.writeUInt8(WITHDRAW_DISCRIMINATOR, 0);
            withdrawData.writeBigUInt64LE(BigInt(withdrawAmount), 1);

            // ✅ SECURE: PDA validation will prevent this
            const withdrawIx = new TransactionInstruction({
                keys: [
                    { pubkey: attacker.publicKey, isSigner: true, isWritable: true },  // Attacker signs
                    { pubkey: victimVaultPda, isSigner: false, isWritable: true },     // Victim's vault
                ],
                programId: PROGRAM_ID,
                data: withdrawData,
            });

            const withdrawTx = new Transaction().add(withdrawIx);
            await sendAndConfirmTransaction(connection, withdrawTx, [attacker]);

            // If we reach here, the fix didn't work
            console.log("\n❌ VERIFICATION FAILED!");
            console.log("⚠️  The secure version should have prevented this withdrawal!");
            throw new Error("Exploit succeeded when it should have been blocked");

        } catch (error) {
            // Expected to fail
            const victimVaultBalanceAfter = await connection.getBalance(victimVaultPda);

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
        const legitWithdrawData = Buffer.alloc(9);
        legitWithdrawData.writeUInt8(WITHDRAW_DISCRIMINATOR, 0);
        legitWithdrawData.writeBigUInt64LE(BigInt(legitimateWithdraw), 1);

        const legitWithdrawIx = new TransactionInstruction({
            keys: [
                { pubkey: victim.publicKey, isSigner: true, isWritable: true },     // ✅ Victim signs
                { pubkey: victimVaultPda, isSigner: false, isWritable: true },      // ✅ Their own vault
            ],
            programId: PROGRAM_ID,
            data: legitWithdrawData,
        });

        const legitWithdrawTx = new Transaction().add(legitWithdrawIx);
        await sendAndConfirmTransaction(connection, legitWithdrawTx, [victim]);

        const finalVaultBalance = await connection.getBalance(victimVaultPda);
        console.log(`✅ Legitimate withdrawal successful`);
        console.log(`🏦 Final vault balance: ${finalVaultBalance / LAMPORTS_PER_SOL} SOL`);
        console.log("\n🎉 The secure version works correctly!");
    });
});
