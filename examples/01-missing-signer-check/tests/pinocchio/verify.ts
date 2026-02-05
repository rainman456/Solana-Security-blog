/**
 * VERIFY TEST: Missing Signer Check Fix (Pinocchio)
 * 
 * This test verifies that the secure Pinocchio program properly prevents unauthorized
 * withdrawals by checking if the user account is a signer.
 * 
 * Fix: The withdraw function includes `if !user.is_signer()` check before processing,
 * returning ProgramError::MissingRequiredSignature if the check fails.
 * 
 * Expected Result: The exploit should FAIL with a signature verification error.
 * 
 * Note: Pinocchio programs don't have IDLs, so we manually construct transactions
 * with instruction discriminators and serialized data.
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

describe("01-missing-signer-check: Pinocchio Verify Fix", () => {
    const connection = new Connection("http://localhost:8899", "confirmed");

    // This should match the program ID in the secure Pinocchio program
    const PROGRAM_ID = new PublicKey("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

    // Instruction discriminators (from the Pinocchio program)
    const INITIALIZE_DISCRIMINATOR = 0;
    const DEPOSIT_DISCRIMINATOR = 1;
    const WITHDRAW_DISCRIMINATOR = 2;

    it("Prevents unauthorized withdrawal with proper signer check", async () => {
        console.log("\n✅ VERIFY: Signer Check Fix (Pinocchio)\n");

        // Create victim and attacker wallets
        const victim = Keypair.generate();
        const attacker = Keypair.generate();

        console.log("👤 Victim:", victim.publicKey.toBase58());
        console.log("🦹 Attacker:", attacker.publicKey.toBase58());

        // Airdrop SOL to victim and attacker
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

        // Derive vault PDA for victim
        const [vaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), victim.publicKey.toBuffer()],
            PROGRAM_ID
        );

        console.log("🏦 Vault PDA:", vaultPda.toBase58());

        // Step 1: Victim initializes their vault
        console.log("\n📝 Step 1: Victim initializes vault...");

        const initializeIx = new TransactionInstruction({
            keys: [
                { pubkey: victim.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([INITIALIZE_DISCRIMINATOR]),
        });

        const initTx = new Transaction().add(initializeIx);
        await sendAndConfirmTransaction(connection, initTx, [victim]);
        console.log("✅ Vault initialized");

        // Step 2: Victim deposits funds
        const depositAmount = 1 * LAMPORTS_PER_SOL;
        console.log(`\n💰 Step 2: Victim deposits ${depositAmount / LAMPORTS_PER_SOL} SOL...`);

        const depositData = Buffer.alloc(9);
        depositData.writeUInt8(DEPOSIT_DISCRIMINATOR, 0);
        depositData.writeBigUInt64LE(BigInt(depositAmount), 1);

        const depositIx = new TransactionInstruction({
            keys: [
                { pubkey: victim.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: depositData,
        });

        const depositTx = new Transaction().add(depositIx);
        await sendAndConfirmTransaction(connection, depositTx, [victim]);

        const vaultBalanceAfterDeposit = await connection.getBalance(vaultPda);
        console.log(`✅ Vault balance: ${vaultBalanceAfterDeposit / LAMPORTS_PER_SOL} SOL`);

        // Step 3: Attacker attempts to withdraw (should FAIL)
        const withdrawAmount = 0.5 * LAMPORTS_PER_SOL;
        console.log(`\n🛡️  Step 3: Attacker attempts to withdraw ${withdrawAmount / LAMPORTS_PER_SOL} SOL...`);
        console.log("⚠️  Using victim's public key but attacker's signature!");

        const vaultBalanceBefore = await connection.getBalance(vaultPda);

        try {
            const withdrawData = Buffer.alloc(9);
            withdrawData.writeUInt8(WITHDRAW_DISCRIMINATOR, 0);
            withdrawData.writeBigUInt64LE(BigInt(withdrawAmount), 1);

            // ✅ SECURE: The program checks if user is a signer
            const withdrawIx = new TransactionInstruction({
                keys: [
                    { pubkey: victim.publicKey, isSigner: false, isWritable: true }, // Not marked as signer
                    { pubkey: vaultPda, isSigner: false, isWritable: true },
                ],
                programId: PROGRAM_ID,
                data: withdrawData,
            });

            const withdrawTx = new Transaction().add(withdrawIx);
            await sendAndConfirmTransaction(connection, withdrawTx, [attacker]); // Attacker signs

            // If we reach here, the fix didn't work
            console.log("\n❌ VERIFICATION FAILED!");
            console.log("⚠️  The secure version should have prevented this withdrawal!");
            throw new Error("Exploit succeeded when it should have been blocked");

        } catch (error) {
            // Expected to fail
            const vaultBalanceAfter = await connection.getBalance(vaultPda);

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
        const legitWithdrawData = Buffer.alloc(9);
        legitWithdrawData.writeUInt8(WITHDRAW_DISCRIMINATOR, 0);
        legitWithdrawData.writeBigUInt64LE(BigInt(legitimateWithdraw), 1);

        const legitWithdrawIx = new TransactionInstruction({
            keys: [
                { pubkey: victim.publicKey, isSigner: true, isWritable: true }, // ✅ Victim signs
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: legitWithdrawData,
        });

        const legitWithdrawTx = new Transaction().add(legitWithdrawIx);
        await sendAndConfirmTransaction(connection, legitWithdrawTx, [victim]); // Victim signs their own transaction

        const finalVaultBalance = await connection.getBalance(vaultPda);
        console.log(`✅ Legitimate withdrawal successful`);
        console.log(`🏦 Final vault balance: ${finalVaultBalance / LAMPORTS_PER_SOL} SOL`);
        console.log("\n🎉 The secure version works correctly!");
    });
});
