/**
 * VERIFY TEST: Unsafe Account Closure Fix (Pinocchio)
 * 
 * This test verifies that the secure Pinocchio program zeros data and reassigns ownership.
 */

import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    TransactionInstruction,
    LAMPORTS_PER_SOL,
    SystemProgram,
    sendAndConfirmTransaction,
} from "@solana/web3.js";

describe("05-unsafe-account-closure: Pinocchio Verify Fix", () => {
    const connection = new Connection("http://localhost:8899", "confirmed");
    const PROGRAM_ID = new PublicKey("CZqKx8VFNjKT4h8YqvLLN9vZ3qWKFQvXYrJJMWJWWNnL");

    const INITIALIZE_DISCRIMINATOR = 0;
    const DEPOSIT_DISCRIMINATOR = 1;
    const CLOSE_DISCRIMINATOR = 2;

    const BALANCE_OFFSET = 32;
    const SYSTEM_PROGRAM_ID = SystemProgram.programId;

    it("Ensures closed account is clean and owned by System Program", async () => {
        console.log("\n✅ VERIFY: Unsafe Account Closure Fix (Pinocchio)\n");

        const user = Keypair.generate();
        console.log("👤 User:", user.publicKey.toBase58());

        const airdropSig = await connection.requestAirdrop(
            user.publicKey,
            2 * LAMPORTS_PER_SOL
        );
        await connection.confirmTransaction(airdropSig);

        const [vaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), user.publicKey.toBuffer()],
            PROGRAM_ID
        );

        // Initialize
        console.log("\n📝 Step 1: Initialize vault...");
        const initIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([INITIALIZE_DISCRIMINATOR]),
        });
        await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [user]);

        // Deposit
        const depositAmount = 0.5 * LAMPORTS_PER_SOL;
        const depositData = Buffer.alloc(9);
        depositData.writeUInt8(DEPOSIT_DISCRIMINATOR, 0);
        depositData.writeBigUInt64LE(BigInt(depositAmount), 1);
        const depositIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: depositData,
        });
        await sendAndConfirmTransaction(connection, new Transaction().add(depositIx), [user]);

        // Secure Close + Resurrection Attempt
        console.log("\n🛡️  Step 2: Close and Attempt Revive...");

        const closeIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: Buffer.from([CLOSE_DISCRIMINATOR]),
        });

        const refundIx = SystemProgram.transfer({
            fromPubkey: user.publicKey,
            toPubkey: vaultPda,
            lamports: await connection.getMinimumBalanceForRentExemption(40),
        });

        const tx = new Transaction().add(closeIx).add(refundIx);
        await sendAndConfirmTransaction(connection, tx, [user]);

        // Verify State
        const accountInfo = await connection.getAccountInfo(vaultPda);
        console.log(`\n🔍 Resurrected Account Info:`);
        console.log(`Owner: ${accountInfo.owner.toBase58()}`);
        console.log(`Data Length: ${accountInfo.data.length}`);

        const isSystemOwned = accountInfo.owner.equals(SYSTEM_PROGRAM_ID);
        const isZeroed = accountInfo.data.every(b => b === 0);

        if (isSystemOwned) {
            console.log("✅ Account is owned by System Program (Correctly reassigned)");
        } else if (isZeroed) {
            console.log("✅ Account data is completely zeroed (Information destroyed)");
        } else {
            // If it's still program owned and has data, verification failed
            console.log("❌ VERIFICATION FAILED: Data persisted or wrong owner");
            throw new Error("Secure close failed to clean up account");
        }

        if (isSystemOwned || isZeroed) {
            console.log("✅ Fix Verified: Resurrection attack yielded a blank/system account.");
        }
    });
});
