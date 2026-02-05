/**
 * VERIFY TEST: Reentrancy Risk Fix (Pinocchio)
 * 
 * This test verifies that the secure Pinocchio program functions correctly.
 * 
 * Fix: Updates state before interacting with external programs.
 */

import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    TransactionInstruction,
    LAMPORTS_PER_SOL,
    sendAndConfirmTransaction,
} from "@solana/web3.js";

describe("04-reentrancy-risk: Pinocchio Verify Fix", () => {
    const connection = new Connection("http://localhost:8899", "confirmed");
    const PROGRAM_ID = new PublicKey("9vK8vvwYXN2vVrxKPPzVqWKFQvXYrJJMWJWWNnLqFqBZ");

    const INITIALIZE_DISCRIMINATOR = 0;
    const DEPOSIT_DISCRIMINATOR = 1;
    const WITHDRAW_DISCRIMINATOR = 2;
    const BALANCE_OFFSET = 32;

    it("Executes the secure withdraw function", async () => {
        console.log("\n✅ VERIFY: Reentrancy Risk Fix (Pinocchio)\n");

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

        // Step 1: Initialize
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

        // Step 2: Deposit 1 SOL
        const depositAmount = 1 * LAMPORTS_PER_SOL;
        console.log(`\n💰 Step 2: Deposit 1 SOL...`);
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

        // Step 3: Withdraw 0.5 SOL
        const withdrawAmount = 0.5 * LAMPORTS_PER_SOL;
        console.log(`\n🛡️  Step 3: Withdraw 0.5 SOL...`);

        const withdrawData = Buffer.alloc(9);
        withdrawData.writeUInt8(WITHDRAW_DISCRIMINATOR, 0);
        withdrawData.writeBigUInt64LE(BigInt(withdrawAmount), 1);

        const withdrawIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: withdrawData,
        });
        await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [user]);

        // Verify balance
        const accountInfo = await connection.getAccountInfo(vaultPda);
        const balance = accountInfo.data.readBigUInt64LE(BALANCE_OFFSET);
        console.log(`\n✅ Withdrawal successful`);
        console.log(`🏦 Final Vault internal balance: ${balance}`);

        if (balance === BigInt(depositAmount) - BigInt(withdrawAmount)) {
            console.log("✅ State correctly maintained.");
        } else {
            throw new Error("State update incorrect");
        }
    });
});
