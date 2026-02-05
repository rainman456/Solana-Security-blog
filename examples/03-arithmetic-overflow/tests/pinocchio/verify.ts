/**
 * VERIFY TEST: Arithmetic Overflow Fix (Pinocchio)
 * 
 * This test verifies that the secure Pinocchio program prevents arithmetic overflow/underflow.
 * 
 * Fix: The program uses checked arithmetic and returns explicit errors.
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

describe("03-arithmetic-overflow: Pinocchio Verify Fix", () => {
    const connection = new Connection("http://localhost:8899", "confirmed");
    const PROGRAM_ID = new PublicKey("3Z9vL1zjN4N5tRDNEPQuv876tMB1qdNGo4B2PqJdZZXR");

    const INITIALIZE_DISCRIMINATOR = 0;
    const DEPOSIT_DISCRIMINATOR = 1;
    const WITHDRAW_DISCRIMINATOR = 2;
    const BALANCE_OFFSET = 32;

    it("Prevents arithmetic underflow with checked math", async () => {
        console.log("\n✅ VERIFY: Arithmetic Overflow Fix (Pinocchio)\n");

        const user = Keypair.generate();
        console.log("👤 User:", user.publicKey.toBase58());

        const airdropSig = await connection.requestAirdrop(
            user.publicKey,
            10 * LAMPORTS_PER_SOL
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

        // Step 2: Deposit 2 SOL
        const depositLambda = 2 * LAMPORTS_PER_SOL;
        console.log(`\n💰 Step 2: Deposit 2 SOL...`);
        const depositData = Buffer.alloc(9);
        depositData.writeUInt8(DEPOSIT_DISCRIMINATOR, 0);
        depositData.writeBigUInt64LE(BigInt(depositLambda), 1);

        const depositIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: depositData,
        });
        await sendAndConfirmTransaction(connection, new Transaction().add(depositIx), [user]);

        // Fund vault manually
        const fundSig = await connection.requestAirdrop(
            vaultPda,
            10 * LAMPORTS_PER_SOL
        );
        await connection.confirmTransaction(fundSig);

        // Step 3: Withdraw 5 SOL (Underflow attempt)
        const withdrawLambda = 5 * LAMPORTS_PER_SOL;
        console.log(`\n🛡️  Step 3: Withdraw 5 SOL (expecting fail)...`);

        const withdrawData = Buffer.alloc(9);
        withdrawData.writeUInt8(WITHDRAW_DISCRIMINATOR, 0);
        withdrawData.writeBigUInt64LE(BigInt(withdrawLambda), 1);

        const withdrawIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: withdrawData,
        });

        try {
            await sendAndConfirmTransaction(connection, new Transaction().add(withdrawIx), [user]);
            throw new Error("Exploit succeeded when it should have failed!");
        } catch (error) {
            console.log("\n✅ VERIFICATION SUCCESSFUL!");
            console.log("Error message:", error.message);
            console.log("✅ Transaction failed as expected due to checked math");
        }

        // Verify state
        const accountInfo = await connection.getAccountInfo(vaultPda);
        const balance = accountInfo.data.readBigUInt64LE(BALANCE_OFFSET);
        console.log(`\n🏦 Final Vault internal balance: ${balance}`);

        if (balance === BigInt(depositLambda)) {
            console.log("✅ Balance matches initial deposit (state preserved)");
        } else {
            throw new Error("Vault state modified unexpectedly");
        }
    });
});
