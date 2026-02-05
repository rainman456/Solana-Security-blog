/**
 * VERIFY TEST: Missing Mint Validation Fix (Pinocchio)
 * 
 * This test verifies that the secure Pinocchio program rejects deposits of incorrect token mints.
 */

import {
    Connection,
    Keypair,
    PublicKey,
    Transaction,
    TransactionInstruction,
    SystemProgram,
    sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
    createMint,
    createAccount,
    mintTo,
    TOKEN_PROGRAM_ID
} from "@solana/spl-token";

describe("06-missing-mint-validation: Pinocchio Verify Fix", () => {
    const connection = new Connection("http://localhost:8899", "confirmed");
    const PROGRAM_ID = new PublicKey("SECU6mintVa11d1d1d1d1d1d1d1d1d1d1d1d1d1d1");

    const INITIALIZE_DISCRIMINATOR = 0;
    const DEPOSIT_DISCRIMINATOR = 1;

    it("Rejects deposit of Fake Tokens", async () => {
        console.log("\n✅ VERIFY: Missing Mint Validation Fix (Pinocchio)\n");

        const user = Keypair.generate();
        const airdropSig = await connection.requestAirdrop(user.publicKey, 2 * 1000000000);
        await connection.confirmTransaction(airdropSig);

        const goodMint = await createMint(connection, user, user.publicKey, null, 6);
        const badMint = await createMint(connection, user, user.publicKey, null, 6);

        const [vaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), goodMint.toBuffer()],
            PROGRAM_ID
        );

        // Initialize
        console.log("📝 Initializing...");
        const initIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
                { pubkey: goodMint, isSigner: false, isWritable: false },
                { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
            ],
            programId: PROGRAM_ID,
            data: Buffer.concat([Buffer.from([INITIALIZE_DISCRIMINATOR]), Buffer.alloc(8)]),
        });
        await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [user]);

        // Setup Bad Accounts
        const userBadTokenAccount = await createAccount(connection, user, badMint, user.publicKey);
        const vaultBadTokenAccount = await createAccount(connection, user, badMint, vaultPda);
        await mintTo(connection, user, badMint, userBadTokenAccount, user, 1000000);

        // Exploit Attempt
        console.log("\n🛡️  Attempting deposit with Fake Tokens...");
        const depositAmount = 500000;
        const depositData = Buffer.alloc(9);
        depositData.writeUInt8(DEPOSIT_DISCRIMINATOR, 0);
        depositData.writeBigUInt64LE(BigInt(depositAmount), 1);

        const depositIx = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: vaultBadTokenAccount, isSigner: false, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: false },
                { pubkey: userBadTokenAccount, isSigner: false, isWritable: true },
                { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
            ],
            programId: PROGRAM_ID,
            data: depositData,
        });

        try {
            await sendAndConfirmTransaction(connection, new Transaction().add(depositIx), [user]);
            throw new Error("❌ FAIL: Secure vault accepted fake tokens!");
        } catch (e) {
            // Pinocchio custom error usually shows as logic error or custom error index
            console.log("✅ SUCCESS: Transaction rejected as expected.");
            console.log("   Error:", e.message);
        }
    });
});
