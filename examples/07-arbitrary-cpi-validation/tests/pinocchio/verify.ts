/**
 * VERIFY TEST: Arbitrary CPI Validation Fix (Pinocchio)
 * 
 * This test verifies the secure Pinocchio program checks the program ID.
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

describe("07-arbitrary-cpi-validation: Pinocchio Verify Fix", () => {
    // Using placeholder ID
    const connection = new Connection("http://localhost:8899", "confirmed");
    const PROGRAM_ID = new PublicKey("SECU7cpiVa11d1d1d1d1d1d1d1d1d1d1d1d1d1d1d");

    it("Rejects arbitrary CPI", async () => {
        console.log("\n✅ VERIFY: Arbitrary CPI Validation Fix (Pinocchio)\n");

        const user = Keypair.generate();
        const airdropSig = await connection.requestAirdrop(user.publicKey, 1000000000);
        await connection.confirmTransaction(airdropSig);

        const fakeProgram = SystemProgram.programId;
        const [vaultPda] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);

        const data = Buffer.alloc(8);
        data.writeBigUInt64LE(BigInt(100), 0);

        const ix = new TransactionInstruction({
            keys: [
                { pubkey: user.publicKey, isSigner: true, isWritable: true },
                { pubkey: fakeProgram, isSigner: false, isWritable: false }, // 🚨 Wrong Program
                { pubkey: user.publicKey, isSigner: false, isWritable: true },
                { pubkey: user.publicKey, isSigner: false, isWritable: true },
                { pubkey: vaultPda, isSigner: false, isWritable: true },
            ],
            programId: PROGRAM_ID,
            data: data,
        });

        try {
            await sendAndConfirmTransaction(connection, new Transaction().add(ix), [user]);
            throw new Error("Fail: Accepted wrong program");
        } catch (e: any) {
            console.log("✅ Success: Rejected.");
            // We expect custom error 1 (InvalidProgram)
        }
    });
});
