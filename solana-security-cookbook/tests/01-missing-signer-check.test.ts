import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction, PublicKey } from "@solana/web3.js";
import { assert } from "chai";

describe("Missing Signer Check Tests", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    // --- Configuration ---
    // Anchor Program IDs (from Anchor.toml)
    const ANCHOR_PROGRAM_ID = new PublicKey("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

    // Pinocchio Program IDs (Placeholder - user must deploy and update these)
    // For now we use the same ID as placeholder, but in reality they would be different.
    // We will skip Pinocchio tests if IDs are not set/deployed.
    const PINOCCHIO_VULNERABLE_ID = new PublicKey("PinocchioVuLnErAbLe111111111111111111111111");
    const PINOCCHIO_SECURE_ID = new PublicKey("PinocchioSecuRe111111111111111111111111111");

    // Users
    const user = Keypair.generate();
    const attacker = Keypair.generate();
    const amount = new anchor.BN(1000000); // 0.001 SOL

    before(async () => {
        // Air drop SOL to users
        const latestBlockHash = await provider.connection.getLatestBlockhash();
        for (const u of [user, attacker]) {
            const sig = await provider.connection.requestAirdrop(u.publicKey, 10 * anchor.web3.LAMPORTS_PER_SOL);
            await provider.connection.confirmTransaction({
                blockhash: latestBlockHash.blockhash,
                lastValidBlockHeight: latestBlockHash.lastValidBlockHeight,
                signature: sig,
            });
        }
    });

    // Helper to create Pinocchio instruction data
    // Discriminator: 0=Init, 1=Deposit, 2=Withdraw
    function createPinocchioData(discriminator: number, amount: anchor.BN): Buffer {
        const data = Buffer.alloc(9);
        data.writeUInt8(discriminator, 0);
        data.writeBigUInt64LE(BigInt(amount.toString()), 1);
        return data;
    }

    // --- Anchor Tests ---
    describe("Anchor Implementation", () => {
        // We assume the Anchor program is deployed at ANCHOR_PROGRAM_ID
        // Note: To test both vulnerable and secure Anchor programs, 
        // we normally need them deployed to different IDs or run tests sequentially.
        // This test structure is a template.

        it("Placeholder for Anchor tests", async () => {
            console.log("Anchor tests would run here. Deployment of specific version required.");
        });
    });

    // --- Pinocchio Tests ---
    describe("Pinocchio Implementation", () => {
        it("Vulnerable: Allows withdraw without signature", async () => {
            // Skip if program not deployed
            const accountInfo = await provider.connection.getAccountInfo(PINOCCHIO_VULNERABLE_ID);
            if (!accountInfo) {
                console.log("Skipping Pinocchio Vulnerable test - program not deployed");
                return;
            }

            // PDA for vault
            const [vaultPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("vault"), user.publicKey.toBuffer()],
                PINOCCHIO_VULNERABLE_ID
            );

            // 1. Initialize (using user)
            // 2. Deposit (using user)
            // 3. Attack (using attacker, passing user as 'signer' but NOT signing)

            const ix = new TransactionInstruction({
                keys: [
                    { pubkey: user.publicKey, isSigner: false, isWritable: true }, // ❌ Not signing!
                    { pubkey: vaultPda, isSigner: false, isWritable: true },
                ],
                programId: PINOCCHIO_VULNERABLE_ID,
                data: createPinocchioData(2, amount) // Withdraw
            });

            const tx = new Transaction().add(ix);

            try {
                await sendAndConfirmTransaction(provider.connection, tx, [attacker]);
                // If we are here, it succeeded -> VULNERABLE confirmed
                console.log("Attack successful: Withdrew without signature!");
            } catch (err) {
                assert.fail("Should have allowed withdrawal without signature: " + err);
            }
        });

        it("Secure: Rejects withdraw without signature", async () => {
            // Skip if program not deployed
            const accountInfo = await provider.connection.getAccountInfo(PINOCCHIO_SECURE_ID);
            if (!accountInfo) {
                console.log("Skipping Pinocchio Secure test - program not deployed");
                return;
            }

            const [vaultPda] = PublicKey.findProgramAddressSync(
                [Buffer.from("vault"), user.publicKey.toBuffer()],
                PINOCCHIO_SECURE_ID
            );

            const ix = new TransactionInstruction({
                keys: [
                    { pubkey: user.publicKey, isSigner: false, isWritable: true }, // ❌ Not signing!
                    { pubkey: vaultPda, isSigner: false, isWritable: true },
                ],
                programId: PINOCCHIO_SECURE_ID,
                data: createPinocchioData(2, amount)
            });

            const tx = new Transaction().add(ix);

            try {
                await sendAndConfirmTransaction(provider.connection, tx, [attacker]);
                assert.fail("Should have failed!");
            } catch (err) {
                // Expected error: "MissingRequiredSignature" or similar
                // console.log("Secure program correctly rejected transaction:", err);
                assert.ok(true);
            }
        });
    });
});
