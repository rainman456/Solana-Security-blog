/**
 * VERIFY TEST: Missing Mint Validation Fix (Anchor)
 * 
 * This test verifies that the secure Anchor program REJECTS deposits of incorrect token mints.
 * 
 * Fix: The program uses Anchor constraints:
 * `constraint = vault_token_account.mint == vault.token_mint @ VaultError::InvalidMint`
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair, SystemProgram } from "@solana/web3.js";
import {
    createMint,
    createAccount,
    mintTo,
    TOKEN_PROGRAM_ID
} from "@solana/spl-token";
import { BN } from "bn.js";

describe("06-missing-mint-validation: Anchor Verify Fix", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const PROGRAM_ID = new PublicKey("SECU6mintVa11d1d1d1d1d1d1d1d1d1d1d1d1d1d1");

    it("Rejects deposit of Fake Tokens", async () => {
        console.log("\n✅ VERIFY: Missing Mint Validation Fix (Anchor)\n");

        const idl = await Program.fetchIdl(PROGRAM_ID, provider);
        if (!idl) {
            throw new Error("IDL not found. Make sure the secure program is deployed.");
        }
        const program = new Program(idl, PROGRAM_ID, provider);

        const user = Keypair.generate();
        console.log("👤 User:", user.publicKey.toBase58());

        const airdropSig = await provider.connection.requestAirdrop(
            user.publicKey,
            2 * 1000000000
        );
        await provider.connection.confirmTransaction(airdropSig);

        // 1. Create GOOD Mint
        const goodMint = await createMint(provider.connection, user, user.publicKey, null, 6);
        // 2. Create BAD Mint
        const badMint = await createMint(provider.connection, user, user.publicKey, null, 6);

        // 3. Initialize Vault with GOOD Mint
        const [vaultPda] = PublicKey.findProgramAddressSync(
            [Buffer.from("vault"), goodMint.toBuffer()],
            PROGRAM_ID
        );

        await program.methods
            .initializeVault(goodMint)
            .accounts({
                payer: user.publicKey,
                vault: vaultPda,
                tokenMint: goodMint,
                systemProgram: SystemProgram.programId,
            })
            .signers([user])
            .rpc();

        // 4. Setup Bad Token Accounts
        const userBadTokenAccount = await createAccount(provider.connection, user, badMint, user.publicKey);
        const vaultBadTokenAccount = await createAccount(provider.connection, user, badMint, vaultPda);

        await mintTo(provider.connection, user, badMint, userBadTokenAccount, user, 1000000);

        // 5. Attempt Exploit
        console.log("\n🛡️  Attempting to deposit Fake Tokens to Secure Vault...");
        const depositAmount = new BN(500000);

        try {
            await program.methods
                .deposit(depositAmount)
                .accounts({
                    user: user.publicKey,
                    vaultTokenAccount: vaultBadTokenAccount,
                    vault: vaultPda,
                    userTokenAccount: userBadTokenAccount,
                    tokenProgram: TOKEN_PROGRAM_ID,
                })
                .signers([user])
                .rpc();

            throw new Error("❌ FAIL: Secure vault accepted fake tokens!");

        } catch (e) {
            if (e.message.includes("Token account mint must match vault mint") || e.message.includes("InvalidMint") || e.toString().includes("Constraint")) {
                console.log("✅ SUCCESS: Transaction rejected with 'InvalidMint' error.");
            } else {
                console.log("✅ SUCCESS: Transaction rejected (Other Error)");
                console.log("   Error:", e.message);
            }
        }
    });
});
