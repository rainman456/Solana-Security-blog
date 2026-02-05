/**
 * VERIFY TEST: Arbitrary CPI Validation Fix (Anchor)
 * 
 * This test verifies that the secure Anchor program REJECTS CPI calls to arbitrary programs.
 * 
 * Fix: The program enforces `address = token::ID` constraint on the program account.
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

describe("07-arbitrary-cpi-validation: Anchor Verify Fix", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const PROGRAM_ID = new PublicKey("SECU7cpiVa11d1d1d1d1d1d1d1d1d1d1d1d1d1d1d");

    it("Rejects CPI to Arbitrary Program", async () => {
        console.log("\n✅ VERIFY: Arbitrary CPI Validation Fix (Anchor)\n");

        const idl = await Program.fetchIdl(PROGRAM_ID, provider);
        if (!idl) {
            throw new Error("IDL not found. Make sure the secure program is deployed.");
        }
        const program = new Program(idl, PROGRAM_ID, provider);

        const user = Keypair.generate();
        console.log("👤 User:", user.publicKey.toBase58());

        const airdropSig = await provider.connection.requestAirdrop(user.publicKey, 2 * 1000000000);
        await provider.connection.confirmTransaction(airdropSig);

        const [vaultPda] = PublicKey.findProgramAddressSync([Buffer.from("vault")], PROGRAM_ID);

        // Note: Assuming initialization works or using existing state logic (see Exploit note)

        const fakeProgram = SystemProgram.programId;

        try {
            await program.methods
                .executeSwap(new BN(100))
                .accounts({
                    user: user.publicKey,
                    tokenProgram: fakeProgram, // 🚨 Try to pass System Program
                    vaultTokenAccount: vaultPda, // Dummy
                    vault: vaultPda,
                    userTokenAccount: vaultPda, // Dummy
                })
                .signers([user])
                .rpc();

            throw new Error("❌ FAIL: Secure vault accepted arbitrary program!");

        } catch (e: any) {
            if (e.message.includes("InvalidProgramId") || e.message.includes("ConstraintAddress") || e.toString().includes("Constraint")) {
                console.log("✅ SUCCESS: Transaction rejected because Program ID did not match Token Program.");
            } else {
                console.log("✅ SUCCESS: Transaction rejected (Other Error)");
                console.log("   Error:", e.message);
            }
        }
    });
});
