package com.cipherlink.cipherlink.service;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import com.cipherlink.cipherlink.service.FileTransferCryptoService.SignedFilePackage;

class FileTransferCryptoServiceTest {
    private final KeyService keys = new KeyService();
    private final FileTransferCryptoService crypto = new FileTransferCryptoService(
            new AesGcmService(), new RsaOaepService(), new SignatureService());

    @Test void roundTripsAndAuthenticatesPackage() throws Exception {
        KeyPair receiver = keys.generateRSAKeyPair();
        KeyPair sender = keys.generateSigningKeyPair();
        byte[] input = "confidential file".getBytes(StandardCharsets.UTF_8);
        SignedFilePackage pkg = crypto.encryptAndSign(input, "sample.txt", "alice", "bob",
                receiver.getPublic(), sender.getPrivate());
        assertTrue(crypto.verifySignature(pkg, sender.getPublic()));
        assertArrayEquals(input, crypto.verifyAndDecrypt(pkg, sender.getPublic(), receiver.getPrivate()));
    }

    @Test void rejectsPackageMetadataTamperingBeforeDecrypt() throws Exception {
        KeyPair receiver = keys.generateRSAKeyPair();
        KeyPair sender = keys.generateSigningKeyPair();
        SignedFilePackage pkg = crypto.encryptAndSign(new byte[] {1,2}, "a.txt", "alice", "bob",
                receiver.getPublic(), sender.getPrivate());
        SignedFilePackage changed = new SignedFilePackage("evil.txt", pkg.senderId(), pkg.recipientId(),
                pkg.wrappedAesKey(), pkg.nonce(), pkg.ciphertextAndTag(), pkg.signature());
        assertFalse(crypto.verifySignature(changed, sender.getPublic()));
        assertThrows(java.security.SignatureException.class,
                () -> crypto.verifyAndDecrypt(changed, sender.getPublic(), receiver.getPrivate()));
    }

    @Test void rejectsWrongSenderKey() throws Exception {
        KeyPair receiver = keys.generateRSAKeyPair();
        KeyPair sender = keys.generateSigningKeyPair();
        KeyPair attacker = keys.generateSigningKeyPair();
        SignedFilePackage pkg = crypto.encryptAndSign(new byte[] {7}, "a.txt", "alice", "bob",
                receiver.getPublic(), sender.getPrivate());
        assertFalse(crypto.verifySignature(pkg, attacker.getPublic()));
    }
}
