package com.cipherlink.cipherlink.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

class RsaOaepServiceTest {

    private final KeyService keyService = new KeyService();
    private final RsaOaepService rsaOaepService = new RsaOaepService();
    private final AesGcmService aesGcmService = new AesGcmService();

    @Test
    void wrapsAndUnwrapsAes128KeyForReceiver() throws Exception {
        KeyPair receiverKeys = keyService.generateRSAKeyPair();
        KeyPair otherUserKeys = keyService.generateRSAKeyPair();
        byte[] plaintext = "file contents".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        AesGcmService.EncryptedFile encrypted = aesGcmService.encrypt(
                plaintext);

        byte[] wrappedKey = rsaOaepService.wrapAesKey(encrypted.aesKey(), receiverKeys.getPublic());
        SecretKey recoveredKey = rsaOaepService.unwrapAesKey(wrappedKey, receiverKeys.getPrivate());

        assertArrayEquals(encrypted.aesKey().getEncoded(), recoveredKey.getEncoded());
        assertArrayEquals(
                plaintext,
                aesGcmService.decrypt(recoveredKey, encrypted.nonce(), encrypted.ciphertextAndTag()));
        assertThrows(
                GeneralSecurityException.class,
                () -> rsaOaepService.unwrapAesKey(wrappedKey, otherUserKeys.getPrivate()));
    }

    @Test
    void rejectsAes256Key() {
        SecretKey aes256Key = new SecretKeySpec(new byte[32], "AES");

        assertThrows(
                GeneralSecurityException.class,
                () -> rsaOaepService.wrapAesKey(
                        aes256Key,
                        keyService.generateRSAKeyPair().getPublic()));
    }
}
