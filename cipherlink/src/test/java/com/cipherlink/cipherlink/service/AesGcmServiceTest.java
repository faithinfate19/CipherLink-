package com.cipherlink.cipherlink.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.crypto.AEADBadTagException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AesGcmServiceTest {

    private final AesGcmService aesGcmService = new AesGcmService();

    @TempDir
    Path tempDir;

    @Test
    void encryptsAndDecryptsBytes() throws GeneralSecurityException {
        byte[] original = "CipherLink test file".getBytes(StandardCharsets.UTF_8);

        AesGcmService.EncryptedFile encrypted = aesGcmService.encrypt(original);

        assertEquals("AES", encrypted.aesKey().getAlgorithm());
        assertEquals(128, encrypted.aesKey().getEncoded().length * Byte.SIZE);
        assertEquals(12, encrypted.nonce().length);
        assertNotNull(encrypted.ciphertextAndTag());

        byte[] decrypted = aesGcmService.decrypt(
                encrypted.aesKey(),
                encrypted.nonce(),
                encrypted.ciphertextAndTag());

        assertArrayEquals(original, decrypted);
    }

    @Test
    void rejectsModifiedCiphertext() throws GeneralSecurityException {
        byte[] original = "CipherLink test file".getBytes(StandardCharsets.UTF_8);
        AesGcmService.EncryptedFile encrypted = aesGcmService.encrypt(original);

        byte[] modifiedCiphertext = encrypted.ciphertextAndTag();
        modifiedCiphertext[0] ^= 1;

        assertThrows(
                AEADBadTagException.class,
                () -> aesGcmService.decrypt(
                        encrypted.aesKey(),
                        encrypted.nonce(),
                        modifiedCiphertext));
    }

    @Test
    void encryptsAndDecryptsEmptyInput() throws GeneralSecurityException {
        byte[] original = new byte[0];
        AesGcmService.EncryptedFile encrypted = aesGcmService.encrypt(original);

        byte[] decrypted = aesGcmService.decrypt(
                encrypted.aesKey(), encrypted.nonce(), encrypted.ciphertextAndTag());

        assertArrayEquals(original, decrypted);
        assertEquals(16, encrypted.ciphertextAndTag().length);
    }

    @Test
    void rejectsWrongLengthNonce() throws GeneralSecurityException {
        AesGcmService.EncryptedFile encrypted = aesGcmService.encrypt(new byte[] { 1 });

        assertThrows(
                IllegalArgumentException.class,
                () -> aesGcmService.decrypt(
                        encrypted.aesKey(), new byte[11], encrypted.ciphertextAndTag()));
    }

    @Test
    void encryptsAndDecryptsJsonFile() throws Exception {
        String json = "{\"message\":\"hello\",\"count\":3}";
        Path input = tempDir.resolve("message.json");
        Path restored = tempDir.resolve("restored.json");

        Files.writeString(input, json, StandardCharsets.UTF_8);
        AesGcmService.EncryptedFile encrypted = aesGcmService.encryptFile(input);

        aesGcmService.decryptToFile(
                encrypted.aesKey(),
                encrypted.nonce(),
                encrypted.ciphertextAndTag(),
                restored);

        assertEquals(json, Files.readString(restored, StandardCharsets.UTF_8));
    }

    @Test
    void doesNotWriteOutputWhenJsonFileAuthenticationFails() throws Exception {
        AesGcmService.EncryptedFile encrypted = aesGcmService.encrypt(
                "{\"message\":\"hello\"}".getBytes(StandardCharsets.UTF_8));
        byte[] modifiedCiphertext = encrypted.ciphertextAndTag();
        modifiedCiphertext[0] ^= 1;
        Path output = tempDir.resolve("must-not-be-written.json");

        assertThrows(
                AEADBadTagException.class,
                () -> aesGcmService.decryptToFile(
                        encrypted.aesKey(),
                        encrypted.nonce(),
                        modifiedCiphertext,
                        output));
        assertFalse(Files.exists(output));
    }
}
