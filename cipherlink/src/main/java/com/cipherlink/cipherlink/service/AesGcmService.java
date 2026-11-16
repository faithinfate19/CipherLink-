package com.cipherlink.cipherlink.service;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.springframework.stereotype.Service;

@Service
public class AesGcmService {

    private static final int AES_KEY_SIZE_BITS = 128;
    private static final int NONCE_SIZE_BYTES = 12;
    private static final int AUTH_TAG_SIZE_BITS = 128;

    private final SecureRandom secureRandom = new SecureRandom();

    public EncryptedFile encrypt(byte[] plaintext) throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "plaintext must not be null");

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE_BITS, secureRandom);
        SecretKey aesKey = keyGenerator.generateKey();

        byte[] nonce = new byte[NONCE_SIZE_BYTES];
        secureRandom.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(AUTH_TAG_SIZE_BITS, nonce));
        byte[] ciphertextAndTag = cipher.doFinal(plaintext);

        return new EncryptedFile(aesKey, nonce, ciphertextAndTag);
    }

    public EncryptedFile encryptFile(Path inputPath)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(inputPath, "inputPath must not be null");

        byte[] fileBytes = Files.readAllBytes(inputPath);
        return encrypt(fileBytes);
    }

    public byte[] decrypt(SecretKey aesKey, byte[] nonce, byte[] ciphertextAndTag)
            throws GeneralSecurityException {
        Objects.requireNonNull(aesKey, "aesKey must not be null");
        Objects.requireNonNull(nonce, "nonce must not be null");
        Objects.requireNonNull(ciphertextAndTag, "ciphertextAndTag must not be null");

        if (nonce.length != NONCE_SIZE_BYTES) {
            throw new IllegalArgumentException("AES-GCM nonce must be exactly 12 bytes");
        }
        if (ciphertextAndTag.length < AUTH_TAG_SIZE_BITS / Byte.SIZE) {
            throw new IllegalArgumentException("AES-GCM data must include its 16-byte authentication tag");
        }

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(AUTH_TAG_SIZE_BITS, nonce));
        return cipher.doFinal(ciphertextAndTag);
    }

    public void decryptToFile(
            SecretKey aesKey,
            byte[] nonce,
            byte[] ciphertextAndTag,
            Path outputPath)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(outputPath, "outputPath must not be null");

        // GCM verifies the authentication tag before this method writes plaintext.
        byte[] plaintext = decrypt(aesKey, nonce, ciphertextAndTag);
        Files.write(outputPath, plaintext, StandardOpenOption.CREATE_NEW);
    }

    public record EncryptedFile(SecretKey aesKey, byte[] nonce, byte[] ciphertextAndTag) {

        public EncryptedFile {
            Objects.requireNonNull(aesKey, "aesKey must not be null");
            Objects.requireNonNull(nonce, "nonce must not be null");
            Objects.requireNonNull(ciphertextAndTag, "ciphertextAndTag must not be null");
            if (nonce.length != NONCE_SIZE_BYTES) {
                throw new IllegalArgumentException("AES-GCM nonce must be exactly 12 bytes");
            }
            if (ciphertextAndTag.length < AUTH_TAG_SIZE_BITS / Byte.SIZE) {
                throw new IllegalArgumentException("AES-GCM data must include its 16-byte authentication tag");
            }

            nonce = Arrays.copyOf(nonce, nonce.length);
            ciphertextAndTag = Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length);
        }

        @Override
        public byte[] nonce() {
            return Arrays.copyOf(nonce, nonce.length);
        }

        @Override
        public byte[] ciphertextAndTag() {
            return Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length);
        }
    }
}
