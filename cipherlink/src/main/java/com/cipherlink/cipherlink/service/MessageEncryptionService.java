package com.cipherlink.cipherlink.service;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

/** Combines AES-GCM content encryption with RSA-OAEP encryption of the AES key. */
@Service
public class MessageEncryptionService {

    private final AesGcmService aesGcmService;
    private final RsaOaepService rsaOaepService;

    public MessageEncryptionService(AesGcmService aesGcmService, RsaOaepService rsaOaepService) {
        this.aesGcmService = Objects.requireNonNull(aesGcmService, "aesGcmService must not be null");
        this.rsaOaepService = Objects.requireNonNull(rsaOaepService, "rsaOaepService must not be null");
    }

    /** Encrypts arbitrary bytes and returns Base64 fields suitable for JSON transport. */
    public EncryptedMessage encrypt(byte[] plaintext, PublicKey receiverPublicKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        Objects.requireNonNull(receiverPublicKey, "receiverPublicKey must not be null");

        AesGcmService.EncryptedFile encrypted = aesGcmService.encrypt(plaintext);
        byte[] wrappedAesKey = rsaOaepService.wrapAesKey(encrypted.aesKey(), receiverPublicKey);

        return new EncryptedMessage(
                Base64.getEncoder().encodeToString(wrappedAesKey),
                Base64.getEncoder().encodeToString(encrypted.nonce()),
                Base64.getEncoder().encodeToString(encrypted.ciphertextAndTag()));
    }

    /** Decrypts a transported message and verifies its AES-GCM authentication tag. */
    public byte[] decrypt(EncryptedMessage message, PrivateKey receiverPrivateKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(message, "message must not be null");
        Objects.requireNonNull(receiverPrivateKey, "receiverPrivateKey must not be null");

        byte[] wrappedAesKey = Base64.getDecoder().decode(message.wrappedAesKey());
        byte[] nonce = Base64.getDecoder().decode(message.nonce());
        byte[] ciphertextAndTag = Base64.getDecoder().decode(message.ciphertextAndTag());
        SecretKey aesKey = rsaOaepService.unwrapAesKey(wrappedAesKey, receiverPrivateKey);

        return aesGcmService.decrypt(aesKey, nonce, ciphertextAndTag);
    }

    /** JSON-friendly representation; ciphertextAndTag contains ciphertext followed by its GCM tag. */
    public record EncryptedMessage(String wrappedAesKey, String nonce, String ciphertextAndTag) {
        public EncryptedMessage {
            Objects.requireNonNull(wrappedAesKey, "wrappedAesKey must not be null");
            Objects.requireNonNull(nonce, "nonce must not be null");
            Objects.requireNonNull(ciphertextAndTag, "ciphertextAndTag must not be null");
        }
    }
}

