package com.cipherlink.cipherlink.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class MessageEncryptionServiceTest {

    private final KeyService keyService = new KeyService();
    private final MessageEncryptionService messageEncryptionService = new MessageEncryptionService(
            new AesGcmService(), new RsaOaepService());

    @Test
    void encryptsJsonBytesForReceiverAndRestoresOriginalBytes() throws Exception {
        KeyPair receiverKeys = keyService.generateRSAKeyPair();
        byte[] json = "{\"message\":\"Hello, receiver!\",\"sequence\":1}"
                .getBytes(StandardCharsets.UTF_8);

        MessageEncryptionService.EncryptedMessage encrypted = messageEncryptionService.encrypt(
                json, receiverKeys.getPublic());

        // Each field is Base64, so the record can be serialized as an ordinary JSON object.
        Base64.getDecoder().decode(encrypted.wrappedAesKey());
        Base64.getDecoder().decode(encrypted.nonce());
        Base64.getDecoder().decode(encrypted.ciphertextAndTag());
        assertArrayEquals(json, messageEncryptionService.decrypt(encrypted, receiverKeys.getPrivate()));
    }

    @Test
    void rejectsTamperedCiphertext() throws Exception {
        KeyPair receiverKeys = keyService.generateRSAKeyPair();
        MessageEncryptionService.EncryptedMessage encrypted = messageEncryptionService.encrypt(
                "secret".getBytes(StandardCharsets.UTF_8), receiverKeys.getPublic());
        byte[] changedCiphertextAndTag = Base64.getDecoder().decode(encrypted.ciphertextAndTag());
        changedCiphertextAndTag[0] ^= 1;

        MessageEncryptionService.EncryptedMessage tampered = new MessageEncryptionService.EncryptedMessage(
                encrypted.wrappedAesKey(),
                encrypted.nonce(),
                Base64.getEncoder().encodeToString(changedCiphertextAndTag));

        assertThrows(
                java.security.GeneralSecurityException.class,
                () -> messageEncryptionService.decrypt(tampered, receiverKeys.getPrivate()));
    }

    @Test
    void rejectsPrivateKeyThatDoesNotMatchReceiver() throws Exception {
        KeyPair receiverKeys = keyService.generateRSAKeyPair();
        KeyPair otherKeys = keyService.generateRSAKeyPair();
        MessageEncryptionService.EncryptedMessage encrypted = messageEncryptionService.encrypt(
                "secret".getBytes(StandardCharsets.UTF_8), receiverKeys.getPublic());

        assertThrows(
                java.security.GeneralSecurityException.class,
                () -> messageEncryptionService.decrypt(encrypted, otherKeys.getPrivate()));
    }
}
