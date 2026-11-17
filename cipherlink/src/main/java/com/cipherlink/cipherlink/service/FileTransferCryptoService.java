package com.cipherlink.cipherlink.service;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

/** Client-side file envelope operations. The server receives only the resulting signed package. */
@Service
public class FileTransferCryptoService {
    private final AesGcmService aes;
    private final RsaOaepService rsa;
    private final SignatureService signatures;

    public FileTransferCryptoService(AesGcmService aes, RsaOaepService rsa, SignatureService signatures) {
        this.aes = Objects.requireNonNull(aes);
        this.rsa = Objects.requireNonNull(rsa);
        this.signatures = Objects.requireNonNull(signatures);
    }

    public SignedFilePackage encryptAndSign(byte[] file, String fileName, String senderId, String recipientId,
            PublicKey recipientEncryptionKey, PrivateKey senderSigningKey) throws GeneralSecurityException {
        Objects.requireNonNull(file, "file must not be null");
        requireText(fileName, "fileName"); requireText(senderId, "senderId"); requireText(recipientId, "recipientId");
        AesGcmService.EncryptedFile encrypted = aes.encrypt(file);
        byte[] wrapped = rsa.wrapAesKey(encrypted.aesKey(), recipientEncryptionKey);
        String wrappedB64 = Base64.getEncoder().encodeToString(wrapped);
        String nonceB64 = Base64.getEncoder().encodeToString(encrypted.nonce());
        String cipherB64 = Base64.getEncoder().encodeToString(encrypted.ciphertextAndTag());
        byte[] signature = signatures.sign(canonical(fileName, senderId, recipientId, wrappedB64, nonceB64, cipherB64), senderSigningKey);
        return new SignedFilePackage(fileName, senderId, recipientId, wrappedB64, nonceB64, cipherB64,
                Base64.getEncoder().encodeToString(signature));
    }

    public byte[] verifyAndDecrypt(SignedFilePackage file, PublicKey senderSigningKey, PrivateKey recipientKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(file, "file package must not be null");
        byte[] sig;
        byte[] wrapped;
        byte[] nonce;
        byte[] ciphertext;
        try {
            sig = Base64.getDecoder().decode(file.signature());
            wrapped = Base64.getDecoder().decode(file.wrappedAesKey());
            nonce = Base64.getDecoder().decode(file.nonce());
            ciphertext = Base64.getDecoder().decode(file.ciphertextAndTag());
        } catch (IllegalArgumentException e) { throw new GeneralSecurityException("Package contains invalid Base64 data", e); }
        if (!signatures.verify(canonical(file.fileName(), file.senderId(), file.recipientId(),
                file.wrappedAesKey(), file.nonce(), file.ciphertextAndTag()), sig, senderSigningKey))
            throw new java.security.SignatureException("File package signature is invalid");
        SecretKey key = rsa.unwrapAesKey(wrapped, recipientKey);
        return aes.decrypt(key, nonce, ciphertext);
    }

    public boolean verifySignature(SignedFilePackage file, PublicKey senderSigningKey) throws GeneralSecurityException {
        Objects.requireNonNull(file, "file package must not be null");
        try {
            byte[] signature = Base64.getDecoder().decode(file.signature());
            return signatures.verify(canonical(file.fileName(), file.senderId(), file.recipientId(),
                    file.wrappedAesKey(), file.nonce(), file.ciphertextAndTag()), signature, senderSigningKey);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Package contains invalid Base64 data", e);
        }
    }
    private static byte[] canonical(String... fields) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write("CipherLink package v1".getBytes(StandardCharsets.UTF_8));
            for (String field : fields) {
                byte[] value = field.getBytes(StandardCharsets.UTF_8);
                out.writeInt(value.length);
                out.write(value);
            }
            out.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) { throw new AssertionError(impossible); }
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 255) throw new IllegalArgumentException(name + " must contain 1 to 255 characters");
    }

    public record SignedFilePackage(String fileName, String senderId, String recipientId,
            String wrappedAesKey, String nonce, String ciphertextAndTag, String signature) {
        public SignedFilePackage {
            requireText(fileName, "fileName"); requireText(senderId, "senderId"); requireText(recipientId, "recipientId");
            Objects.requireNonNull(wrappedAesKey); Objects.requireNonNull(nonce);
            Objects.requireNonNull(ciphertextAndTag); Objects.requireNonNull(signature);
        }
    }
}




