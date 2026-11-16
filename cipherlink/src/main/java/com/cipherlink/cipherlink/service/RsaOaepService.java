package com.cipherlink.cipherlink.service;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

@Service
public class RsaOaepService {

    private static final int AES_128_KEY_SIZE_BYTES = 16;
    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String OAEP_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final OAEPParameterSpec OAEP_PARAMETERS = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT);

    public byte[] wrapAesKey(SecretKey aesKey, PublicKey receiverPublicKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(aesKey, "aesKey must not be null");
        Objects.requireNonNull(receiverPublicKey, "receiverPublicKey must not be null");
        if (!AES_ALGORITHM.equalsIgnoreCase(aesKey.getAlgorithm())) {
            throw new InvalidKeyException("Only AES keys can be wrapped");
        }
        if (!RSA_ALGORITHM.equalsIgnoreCase(receiverPublicKey.getAlgorithm())) {
            throw new InvalidKeyException("Receiver public key must use RSA");
        }

        byte[] aesKeyBytes = aesKey.getEncoded();
        if (aesKeyBytes == null) {
            throw new InvalidKeyException("AES key does not expose encodable key material");
        }

        try {
            if (aesKeyBytes.length != AES_128_KEY_SIZE_BYTES) {
                throw new InvalidKeyException("Only 128-bit AES keys can be wrapped");
            }

            Cipher cipher = Cipher.getInstance(OAEP_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey, OAEP_PARAMETERS);
            return cipher.doFinal(aesKeyBytes);
        } finally {
            Arrays.fill(aesKeyBytes, (byte) 0);
        }
    }

    public SecretKey unwrapAesKey(byte[] wrappedAesKey, PrivateKey receiverPrivateKey)
            throws GeneralSecurityException {
        Objects.requireNonNull(wrappedAesKey, "wrappedAesKey must not be null");
        Objects.requireNonNull(receiverPrivateKey, "receiverPrivateKey must not be null");
        if (!RSA_ALGORITHM.equalsIgnoreCase(receiverPrivateKey.getAlgorithm())) {
            throw new InvalidKeyException("Receiver private key must use RSA");
        }

        Cipher cipher = Cipher.getInstance(OAEP_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey, OAEP_PARAMETERS);
        byte[] aesKeyBytes = cipher.doFinal(wrappedAesKey);

        try {
            if (aesKeyBytes.length != AES_128_KEY_SIZE_BYTES) {
                throw new InvalidKeyException("Unwrapped key is not a 128-bit AES key");
            }
            return new SecretKeySpec(aesKeyBytes, AES_ALGORITHM);
        } finally {
            Arrays.fill(aesKeyBytes, (byte) 0);
        }
    }
}
