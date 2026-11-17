package com.cipherlink.cipherlink.service;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Objects;
import org.springframework.stereotype.Service;

/** Ed25519 signatures authenticate a canonical encrypted-package representation. */
@Service
public class SignatureService {
    public byte[] sign(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        if (!"EdDSA".equalsIgnoreCase(privateKey.getAlgorithm()) && !"Ed25519".equalsIgnoreCase(privateKey.getAlgorithm()))
            throw new java.security.InvalidKeyException("Signing key must use Ed25519");
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public boolean verify(byte[] data, byte[] signed, PublicKey publicKey) throws GeneralSecurityException {
        Objects.requireNonNull(data, "data must not be null");
        Objects.requireNonNull(signed, "signature must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        if (!"EdDSA".equalsIgnoreCase(publicKey.getAlgorithm()) && !"Ed25519".equalsIgnoreCase(publicKey.getAlgorithm()))
            throw new java.security.InvalidKeyException("Verification key must use Ed25519");
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signed);
    }
}

