package com.cipherlink.cipherlink.service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

/** Local, password-protected serialization for both user key pairs. This service must stay on user devices. */
@Service
public class EncryptedKeyStore {
    private static final byte[] MAGIC = "CIPHERLINK-KEYS-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int SALT_BYTES = 16, NONCE_BYTES = 12, TAG_BITS = 128, ITERATIONS = 600_000;
    private final SecureRandom random = new SecureRandom();

    public void save(Path destination, KeyPair encryption, KeyPair signing, char[] passphrase)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(destination); Objects.requireNonNull(encryption); Objects.requireNonNull(signing);
        byte[] payload = encode(encryption, signing);
        byte[] salt = new byte[SALT_BYTES], nonce = new byte[NONCE_BYTES];
        random.nextBytes(salt); random.nextBytes(nonce);
        byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, payload, salt, nonce, passphrase);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.write(MAGIC); out.write(salt); out.write(nonce); out.writeInt(ciphertext.length); out.write(ciphertext);
        } finally { Arrays.fill(payload, (byte) 0); }
        Files.write(destination, bytes.toByteArray(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    public StoredKeys load(Path source, char[] passphrase) throws IOException, GeneralSecurityException {
        byte[] file = Files.readAllBytes(source);
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(file))) {
            byte[] magic = in.readNBytes(MAGIC.length);
            if (!Arrays.equals(MAGIC, magic)) throw new IOException("Not a CipherLink key file");
            byte[] salt = in.readNBytes(SALT_BYTES), nonce = in.readNBytes(NONCE_BYTES);
            int length = in.readInt();
            if (length < 16 || length != in.available()) throw new IOException("Invalid key file length");
            byte[] ciphertext = in.readNBytes(length);
            byte[] payload = crypt(Cipher.DECRYPT_MODE, ciphertext, salt, nonce, passphrase);
            try { return decode(payload); } finally { Arrays.fill(payload, (byte) 0); }
        } catch (java.io.EOFException e) { throw new IOException("Truncated key file", e); }
    }

    private byte[] crypt(int mode, byte[] data, byte[] salt, byte[] nonce, char[] password) throws GeneralSecurityException {
        if (password == null || password.length < 12) throw new IllegalArgumentException("Passphrase must be at least 12 characters");
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 128);
        byte[] raw = null;
        try {
            raw = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(raw, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(MAGIC);
            return cipher.doFinal(data);
        } finally { spec.clearPassword(); if (raw != null) Arrays.fill(raw, (byte) 0); }
    }

    private static byte[] encode(KeyPair rsa, KeyPair signing) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            write(out, rsa.getPrivate().getEncoded()); write(out, rsa.getPublic().getEncoded());
            write(out, signing.getPrivate().getEncoded()); write(out, signing.getPublic().getEncoded());
        }
        return bytes.toByteArray();
    }
    private static StoredKeys decode(byte[] payload) throws IOException, GeneralSecurityException {
        try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
            byte[] rsaPrivate=read(in), rsaPublic=read(in), signPrivate=read(in), signPublic=read(in);
            if (in.available()!=0) throw new IOException("Unexpected data in key file");
            KeyFactory rsa=KeyFactory.getInstance("RSA"), ed=KeyFactory.getInstance("Ed25519");
            return new StoredKeys(new KeyPair(rsa.generatePublic(new X509EncodedKeySpec(rsaPublic)), rsa.generatePrivate(new PKCS8EncodedKeySpec(rsaPrivate))),
                    new KeyPair(ed.generatePublic(new X509EncodedKeySpec(signPublic)), ed.generatePrivate(new PKCS8EncodedKeySpec(signPrivate))));
        } catch (java.io.EOFException e) { throw new IOException("Invalid key file contents", e); }
    }
    private static void write(DataOutputStream out, byte[] value) throws IOException { out.writeInt(value.length); out.write(value); }
    private static byte[] read(DataInputStream in) throws IOException {
        int n=in.readInt(); if (n<1 || n>16_384 || n>in.available()) throw new IOException("Invalid key material length");
        return in.readNBytes(n);
    }
    public record StoredKeys(KeyPair encryptionKeys, KeyPair signingKeys) { }
}

