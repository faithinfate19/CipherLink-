package com.cipherlink.cipherlink.service;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EncryptedKeyStoreTest {
    @TempDir Path temp;
    private final KeyService keys = new KeyService();
    private final EncryptedKeyStore store = new EncryptedKeyStore();

    @Test void savesAndLoadsPrivateKeysOnlyWithCorrectPassphrase() throws Exception {
        KeyPair rsa=keys.generateRSAKeyPair(), ed=keys.generateSigningKeyPair();
        Path file=temp.resolve("alice.keys");
        store.save(file, rsa, ed, "correct horse battery".toCharArray());
        var restored=store.load(file, "correct horse battery".toCharArray());
        assertArrayEquals(rsa.getPublic().getEncoded(), restored.encryptionKeys().getPublic().getEncoded());
        assertArrayEquals(ed.getPrivate().getEncoded(), restored.signingKeys().getPrivate().getEncoded());
        assertThrows(java.security.GeneralSecurityException.class,
                () -> store.load(file, "incorrect passphrase".toCharArray()));
        assertThrows(java.nio.file.FileAlreadyExistsException.class,
                () -> store.save(file, rsa, ed, "correct horse battery".toCharArray()));
    }
}
