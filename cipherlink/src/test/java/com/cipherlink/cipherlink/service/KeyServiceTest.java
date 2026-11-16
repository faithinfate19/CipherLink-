package com.cipherlink.cipherlink.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;

class KeyServiceTest {

    private final KeyService keyService = new KeyService();

    @Test
    void generates3072BitRSAKeyPair() throws Exception {
        KeyPair keyPair = keyService.generateRSAKeyPair();

        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals(3072, ((RSAPublicKey) keyPair.getPublic()).getModulus().bitLength());
    }

    @Test
    void generatesEd25519SigningKeyPair() throws Exception {
        KeyPair keyPair = keyService.generateSigningKeyPair();

        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("Ed25519", ((EdECPublicKey) keyPair.getPublic()).getParams().getName());
    }
}
