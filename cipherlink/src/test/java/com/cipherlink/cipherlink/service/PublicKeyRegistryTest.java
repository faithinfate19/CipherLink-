package com.cipherlink.cipherlink.service;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.ObjectMapper;

class PublicKeyRegistryTest {
    @TempDir Path temp;
    @Test void publicKeysSurviveRestartAndRequireTheSameToken() throws Exception {
        KeyService keys=new KeyService();
        var rsa=keys.generateRSAKeyPair(); var ed=keys.generateSigningKeyPair();
        String id="user-"+UUID.randomUUID(), token=new AccessTokenService().generate();
        String r=Base64.getEncoder().encodeToString(rsa.getPublic().getEncoded());
        String s=Base64.getEncoder().encodeToString(ed.getPublic().getEncoded());
        var first=new PublicKeyRegistry(new ObjectMapper(), new AccessTokenService(), temp.toString());
        first.load();
        var original=first.register(id,r,s,token);
        var restarted=new PublicKeyRegistry(new ObjectMapper(), new AccessTokenService(), temp.toString());
        restarted.load();
        assertEquals(original, restarted.find(id));
        assertTrue(restarted.authenticate(id, token));
        assertFalse(restarted.authenticate(id, new AccessTokenService().generate()));
        assertThrows(IllegalStateException.class, () -> restarted.register(id, r, s, new AccessTokenService().generate()));
    }
}
