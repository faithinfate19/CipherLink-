package com.cipherlink.cipherlink.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.cipherlink.cipherlink.service.AccessTokenService;
import com.cipherlink.cipherlink.service.FileTransferCryptoService;
import com.cipherlink.cipherlink.service.FileTransferCryptoService.SignedFilePackage;
import com.cipherlink.cipherlink.service.KeyService;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
class FileTransferControllerTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired FileTransferCryptoService crypto;
    private final KeyService keys = new KeyService();
    private final AccessTokenService tokens = new AccessTokenService();

    @Test void registersKeysVerifiesSignatureAndRoutesOnlyToRecipient() throws Exception {
        String senderId="alice-"+UUID.randomUUID(), recipientId="bob-"+UUID.randomUUID();
        String senderToken=tokens.generate(), recipientToken=tokens.generate();
        var senderRsa=keys.generateRSAKeyPair(); var senderSign=keys.generateSigningKeyPair();
        var recipientRsa=keys.generateRSAKeyPair(); var recipientSign=keys.generateSigningKeyPair();
        register(senderId, senderRsa, senderSign, senderToken);
        register(recipientId, recipientRsa, recipientSign, recipientToken);
        mvc.perform(get("/api/keys/{id}", senderId)).andExpect(status().isOk())
                .andExpect(jsonPath("$.rsaFingerprintSha256").exists());

        var pkg=crypto.encryptAndSign("private".getBytes(), "note.txt", senderId, recipientId,
                recipientRsa.getPublic(), senderSign.getPrivate());
        var request=mapper.createObjectNode().set("file", mapper.valueToTree(pkg));
        mvc.perform(post("/api/files/send").header("Authorization", "Bearer " + senderToken)
                        .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(request)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.file.signature").value(pkg.signature()));
        mvc.perform(get("/api/files/receive/{id}", recipientId).header("Authorization", "Bearer " + recipientToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].file.fileName").value("note.txt"));
        mvc.perform(get("/api/files/receive/{id}", senderId).header("Authorization", "Bearer " + senderToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$").isEmpty());

        mvc.perform(get("/api/files/receive/{id}", recipientId)).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/files/receive/{id}", recipientId).header("Authorization", "Bearer " + senderToken))
                .andExpect(status().isUnauthorized());
        SignedFilePackage tampered=new SignedFilePackage(pkg.fileName(), pkg.senderId(), pkg.recipientId(),
                pkg.wrappedAesKey(), pkg.nonce(), pkg.ciphertextAndTag(), Base64.getEncoder().encodeToString(new byte[64]));
        var bad=mapper.createObjectNode().set("file", mapper.valueToTree(tampered));
        mvc.perform(post("/api/files/send").header("Authorization", "Bearer " + senderToken)
                        .contentType(MediaType.APPLICATION_JSON).content(mapper.writeValueAsBytes(bad)))
                .andExpect(status().isBadRequest());
    }

    private void register(String id, java.security.KeyPair rsa, java.security.KeyPair ed, String token) throws Exception {
        var req=mapper.createObjectNode().put("userId", id)
                .put("rsaPublicKey", Base64.getEncoder().encodeToString(rsa.getPublic().getEncoded()))
                .put("signingPublicKey", Base64.getEncoder().encodeToString(ed.getPublic().getEncoded()))
                .put("accessToken", token);
        mvc.perform(post("/api/keys/register").contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsBytes(req)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.userId").value(id));
    }
}
