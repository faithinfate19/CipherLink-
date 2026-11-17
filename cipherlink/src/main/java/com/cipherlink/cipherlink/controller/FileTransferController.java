package com.cipherlink.cipherlink.controller;

import com.cipherlink.cipherlink.service.FileTransferCryptoService;
import com.cipherlink.cipherlink.service.FileTransferCryptoService.SignedFilePackage;
import com.cipherlink.cipherlink.service.PublicKeyRegistry;
import com.cipherlink.cipherlink.service.TransferMailbox;
import com.cipherlink.cipherlink.service.TransferMailbox.Transfer;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/files")
public class FileTransferController {
    private final PublicKeyRegistry registry;
    private final TransferMailbox mailbox;
    private final FileTransferCryptoService crypto;

    public FileTransferController(PublicKeyRegistry registry, TransferMailbox mailbox, FileTransferCryptoService crypto) {
        this.registry = registry; this.mailbox = mailbox; this.crypto = crypto;
    }

    /** Accepts ciphertext and signature only; requires the sender's bearer token. */
    @PostMapping(path="/send", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
    public Transfer send(@Valid @RequestBody SendRequest request,
            @RequestHeader(value="Authorization", required=false) String authorization) {
        SignedFilePackage file = request.file();
        if (!registry.authenticate(file.senderId(), bearerToken(authorization)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Valid sender bearer token required");
        var sender = registry.find(file.senderId());
        if (registry.find(file.recipientId()) == null)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Recipient must register public keys first");
        try {
            var signingKey = KeyFactory.getInstance("Ed25519").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(sender.signingPublicKey())));
            if (!crypto.verifySignature(file, signingKey))
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "File package signature is invalid");
            return mailbox.send(file);
        } catch (ResponseStatusException e) { throw e; }
        catch (IllegalArgumentException | GeneralSecurityException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid signed transfer package", e);
        }
    }

    /** Requires the matching recipient bearer token. */
    @GetMapping(path="/receive/{userId}", produces=MediaType.APPLICATION_JSON_VALUE)
    public List<Transfer> receive(@PathVariable String userId,
            @RequestHeader(value="Authorization", required=false) String authorization) {
        if (!registry.authenticate(userId, bearerToken(authorization)))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Valid recipient bearer token required");
        return mailbox.receive(userId);
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) return null;
        return authorization.substring(7).trim();
    }
    public record SendRequest(@NotNull @Valid SignedFilePackage file) { }
}
