package com.cipherlink.cipherlink.controller;

import com.cipherlink.cipherlink.service.PublicKeyRegistry;
import com.cipherlink.cipherlink.service.PublicKeyRegistry.PublicIdentity;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.security.GeneralSecurityException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/keys")
public class KeyController {
    private final PublicKeyRegistry registry;
    public KeyController(PublicKeyRegistry registry) { this.registry = registry; }

    @PostMapping(path="/register", consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
    public PublicIdentity register(@Valid @RequestBody RegisterKeysRequest request) {
        try { return registry.register(request.userId(), request.rsaPublicKey(), request.signingPublicKey(), request.accessToken()); }
        catch (IllegalStateException e) { throw new ResponseStatusException(HttpStatus.CONFLICT, e.getMessage(), e); }
        catch (IllegalArgumentException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e); }
        catch (GeneralSecurityException e) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid public key encoding", e); }
    }

    @GetMapping(path="/{userId}", produces=MediaType.APPLICATION_JSON_VALUE)
    public PublicIdentity get(@PathVariable String userId) {
        PublicIdentity identity = registry.find(userId);
        if (identity == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "User is not registered");
        return identity;
    }

    public record RegisterKeysRequest(@NotBlank @Size(max=100) String userId,
            @NotBlank @Size(max=8192) String rsaPublicKey,
            @NotBlank @Size(max=8192) String signingPublicKey,
            @NotBlank @Size(min=43, max=43) String accessToken) { }
}
