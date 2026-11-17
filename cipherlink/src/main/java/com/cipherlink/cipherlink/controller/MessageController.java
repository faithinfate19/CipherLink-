package com.cipherlink.cipherlink.controller;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Plaintext encryption was removed from the server API; clients encrypt and sign before upload. */
@RestController
@RequestMapping("/api/messages")
public class MessageController {
    @PostMapping("/encrypt")
    public void encryptionMustRunOnClient() {
        throw new ResponseStatusException(HttpStatus.GONE,
                "Encrypt and sign on the sender device; submit the signed ciphertext to /api/files/send");
    }
}
