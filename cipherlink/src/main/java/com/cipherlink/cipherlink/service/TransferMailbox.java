package com.cipherlink.cipherlink.service;

import com.cipherlink.cipherlink.service.FileTransferCryptoService.SignedFilePackage;
import com.cipherlink.cipherlink.service.PublicKeyRegistry;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Durable mailbox stores signed ciphertext only, never plaintext or private keys. */
@Service
public class TransferMailbox {
    private final Map<String, Transfer> transfers = new ConcurrentHashMap<>();
    private final Path file;
    private final ObjectMapper mapper;

    public TransferMailbox(ObjectMapper mapper, @Value("${cipherlink.data-dir:./data}") String dataDir) {
        this.mapper = mapper;
        this.file = Path.of(dataDir).resolve("transfers.json");
    }

    @PostConstruct
    void load() throws IOException {
        if (Files.exists(file)) transfers.putAll(mapper.readValue(file.toFile(), new TypeReference<Map<String, Transfer>>() {}));
    }

    public synchronized Transfer send(SignedFilePackage file) {
        Transfer transfer = new Transfer(UUID.randomUUID().toString(), file, Instant.now());
        transfers.put(transfer.id(), transfer);
        try { PublicKeyRegistry.writeAtomically(this.file, mapper.writeValueAsBytes(transfers)); }
        catch (IOException e) { transfers.remove(transfer.id()); throw new IllegalStateException("Could not persist transfer mailbox", e); }
        return transfer;
    }
    public List<Transfer> receive(String userId) {
        return transfers.values().stream().filter(t -> t.file().recipientId().equals(userId))
                .sorted((a,b) -> a.createdAt().compareTo(b.createdAt())).toList();
    }
    public record Transfer(String id, SignedFilePackage file, Instant createdAt) { }
}
