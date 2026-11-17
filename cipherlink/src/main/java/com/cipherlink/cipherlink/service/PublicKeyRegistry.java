package com.cipherlink.cipherlink.service;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Stores public keys and a digest of each high-entropy bearer token; token plaintext is never persisted. */
@Service
public class PublicKeyRegistry {
    private final Map<String, UserRecord> users = new ConcurrentHashMap<>();
    private final Path file;
    private final ObjectMapper mapper;
    private final AccessTokenService tokens;

    public PublicKeyRegistry(ObjectMapper mapper, AccessTokenService tokens,
            @Value("${cipherlink.data-dir:./data}") String dataDir) {
        this.mapper = mapper; this.tokens = tokens;
        this.file = Path.of(dataDir).resolve("public-keys.json");
    }

    @PostConstruct
    void load() throws IOException {
        if (!Files.exists(file)) return;
        JsonNode root = mapper.readTree(Files.readAllBytes(file));
        Iterator<Map.Entry<String, JsonNode>> fields = root.properties().iterator();
        while (fields.hasNext()) {
            var entry = fields.next();
            if (entry.getValue().has("identity")) {
                users.put(entry.getKey(), mapper.treeToValue(entry.getValue(), UserRecord.class));
            } else {
                // Read the pre-token JSON shape so existing local public-key data remains visible.
                PublicIdentity legacy = mapper.treeToValue(entry.getValue(), PublicIdentity.class);
                users.put(entry.getKey(), new UserRecord(legacy, null));
            }
        }
    }

    public synchronized PublicIdentity register(String userId, String rsa, String ed25519, String accessToken)
            throws GeneralSecurityException {
        if (userId == null || userId.isBlank() || userId.length() > 100) throw new IllegalArgumentException("userId must contain 1 to 100 characters");
        String tokenHash = tokens.hash(accessToken);
        var rsaKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(rsa)));
        if (!(rsaKey instanceof RSAPublicKey r) || r.getModulus().bitLength() < 3072) throw new IllegalArgumentException("RSA public key must be at least 3072 bits");
        var signKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(ed25519)));
        if (!"EdDSA".equalsIgnoreCase(signKey.getAlgorithm()) && !"Ed25519".equalsIgnoreCase(signKey.getAlgorithm())) throw new IllegalArgumentException("Signing key must be Ed25519");
        PublicIdentity identity = new PublicIdentity(userId, rsa, ed25519, fingerprint(rsaKey.getEncoded()), fingerprint(signKey.getEncoded()));
        UserRecord existing = users.get(userId);
        if (existing != null) {
            if (!existing.identity().equals(identity)) throw new IllegalStateException("User already registered; key replacement requires a separate recovery process");
            if (existing.accessTokenHash() == null) throw new IllegalStateException("Legacy account requires administrator recovery before token authentication");
            if (!tokens.matches(accessToken, existing.accessTokenHash())) throw new IllegalStateException("Incorrect access token for this user");
            return identity;
        }
        users.put(userId, new UserRecord(identity, tokenHash));
        persist();
        return identity;
    }

    public PublicIdentity find(String userId) { UserRecord record = users.get(userId); return record == null ? null : record.identity(); }
    public boolean authenticate(String userId, String accessToken) {
        UserRecord record = users.get(userId);
        return record != null && tokens.matches(accessToken, record.accessTokenHash());
    }
    private static String fingerprint(byte[] key) throws GeneralSecurityException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key));
    }
    private void persist() {
        try { writeAtomically(file, mapper.writeValueAsBytes(users)); }
        catch (IOException e) { throw new IllegalStateException("Could not persist public key registry", e); }
    }
    static void writeAtomically(Path destination, byte[] bytes) throws IOException {
        Files.createDirectories(destination.getParent());
        Path temp = destination.resolveSibling(destination.getFileName() + ".tmp");
        try {
            Files.write(temp, bytes);
            try { Files.move(temp, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
            catch (java.nio.file.AtomicMoveNotSupportedException e) { Files.move(temp, destination, StandardCopyOption.REPLACE_EXISTING); }
        } finally { Files.deleteIfExists(temp); }
    }
    private record UserRecord(PublicIdentity identity, String accessTokenHash) { }
    public record PublicIdentity(String userId, String rsaPublicKey, String signingPublicKey,
            String rsaFingerprintSha256, String signingFingerprintSha256) { }
}
