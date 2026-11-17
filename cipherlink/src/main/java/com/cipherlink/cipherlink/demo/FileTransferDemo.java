package com.cipherlink.cipherlink.demo;

import com.cipherlink.cipherlink.service.AesGcmService;
import com.cipherlink.cipherlink.service.AccessTokenService;
import com.cipherlink.cipherlink.service.FileTransferCryptoService;
import com.cipherlink.cipherlink.service.FileTransferCryptoService.SignedFilePackage;
import com.cipherlink.cipherlink.service.KeyService;
import com.cipherlink.cipherlink.service.RsaOaepService;
import com.cipherlink.cipherlink.service.SignatureService;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

/** Runs a complete local Alice-to-Bob encrypted transfer against the running API. */
public class FileTransferDemo {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    public static void main(String[] args) throws Exception {
        String baseUrl = (args.length > 0 ? args[0] : "http://localhost:8080").replaceAll("/$", "");
        Path input = args.length > 1 ? Path.of(args[1]) : null;
        String fileName = input == null ? "hello-cipherlink.txt" : input.getFileName().toString();
        byte[] plaintext = input == null
                ? "Hello Bob — this file was encrypted and signed on Alice's device.".getBytes(StandardCharsets.UTF_8)
                : Files.readAllBytes(input);

        KeyService keyService = new KeyService();
        KeyPair aliceRsa = keyService.generateRSAKeyPair();
        KeyPair aliceEd = keyService.generateSigningKeyPair();
        KeyPair bobRsa = keyService.generateRSAKeyPair();
        KeyPair bobEd = keyService.generateSigningKeyPair();
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String aliceId = "alice-" + suffix;
        String bobId = "bob-" + suffix;
        AccessTokenService tokenService = new AccessTokenService();
        String aliceToken = tokenService.generate();
        String bobToken = tokenService.generate();

        ObjectNode aliceRegistration = registration(aliceId, aliceRsa, aliceEd, aliceToken);
        ObjectNode bobRegistration = registration(bobId, bobRsa, bobEd, bobToken);
        JsonNode aliceIdentity = request(baseUrl, "POST", "/api/keys/register", aliceRegistration);
        JsonNode bobIdentity = request(baseUrl, "POST", "/api/keys/register", bobRegistration);

        FileTransferCryptoService crypto = new FileTransferCryptoService(
                new AesGcmService(), new RsaOaepService(), new SignatureService());
        SignedFilePackage file = crypto.encryptAndSign(plaintext, fileName, aliceId, bobId,
                bobRsa.getPublic(), aliceEd.getPrivate());
        ObjectNode sendBody = JSON.createObjectNode().set("file", JSON.valueToTree(file));
        JsonNode queued = request(baseUrl, "POST", "/api/files/send", sendBody, aliceToken);
        JsonNode inbox = request(baseUrl, "GET", "/api/files/receive/" + bobId, null, bobToken);
        if (!inbox.isArray() || inbox.isEmpty()) throw new IllegalStateException("Bob's inbox did not contain the sent file");
        SignedFilePackage receivedPackage = JSON.treeToValue(inbox.get(0).get("file"), SignedFilePackage.class);

        // Fetch Alice's public signing key from the API, then compare it with the key generated locally.
        JsonNode publishedAlice = request(baseUrl, "GET", "/api/keys/" + aliceId, null);
        String trustedPublic = Base64.getEncoder().encodeToString(aliceEd.getPublic().getEncoded());
        if (!trustedPublic.equals(publishedAlice.get("signingPublicKey").asString()))
            throw new SecurityException("Alice's registered signing key did not match the locally generated key");
        var senderSigningKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(
                Base64.getDecoder().decode(publishedAlice.get("signingPublicKey").asString())));
        byte[] restored = crypto.verifyAndDecrypt(receivedPackage, senderSigningKey, bobRsa.getPrivate());
        Path output = Path.of("target", "cipherlink-demo-received-" + suffix + "-" + fileName);
        Files.createDirectories(output.getParent());
        Files.write(output, restored);

        ObjectNode environment = postmanEnvironment(baseUrl, aliceRegistration, bobRegistration, sendBody);
        Path environmentFile = Path.of("target", "CipherLink-Demo.postman_environment.json");
        Files.writeString(environmentFile, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(environment));

        System.out.println("Transfer succeeded and Bob verified Alice's signature before decrypting.");
        System.out.println("Alice: " + aliceId + " (fingerprint " + aliceIdentity.get("signingFingerprintSha256").asString() + ")");
        System.out.println("Bob:   " + bobId + " (fingerprint " + bobIdentity.get("signingFingerprintSha256").asString() + ")");
        System.out.println("Transfer ID: " + queued.get("id").asString());
        System.out.println("Decrypted file: " + output.toAbsolutePath());
        System.out.println("Postman environment: " + environmentFile.toAbsolutePath());
        System.out.println("Import postman/CipherLink.postman_collection.json and the environment above to inspect the API calls.");
    }

    private static ObjectNode registration(String userId, KeyPair rsa, KeyPair ed, String accessToken) {
        return JSON.createObjectNode().put("userId", userId)
                .put("rsaPublicKey", Base64.getEncoder().encodeToString(rsa.getPublic().getEncoded()))
                .put("signingPublicKey", Base64.getEncoder().encodeToString(ed.getPublic().getEncoded()))
                .put("accessToken", accessToken);
    }

    private static JsonNode request(String baseUrl, String method, String path, JsonNode body) throws Exception {
        return request(baseUrl, method, path, body, null);
    }

    private static JsonNode request(String baseUrl, String method, String path, JsonNode body, String accessToken) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Accept", "application/json");
        if (accessToken != null) builder.header("Authorization", "Bearer " + accessToken);
        if (body == null) builder.GET();
        else builder.header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
        HttpResponse<String> response = HTTP.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300)
            throw new IllegalStateException(method + " " + path + " returned HTTP " + response.statusCode() + ": " + response.body());
        return JSON.readTree(response.body());
    }

    private static ObjectNode postmanEnvironment(String baseUrl, ObjectNode alice, ObjectNode bob, ObjectNode sendBody) throws Exception {
        ObjectNode env = JSON.createObjectNode();
        env.put("id", UUID.randomUUID().toString());
        env.put("name", "CipherLink local demo");
        env.put("_postman_variable_scope", "environment");
        env.put("_postman_exported_at", Instant.now().toString());
        env.put("_postman_exported_using", "CipherLink file transfer demo");
        var values = env.putArray("values");
        add(values, "baseUrl", baseUrl);
        add(values, "senderId", alice.get("userId").asString());
        add(values, "senderRsaPublicKey", alice.get("rsaPublicKey").asString());
        add(values, "senderSigningPublicKey", alice.get("signingPublicKey").asString());
        add(values, "recipientId", bob.get("userId").asString());
        add(values, "recipientRsaPublicKey", bob.get("rsaPublicKey").asString());
        add(values, "recipientSigningPublicKey", bob.get("signingPublicKey").asString());
        add(values, "sendBody", JSON.writeValueAsString(sendBody));
        env.put("_postman_isSubmitted", false);
        return env;
    }

    private static void add(tools.jackson.databind.node.ArrayNode values, String key, String value) {
        ObjectNode item = values.addObject();
        item.put("key", key); item.put("value", value); item.put("type", "default"); item.put("enabled", true);
    }
}
