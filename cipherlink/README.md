# CipherLink

Secure file-transfer API using AES-128-GCM, RSA-OAEP (SHA-256), and Ed25519 signatures.

## Security design

- Generate one random AES-128 key and a fresh 96-bit nonce for each file.
- Encrypt file bytes locally with AES-GCM and a 128-bit authentication tag.
- Wrap the AES key to the receiver's RSA-3072 public key with RSA-OAEP using SHA-256 for both OAEP and MGF1.
- Sign a versioned, length-prefixed representation of the filename, sender, recipient, wrapped key, nonce, and ciphertext with the sender's Ed25519 private key.
- Verify the signature before decrypting. GCM verifies ciphertext integrity before returning plaintext.
- Send only the signed encrypted package to `/api/files/send`. Private keys and plaintext do not go to the API.
- Register RSA and Ed25519 public keys at `/api/keys/register`; the API returns SHA-256 fingerprints. Compare those fingerprints over an independent trusted channel before relying on a key.

`EncryptedKeyStore` stores both private key pairs locally in a password-protected AES-GCM file. It derives an AES-128 key with PBKDF2-HMAC-SHA-256 (600,000 iterations), uses a random salt and nonce, and refuses to overwrite an existing key file.

## Run

Requires Java 21. From the `cipherlink` folder:

```powershell
.\mvnw.cmd test
.\mvnw.cmd spring-boot:run
```

The service listens on `http://localhost:8080`.

## Try a complete transfer

Use two PowerShell terminals from the `cipherlink` folder.

Terminal 1 starts the API:

```powershell
.\mvnw.cmd spring-boot:run
```

Terminal 2 runs the sample Alice-to-Bob transfer:

```powershell
.\mvnw.cmd -q "-Dspring-boot.run.main-class=com.cipherlink.cipherlink.demo.FileTransferDemo" spring-boot:run
```

The demo creates throwaway RSA and Ed25519 key pairs, registers only the public keys, encrypts and signs a sample file locally, uploads the package, downloads it as Bob, verifies Alice's signature, decrypts locally, and writes the recovered file under `target/`. Pass a custom file with the optional second argument by adding `-Dspring-boot.run.arguments="http://localhost:8080 C:\path\to\file"`.

To inspect the API in Postman, import `postman/CipherLink.postman_collection.json` and the environment file generated at `target/CipherLink-Demo.postman_environment.json`. The environment contains demo public keys and a signed ciphertext package; it contains no private keys or plaintext.
## Run in Docker

Requires Docker Desktop or Docker Engine with Compose. From the `cipherlink` folder:

```powershell
docker compose up --build
```

The API is available at `http://localhost:8080`; Compose keeps JSON registry and transfer data in the `cipherlink-data` volume. To use another local port, set `CIPHERLINK_PORT`, for example `$env:CIPHERLINK_PORT=8081` before starting Compose. Stop with `Ctrl+C`; run `docker compose down` to remove the container while keeping its data volume.

This prepares a portable container for a VPS or container host. It does not publish a public URL by itself: the host account, DNS/TLS, firewall rules, and persistent storage still need to be configured.
## API

### Register public keys

`POST /api/keys/register`

```json
{
  "userId": "alice",
  "rsaPublicKey": "<Base64 X.509 RSA public key>",
  "signingPublicKey": "<Base64 X.509 Ed25519 public key>",
  "accessToken": "<43-character random Base64URL token>"
}
```

`GET /api/keys/{userId}` returns both public keys and their SHA-256 fingerprints. A registered identity cannot silently replace its keys.

### Send a transfer

The sender uses `FileTransferCryptoService.encryptAndSign(...)` on the sender device, then posts the returned JSON package:

`POST /api/files/send`

```json
{
  "file": {
    "fileName": "report.pdf",
    "senderId": "alice",
    "recipientId": "bob",
    "wrappedAesKey": "<Base64>",
    "nonce": "<Base64>",
    "ciphertextAndTag": "<Base64>",
    "signature": "<Base64 Ed25519 signature>"
  }
}
```

The server verifies the signature against Alice's registered signing key before queueing the package. Send requires `Authorization: Bearer <sender access token>`. `GET /api/files/receive/{userId}` also requires the matching recipient token. The recipient fetches the sender's registered signing key, checks its fingerprint against the independently trusted fingerprint, then calls `verifyAndDecrypt(...)` locally with their private RSA key.

The old `/api/messages/encrypt` plaintext endpoint returns `410 Gone`; use client-side encryption and signing instead.

## Current deployment boundary

This is a working learning-project MVP. The public-key registry and signed encrypted mailbox are persisted as JSON files under `cipherlink.data-dir` (default `./data`); set `CIPHERLINK_DATA_DIR` to choose another location. File sending and inbox retrieval require per-user high-entropy bearer tokens. Public-key registration is open for self-registration, and public keys are public. It is intended for local development; it still needs production account verification, rate and size limits, TLS, and operational monitoring before public exposure. Production deployment still needs authenticated accounts, authorization bound to the authenticated identity, PostgreSQL/object storage, rate and size limits, key recovery/rotation policy, TLS, and operational monitoring. Fingerprints must be trusted out of band to prevent first-registration key substitution.
