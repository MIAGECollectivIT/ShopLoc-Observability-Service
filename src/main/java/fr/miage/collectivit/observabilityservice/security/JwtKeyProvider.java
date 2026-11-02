package fr.miage.collectivit.observabilityservice.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@SuppressWarnings("PMD.LawOfDemeter")
public class JwtKeyProvider {

  private static final Logger log = LoggerFactory.getLogger(JwtKeyProvider.class);
  private static final int MIN_KEY_BYTES = 32;
  private static final int MIN_RSA_KEY_LENGTH = 200;
  private static final int HTTP_OK = 200;
  private static final int TIMEOUT_SECONDS = 2;

  private final ObjectMapper objectMapper = new ObjectMapper();

  @Value("${application.security.jwt.public-key:}")
  private String publicKeyString;

  @Value("${application.security.jwt.secret-key:}")
  private String secretKeyString;

  @Value("${services.users.url:http://users-service:8080}")
  private String usersServiceUrl;

  private PublicKey rsaPublicKey;
  private SecretKey hmacSecretKey;

  @PostConstruct
  public void init() {
    if (publicKeyString != null && !publicKeyString.isBlank()) {
      parseRsaPublicKey(publicKeyString);
    }

    if (secretKeyString != null && !secretKeyString.isBlank()) {
      parseHmacSecretKey(secretKeyString);
    }

    if (this.rsaPublicKey == null && this.hmacSecretKey == null) {
      fetchPublicKeyFromUsersService();
    }
  }

  public PublicKey getRsaPublicKey() {
    return rsaPublicKey;
  }

  public SecretKey getHmacSecretKey() {
    return hmacSecretKey;
  }

  public synchronized void refreshKeys() {
    if (this.rsaPublicKey == null && this.hmacSecretKey == null) {
      fetchPublicKeyFromUsersService();
    }
  }

  private void parseRsaPublicKey(String rawKey) {
    try {
      String clean = cleanKeyPem(rawKey);
      byte[] decoded = Base64.getDecoder().decode(clean);
      if (decoded.length > MIN_RSA_KEY_LENGTH) {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.rsaPublicKey = kf.generatePublic(new X509EncodedKeySpec(decoded));
        if (log.isInfoEnabled()) {
          log.info("JWT Validator initialisé avec clé publique RSA asymétrique (RS256).");
        }
      }
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException ex) {
      if (log.isWarnEnabled()) {
        log.warn("Impossible d'initialiser la clé publique RSA : {}", ex.getMessage());
      }
    }
  }

  private void parseHmacSecretKey(String rawKey) {
    try {
      byte[] keyBytes;
      try {
        keyBytes = Base64.getDecoder().decode(rawKey.trim());
        if (keyBytes.length < MIN_KEY_BYTES) {
          keyBytes = rawKey.trim().getBytes(StandardCharsets.UTF_8);
        }
      } catch (IllegalArgumentException notBase64) {
        keyBytes = rawKey.trim().getBytes(StandardCharsets.UTF_8);
      }
      this.hmacSecretKey = Keys.hmacShaKeyFor(keyBytes);
      if (log.isInfoEnabled()) {
        log.info("JWT Validator initialisé avec support clé symétrique HMAC.");
      }
    } catch (IllegalArgumentException ex) {
      if (log.isWarnEnabled()) {
        log.warn("Impossible d'initialiser la clé HMAC : {}", ex.getMessage());
      }
    }
  }

  private synchronized void fetchPublicKeyFromUsersService() {
    if (usersServiceUrl == null || usersServiceUrl.isBlank()) {
      return;
    }
    String endpoint = usersServiceUrl.replaceAll("/+$", "") + "/v1/auth/public-key";
    try (HttpClient client =
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(TIMEOUT_SECONDS)).build()) {
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create(endpoint))
              .timeout(Duration.ofSeconds(TIMEOUT_SECONDS))
              .GET()
              .build();
      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() == HTTP_OK) {
        parseUsersServicePublicKeyResponse(response.body(), endpoint);
      }
    } catch (IOException | IllegalArgumentException e) {
      if (log.isDebugEnabled()) {
        log.debug(
            "Impossible de récupérer la clé publique depuis users-service au démarrage : {}",
            e.getMessage());
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      if (log.isDebugEnabled()) {
        log.debug(
            "Interruption lors de la récupération de la clé publique depuis users-service : {}",
            e.getMessage());
      }
    }
  }

  private void parseUsersServicePublicKeyResponse(String responseBody, String endpoint)
      throws IOException {
    JsonNode root = objectMapper.readTree(responseBody);
    if (root.has("publicKey")) {
      parseRsaPublicKey(root.get("publicKey").asText());
      if (log.isInfoEnabled()) {
        log.info("Clé publique RSA récupérée dynamiquement depuis {}", endpoint);
      }
    }
  }

  private String cleanKeyPem(String keyPem) {
    return keyPem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replaceAll("\\s+", "");
  }
}
