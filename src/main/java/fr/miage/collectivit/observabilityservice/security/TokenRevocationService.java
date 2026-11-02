package fr.miage.collectivit.observabilityservice.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@SuppressWarnings("PMD.LawOfDemeter")
public class TokenRevocationService {

  private static final Logger log = LoggerFactory.getLogger(TokenRevocationService.class);
  private static final long REVOCATION_CACHE_TTL_MS = 15_000L;
  private static final int HTTP_OK = 200;
  private static final int TIMEOUT_SECONDS = 2;

  private final ObjectMapper objectMapper = new ObjectMapper();
  private final Set<String> cachedRevokedJtis =
      Collections.newSetFromMap(new ConcurrentHashMap<>());

  @Value("${services.users.url:http://users-service:8080}")
  private String usersServiceUrl;

  private volatile long lastRevocationFetchTime;

  public boolean isRevoked(String jti) {
    long now = System.currentTimeMillis();
    if (now - lastRevocationFetchTime > REVOCATION_CACHE_TTL_MS) {
      refreshRevokedTokens();
    }
    return cachedRevokedJtis.contains(jti);
  }

  public synchronized void refreshRevokedTokens() {
    if (usersServiceUrl == null || usersServiceUrl.isBlank()) {
      return;
    }
    lastRevocationFetchTime = System.currentTimeMillis();
    fetchRevokedTokensFromService();
  }

  private void fetchRevokedTokensFromService() {
    String endpoint = usersServiceUrl.replaceAll("/+$", "") + "/v1/auth/revoked-tokens";
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
        processRevokedTokensResponse(response.body());
      }
    } catch (IOException | IllegalArgumentException ex) {
      if (log.isDebugEnabled()) {
        log.debug("Impossible de rafraîchir la liste des jetons révoqués : {}", ex.getMessage());
      }
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      if (log.isDebugEnabled()) {
        log.debug(
            "Interruption lors du rafraîchissement des jetons révoqués : {}", ex.getMessage());
      }
    }
  }

  private void processRevokedTokensResponse(String responseBody) throws IOException {
    Set<String> newRevoked = new HashSet<>();
    JsonNode root = objectMapper.readTree(responseBody);
    if (root.isArray()) {
      for (JsonNode item : root) {
        newRevoked.add(item.asText());
      }
    }
    cachedRevokedJtis.clear();
    cachedRevokedJtis.addAll(newRevoked);
    if (log.isDebugEnabled()) {
      log.debug(
          "Liste des jetons révoqués rafraîchie : {} jetons actifs.", cachedRevokedJtis.size());
    }
  }

  public void addRevokedJtiForTest(String jti) {
    cachedRevokedJtis.add(jti);
  }
}
