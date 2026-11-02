package fr.miage.collectivit.observabilityservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.PublicKey;
import java.util.Optional;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@SuppressWarnings("PMD.LawOfDemeter")
public class JwtValidatorService {

  private final JwtKeyProvider jwtKeyProvider;
  private final TokenRevocationService tokenRevocationService;

  public Claims validateAndExtractClaims(String token) {
    Claims claims = parseToken(token);
    verifyNotRevoked(claims);
    return claims;
  }

  private Claims parseToken(String token) {
    PublicKey rsaPublicKey = jwtKeyProvider.getRsaPublicKey();
    SecretKey hmacSecretKey = jwtKeyProvider.getHmacSecretKey();

    if (rsaPublicKey == null && hmacSecretKey == null) {
      jwtKeyProvider.refreshKeys();
      rsaPublicKey = jwtKeyProvider.getRsaPublicKey();
      hmacSecretKey = jwtKeyProvider.getHmacSecretKey();
    }

    Optional<Claims> rsaClaims = tryParseWithRsa(token, rsaPublicKey, hmacSecretKey != null);
    if (rsaClaims.isPresent()) {
      return rsaClaims.get();
    }

    return tryParseWithHmac(token, hmacSecretKey);
  }

  private Optional<Claims> tryParseWithRsa(
      String token, PublicKey rsaPublicKey, boolean hasHmacFallback) {
    if (rsaPublicKey == null) {
      return Optional.empty();
    }
    try {
      return Optional.of(
          Jwts.parser().verifyWith(rsaPublicKey).build().parseSignedClaims(token).getPayload());
    } catch (JwtException | IllegalArgumentException ex) {
      if (hasHmacFallback) {
        return Optional.empty();
      }
      throw new SecurityException("Jeton JWT invalide ou expiré : " + ex.getMessage(), ex);
    }
  }

  private Claims tryParseWithHmac(String token, SecretKey hmacSecretKey) {
    if (hmacSecretKey == null) {
      throw new SecurityException("Aucune clé de validation JWT disponible.");
    }
    try {
      return Jwts.parser().verifyWith(hmacSecretKey).build().parseSignedClaims(token).getPayload();
    } catch (JwtException | IllegalArgumentException ex) {
      throw new SecurityException("Jeton JWT invalide ou expiré : " + ex.getMessage(), ex);
    }
  }

  private void verifyNotRevoked(Claims claims) {
    String jti = claims.getId();
    if (jti != null && tokenRevocationService.isRevoked(jti)) {
      throw new SecurityException("Jeton JWT révoqué. Veuillez vous reconnecter.");
    }
  }

  public String extractRole(Claims claims) {
    String role = claims.get("role", String.class);
    if (role == null) {
      role = claims.get("userRole", String.class);
    }
    return role != null ? role.trim() : "";
  }

  public void addRevokedJtiForTest(String jti) {
    tokenRevocationService.addRevokedJtiForTest(jti);
  }

  public void refreshRevokedTokens() {
    tokenRevocationService.refreshRevokedTokens();
  }
}
