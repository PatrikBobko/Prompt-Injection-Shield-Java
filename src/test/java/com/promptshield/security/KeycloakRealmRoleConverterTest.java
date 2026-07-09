package com.promptshield.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class KeycloakRealmRoleConverterTest {

    private final KeycloakRealmRoleConverter converter = new KeycloakRealmRoleConverter();

    @Test
    void mapsKeycloakRealmRolesToSpringRoleAuthorities() {
        Jwt jwt = jwt(Map.of("roles", List.of("scan", "admin")));

        assertThat(converter.convert(jwt))
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_scan", "ROLE_admin");
    }

    @Test
    void ignoresTokensWithoutRealmRoles() {
        assertThat(converter.convert(jwt(null))).isEmpty();
    }

    private static Jwt jwt(Map<String, Object> realmAccess) {
        Instant now = Instant.now();
        Jwt.Builder builder = Jwt.withTokenValue("test-token")
                .header("alg", "none")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(60));
        if (realmAccess != null) {
            builder.claim("realm_access", realmAccess);
        }
        return builder.build();
    }
}
