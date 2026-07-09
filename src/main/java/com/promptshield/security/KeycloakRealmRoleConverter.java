package com.promptshield.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Maps Keycloak's {@code realm_access.roles} claim to Spring {@code ROLE_*} authorities. */
final class KeycloakRealmRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Objects.requireNonNull(jwt, "jwt must not be null");
        Object realmAccess = jwt.getClaim("realm_access");
        if (!(realmAccess instanceof Map<?, ?> claims)) {
            return Set.of();
        }
        Object rawRoles = claims.get("roles");
        if (!(rawRoles instanceof Collection<?> roles)) {
            return Set.of();
        }

        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        for (Object rawRole : roles) {
            if (rawRole instanceof String role && !role.isBlank()) {
                authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        }
        return Set.copyOf(authorities);
    }
}
