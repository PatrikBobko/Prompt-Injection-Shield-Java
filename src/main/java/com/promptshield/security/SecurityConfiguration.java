package com.promptshield.security;

import com.promptshield.security.ratelimit.ClientKeyResolver;
import com.promptshield.security.ratelimit.ScanRateLimitFilter;
import com.promptshield.security.ratelimit.ScanRateLimiter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

/**
 * Keeps local development frictionless while making the production profile a
 * stateless OAuth2 resource server. The production setting is deliberately
 * explicit: {@code app.security.enabled=true} requires a valid JWT issuer.
 */
@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
public class SecurityConfiguration {

    private static final String[] PUBLIC_ENDPOINTS = {
            "/actuator/health/**", "/actuator/info", "/actuator/prometheus",
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/api/v1/health"
    };

    /** Local/test chain; Compose overrides this with the resource-server chain below. */
    @Bean
    @ConditionalOnProperty(name = "app.security.enabled", havingValue = "false", matchIfMissing = true)
    SecurityFilterChain localSecurityFilterChain(HttpSecurity http,
                                                  ScanRateLimiter scanRateLimiter,
                                                  ClientKeyResolver scanClientKeyResolver,
                                                  @Value("${app.rate-limit.enabled:true}") boolean rateLimitEnabled)
            throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());
        if (rateLimitEnabled) {
            // The local chain has no bearer authentication, so the resolver safely falls back to the peer address.
            http.addFilterBefore(new ScanRateLimitFilter(scanRateLimiter, scanClientKeyResolver), AuthorizationFilter.class);
        }
        return http.build();
    }

    /** Stateless OAuth2/JWT protection for a deployed instance. */
    @Bean
    @ConditionalOnProperty(name = "app.security.enabled", havingValue = "true")
    SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http,
                                                           JwtAuthenticationConverter keycloakJwtConverter,
                                                           ScanRateLimiter scanRateLimiter,
                                                           ClientKeyResolver scanClientKeyResolver,
                                                           @Value("${app.rate-limit.enabled:true}") boolean rateLimitEnabled)
            throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/scan").hasAnyRole("scan", "admin")
                        .requestMatchers("/api/v1/scans/**").hasAnyRole("scan", "admin")
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakJwtConverter)));
        if (rateLimitEnabled) {
            // JWT roles are now available, so authenticated callers receive their own quota.
            http.addFilterAfter(new ScanRateLimitFilter(scanRateLimiter, scanClientKeyResolver),
                    BearerTokenAuthenticationFilter.class);
        }
        return http.build();
    }

    @Bean
    JwtAuthenticationConverter keycloakJwtConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRealmRoleConverter());
        return converter;
    }
}
