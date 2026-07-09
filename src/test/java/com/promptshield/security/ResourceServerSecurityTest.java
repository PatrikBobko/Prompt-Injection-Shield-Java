package com.promptshield.security;

import com.promptshield.audit.CurrentAuditSubject;
import com.promptshield.audit.service.AuditHistoryService;
import com.promptshield.domain.ContentType;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.SeverityCounts;
import com.promptshield.security.ratelimit.ClientKeyResolver;
import com.promptshield.security.ratelimit.ScanRateLimiter;
import com.promptshield.service.DetectionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = com.promptshield.api.ScanController.class, properties = {
        "app.security.enabled=true",
        "app.rate-limit.enabled=false"
})
@Import(SecurityConfiguration.class)
class ResourceServerSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DetectionService detectionService;

    @MockBean
    private AuditHistoryService auditHistoryService;

    @MockBean
    private CurrentAuditSubject currentAuditSubject;

    @MockBean
    private JwtDecoder jwtDecoder;

    // The production configuration still receives these collaborators even
    // when rate limiting itself is disabled for this focused security slice.
    @MockBean
    private ScanRateLimiter scanRateLimiter;

    @MockBean
    private ClientKeyResolver clientKeyResolver;

    @Test
    void rejectsUnauthenticatedScanRequests() throws Exception {
        mockMvc.perform(scanRequest())
                .andExpect(status().isUnauthorized());
    }

    @Test
    void permitsJwtWithKeycloakScanRole() throws Exception {
        when(jwtDecoder.decode("scan-token")).thenReturn(jwtWithRoles("scan"));
        when(detectionService.scan(any())).thenReturn(cleanReport());

        mockMvc.perform(scanRequest().header(HttpHeaders.AUTHORIZATION, "Bearer scan-token"))
                .andExpect(status().isOk());
    }

    @Test
    void rejectsJwtWithoutRequiredRole() throws Exception {
        when(jwtDecoder.decode("viewer-token")).thenReturn(jwtWithRoles());

        mockMvc.perform(scanRequest().header(HttpHeaders.AUTHORIZATION, "Bearer viewer-token"))
                .andExpect(status().isForbidden());
    }

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder scanRequest() {
        return post("/api/v1/scan")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"content\":\"a harmless sentence\",\"contentType\":\"TEXT\"}");
    }

    private static Jwt jwtWithRoles(String... roles) {
        Instant issuedAt = Instant.now();
        return Jwt.withTokenValue("test-token")
                .header("alg", "none")
                .subject("demo-subject")
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(300))
                .claim("realm_access", Map.of("roles", List.of(roles)))
                .claim("aud", List.of("promptshield-api"))
                .build();
    }

    private static RiskReport cleanReport() {
        return new RiskReport(
                ContentType.TEXT,
                1,
                null,
                0,
                new SeverityCounts(0, 0, 0, 0),
                List.of(),
                List.of());
    }
}
