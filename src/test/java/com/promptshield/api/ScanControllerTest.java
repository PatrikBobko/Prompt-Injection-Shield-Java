package com.promptshield.api;

import com.promptshield.audit.CurrentAuditSubject;
import com.promptshield.audit.service.AuditHistoryService;
import com.promptshield.domain.ContentType;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.Severity;
import com.promptshield.domain.SeverityCounts;
import com.promptshield.config.OperationalConfiguration;
import com.promptshield.security.SecurityConfiguration;
import com.promptshield.service.DetectionService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ScanController.class)
@Import({SecurityConfiguration.class, OperationalConfiguration.class})
class ScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DetectionService detectionService;

    @MockBean
    private AuditHistoryService auditHistoryService;

    @MockBean
    private CurrentAuditSubject currentAuditSubject;

    @Test
    void scanReturnsReport() throws Exception {
        RiskReport report = new RiskReport(ContentType.HTML, 1, Severity.HIGH, 40,
                new SeverityCounts(1, 0, 0, 1), List.of(), List.of());
        when(detectionService.scan(any())).thenReturn(report);

        mockMvc.perform(post("/api/v1/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"<p>hi there friend</p>\",\"contentType\":\"HTML\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.overallSeverity").value("HIGH"))
                .andExpect(jsonPath("$.riskScore").value(40));
    }

    @Test
    void blankContentIsRejected() throws Exception {
        mockMvc.perform(post("/api/v1/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"content\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("validation failed"));
    }

    @Test
    void malformedJsonIsRejected() throws Exception {
        mockMvc.perform(post("/api/v1/scan")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("malformed request body"));
    }

    @Test
    void healthReportsUp() throws Exception {
        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}
