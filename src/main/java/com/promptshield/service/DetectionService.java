package com.promptshield.service;

import com.promptshield.detect.Detector;
import com.promptshield.detect.DetectorResult;
import com.promptshield.detect.Segment;
import com.promptshield.domain.ContentType;
import com.promptshield.domain.DetectorCategory;
import com.promptshield.domain.DetectorSummary;
import com.promptshield.domain.Evidence;
import com.promptshield.domain.Finding;
import com.promptshield.domain.RiskReport;
import com.promptshield.domain.ScanRequest;
import com.promptshield.domain.Severity;
import com.promptshield.domain.SeverityCounts;
import com.promptshield.extract.HtmlSegmentExtractor;
import com.promptshield.scoring.RiskScorer;
import com.promptshield.scoring.SeverityScorer;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Orchestrates a scan: extract segments, run every detector over each, apply the
 * severity matrix and assemble a {@link RiskReport}. Mirrors the assembly the
 * extension's {@code scanner.js} did, but with detectors as injected strategies.
 */
@Service
public class DetectionService {

    private static final int SNIPPET_MAX = 140;
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    /** Reason ordering: hiding context first, then stego, then injection (as in scanner.js). */
    private static final List<DetectorCategory> REASON_ORDER =
            List.of(DetectorCategory.HIDING, DetectorCategory.STEGO, DetectorCategory.INJECTION);

    private final List<Detector> detectors;
    private final HtmlSegmentExtractor extractor;
    private final SeverityScorer severityScorer;
    private final RiskScorer riskScorer;

    public DetectionService(List<Detector> detectors,
                            HtmlSegmentExtractor extractor,
                            SeverityScorer severityScorer,
                            RiskScorer riskScorer) {
        this.detectors = List.copyOf(detectors);
        this.extractor = extractor;
        this.severityScorer = severityScorer;
        this.riskScorer = riskScorer;
    }

    public RiskReport scan(ScanRequest request) {
        ContentType type = request.contentTypeOrDefault();
        List<Segment> segments = switch (type) {
            case HTML -> extractor.extract(request.content());
            case TEXT -> List.of(Segment.plainText(request.content()));
        };

        List<Finding> findings = new ArrayList<>();
        int findingId = 0;
        for (Segment segment : segments) {
            List<DetectorResult> results = new ArrayList<>();
            for (Detector detector : detectors) {
                detector.inspect(segment).ifPresent(results::add);
            }
            if (results.isEmpty()) {
                continue;
            }
            boolean hidden = hasCategory(results, DetectorCategory.HIDING);
            boolean injection = hasCategory(results, DetectorCategory.INJECTION);
            boolean stego = hasCategory(results, DetectorCategory.STEGO);

            Optional<Severity> severity = severityScorer.score(hidden, injection, stego);
            if (severity.isEmpty()) {
                continue;
            }
            findings.add(buildFinding(findingId++, segment, results, severity.get()));
        }

        SeverityCounts counts = SeverityCounts.from(findings);
        return new RiskReport(
                type,
                segments.size(),
                riskScorer.overall(counts),
                riskScorer.score(counts),
                counts,
                breakdown(findings),
                findings);
    }

    private Finding buildFinding(int id, Segment segment, List<DetectorResult> results, Severity severity) {
        List<String> reasons = new ArrayList<>();
        List<Evidence> evidence = new ArrayList<>();
        List<String> detectorIds = new ArrayList<>();

        for (DetectorCategory category : REASON_ORDER) {
            for (DetectorResult result : results) {
                if (result.category() == category) {
                    reasons.addAll(result.reasons());
                    evidence.addAll(result.evidence());
                    if (!detectorIds.contains(result.detectorId())) {
                        detectorIds.add(result.detectorId());
                    }
                }
            }
        }

        return new Finding(id, severity, segment.channel(), segment.locator(),
                snippet(segment.text(), evidence), reasons, detectorIds, evidence);
    }

    /** Whitespace-collapsed excerpt capped at 140 chars, with any decoded Tags payload appended. */
    private String snippet(String text, List<Evidence> evidence) {
        String collapsed = WHITESPACE.matcher(text == null ? "" : text.strip()).replaceAll(" ");
        String snippet = collapsed.length() > SNIPPET_MAX ? collapsed.substring(0, SNIPPET_MAX) : collapsed;
        String decoded = decodedTags(evidence);
        if (decoded != null) {
            snippet += "  [decoded tags: \"" + decoded + "\"]";
        }
        return snippet;
    }

    private static String decodedTags(List<Evidence> evidence) {
        return evidence.stream()
                .filter(e -> "tags-payload".equals(e.kind()) && e.decoded() != null)
                .map(Evidence::decoded)
                .findFirst()
                .orElse(null);
    }

    private List<DetectorSummary> breakdown(List<Finding> findings) {
        Map<String, Integer> counts = new HashMap<>();
        for (Finding finding : findings) {
            for (String detectorId : finding.detectors()) {
                counts.merge(detectorId, 1, Integer::sum);
            }
        }
        List<DetectorSummary> breakdown = new ArrayList<>();
        for (Detector detector : detectors) {
            int count = counts.getOrDefault(detector.id(), 0);
            if (count > 0) {
                breakdown.add(new DetectorSummary(detector.id(), detector.category(), count));
            }
        }
        breakdown.sort(Comparator
                .comparingInt((DetectorSummary s) -> s.category().ordinal())
                .thenComparing(DetectorSummary::detectorId));
        return breakdown;
    }

    private static boolean hasCategory(List<DetectorResult> results, DetectorCategory category) {
        return results.stream().anyMatch(r -> r.category() == category);
    }
}
