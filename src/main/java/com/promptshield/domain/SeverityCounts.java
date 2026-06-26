package com.promptshield.domain;

import java.util.List;

/**
 * Per-severity tally of findings, mirroring the extension's {@code summarize()}.
 */
public record SeverityCounts(int high, int medium, int low, int total) {

    public static SeverityCounts from(List<Finding> findings) {
        int high = 0;
        int medium = 0;
        int low = 0;
        for (Finding f : findings) {
            switch (f.severity()) {
                case HIGH -> high++;
                case MEDIUM -> medium++;
                case LOW -> low++;
            }
        }
        return new SeverityCounts(high, medium, low, high + medium + low);
    }
}
