package com.promptshield.detect;

import com.promptshield.domain.DetectorCategory;

import java.util.Optional;

/**
 * A pluggable detection strategy. Each detector inspects one {@link Segment} and
 * either reports a signal or stays silent. Detectors are stateless and pure;
 * severity is decided downstream by the scorer from the categories of whichever
 * detectors fired, so an individual detector never grades risk on its own.
 */
public interface Detector {

    /** Stable identifier, used in evidence, the report breakdown and tests. */
    String id();

    /** The role this detector's signal plays in scoring. */
    DetectorCategory category();

    /**
     * Inspect a segment.
     *
     * @return a result if this detector found something, otherwise empty
     */
    Optional<DetectorResult> inspect(Segment segment);
}
