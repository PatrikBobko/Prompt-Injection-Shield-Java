package com.promptshield.detect.channel;

import com.promptshield.detect.Detector;
import com.promptshield.detect.DetectorResult;
import com.promptshield.detect.Segment;
import com.promptshield.domain.DetectorCategory;
import com.promptshield.domain.Evidence;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

/**
 * Flags text that arrives through a non-rendered channel: HTML comments,
 * instruction-bearing attributes, {@code <meta>} content, hidden inputs. A human
 * reading the page never sees these, but an LLM ingesting the raw HTML does.
 *
 * <p>This is a {@link DetectorCategory#HIDING} detector and mirrors the scanner's
 * {@code "hidden channel: ..."} reason. Like the visibility detector it only
 * amplifies; channel membership alone is never a finding.
 */
@Component
public class HiddenChannelDetector implements Detector {

    public static final String ID = "hidden-channel";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public DetectorCategory category() {
        return DetectorCategory.HIDING;
    }

    @Override
    public Optional<DetectorResult> inspect(Segment segment) {
        if (!segment.channel().isHidden()) {
            return Optional.empty();
        }
        String reason = "hidden channel: " + segment.channelLabel();
        return Optional.of(new DetectorResult(
                ID,
                DetectorCategory.HIDING,
                List.of(reason),
                List.of(Evidence.note("hidden-channel", segment.channelLabel()))));
    }
}
