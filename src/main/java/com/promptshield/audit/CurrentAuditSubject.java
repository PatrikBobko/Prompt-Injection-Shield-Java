package com.promptshield.audit;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/** Resolves a stable, bounded subject for tenant-scoped audit history. */
@Component
public class CurrentAuditSubject {

    private static final String ANONYMOUS = "anonymous";
    private static final int MAX_LENGTH = 255;

    public String subject() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return ANONYMOUS;
        }
        String name = authentication.getName();
        if (name == null || name.isBlank()) {
            return ANONYMOUS;
        }
        return name.length() <= MAX_LENGTH ? name : "sha256:" + ContentFingerprint.sha256(name);
    }
}
