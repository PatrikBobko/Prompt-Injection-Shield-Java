CREATE TABLE scan_audit_records (
    id UUID PRIMARY KEY,
    scanned_at TIMESTAMP WITH TIME ZONE NOT NULL,
    content_sha256 VARCHAR(64) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    content_type VARCHAR(16) NOT NULL,
    segments_scanned INTEGER NOT NULL,
    overall_severity VARCHAR(16),
    risk_score INTEGER NOT NULL,
    high_finding_count INTEGER NOT NULL,
    medium_finding_count INTEGER NOT NULL,
    low_finding_count INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    version BIGINT NOT NULL
);

CREATE INDEX idx_scan_audit_records_scanned_at ON scan_audit_records (scanned_at DESC);
CREATE INDEX idx_scan_audit_records_content_sha256 ON scan_audit_records (content_sha256);
CREATE INDEX idx_scan_audit_records_subject_scanned_at ON scan_audit_records (subject, scanned_at DESC);

CREATE TABLE scan_audit_findings (
    audit_id UUID NOT NULL,
    finding_position INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    severity VARCHAR(16) NOT NULL,
    channel VARCHAR(32) NOT NULL,
    detector_ids VARCHAR(512) NOT NULL,
    PRIMARY KEY (audit_id, finding_position),
    CONSTRAINT fk_scan_audit_findings_audit
        FOREIGN KEY (audit_id) REFERENCES scan_audit_records (id) ON DELETE CASCADE
);
