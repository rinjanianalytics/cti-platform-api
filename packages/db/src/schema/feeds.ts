/**
 * Intel Feed Database Schema
 * 
 * Tables for storing threat intelligence data from external feeds:
 * - iocs: Indicators of Compromise (IPs, domains, hashes, URLs)
 * - vulnerabilities: CVE records with CVSS scores and CISA KEV flags
 * - pulses: AlienVault OTX threat reports
 */

import { pgTable, text, timestamp, uuid, integer, numeric, boolean, jsonb, date, index } from 'drizzle-orm/pg-core';

// =============================================================================
// IOCs (Indicators of Compromise)
// =============================================================================
export const iocs = pgTable('iocs', {
    id: uuid('id').primaryKey().defaultRandom(),
    type: text('type').notNull(), // ip, domain, url, hash-md5, hash-sha1, hash-sha256, email, hostname
    value: text('value').unique().notNull(),
    source: text('source').notNull(), // alienvault, abusessl, virustotal, misp
    threatType: text('threat_type'), // malware, c2, phishing, ransomware, botnet
    confidence: integer('confidence'), // 0-100
    // Composite risk score (0-100) written by the scoring engine and read by
    // alerts / reputation / landscape endpoints. Distinct from `confidence`:
    // confidence reflects source reliability, risk_score reflects the
    // multi-signal weighting (KEV match, VT detections, EPSS, age, etc.).
    riskScore: integer('risk_score').default(0),
    severity: text('severity'), // low, medium, high, critical
    firstSeen: timestamp('first_seen'),
    lastSeen: timestamp('last_seen'),
    tags: text('tags').array(),
    pulseId: text('pulse_id'), // AlienVault pulse reference
    rawData: jsonb('raw_data'),

    // Enrichment persistence (from on-demand enrichment via external APIs)
    enrichmentScore: integer('enrichment_score'),             // 0-100 overall risk score
    enrichmentLevel: text('enrichment_level'),                 // low, medium, high, critical
    enrichmentTags: text('enrichment_tags').array(),           // auto-generated tags from enrichment
    enrichmentData: jsonb('enrichment_data'),                  // full per-source enrichment results
    enrichedAt: timestamp('enriched_at'),                      // last enrichment timestamp

    // Stamped NOW() by the confidenceDecay BullMQ job when an IOC crosses
    // its per-type staleness threshold (DECAY_RATES in
    // apps/api/src/services/confidenceDecay.ts — IPs 30d, domains 60d,
    // hashes 180d, etc.). A BEFORE UPDATE trigger on this table clears it
    // back to NULL whenever last_seen advances, so any feed-sync upsert
    // that re-sights an IOC automatically un-decays it without the call
    // site needing to know about decayed_at. Dashboard / stats endpoints
    // filter `WHERE decayed_at IS NULL` to hide stale entries while
    // keeping them in the table for forensic queries.
    decayedAt: timestamp('decayed_at', { withTimezone: true }),

    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
}, (table) => ({
    typeIdx: index('iocs_type_idx').on(table.type),
    sourceIdx: index('iocs_source_idx').on(table.source),
    valueIdx: index('iocs_value_idx').on(table.value),
    threatTypeIdx: index('iocs_threat_type_idx').on(table.threatType),
}));

// =============================================================================
// Vulnerabilities (CVE)
// =============================================================================
export const vulnerabilities = pgTable('vulnerabilities', {
    id: uuid('id').primaryKey().defaultRandom(),
    cveId: text('cve_id').unique().notNull(),
    description: text('description'),
    cvssScore: numeric('cvss_score', { precision: 3, scale: 1 }),
    cvssVector: text('cvss_vector'),
    severity: text('severity'), // none, low, medium, high, critical
    cweId: text('cwe_id'),

    // CISA KEV (Known Exploited Vulnerabilities)
    isExploited: boolean('is_exploited').default(false),
    exploitAddedDate: date('exploit_added_date'),
    dueDate: date('due_date'), // CISA remediation deadline

    // EPSS — FIRST.org's daily exploit-prediction score.
    //   epssScore      ∈ [0, 1] — probability of exploitation in the next 30 days
    //   epssPercentile ∈ [0, 1] — score's rank vs the entire CVE corpus
    // Both nullable: every CVE present in the EPSS feed gets values, but
    // brand-new CVEs (and CVEs we ingest from sources EPSS hasn't scored
    // yet) stay null until the daily refresh.
    epssScore: numeric('epss_score', { precision: 6, scale: 5 }),
    epssPercentile: numeric('epss_percentile', { precision: 6, scale: 5 }),
    epssUpdatedAt: timestamp('epss_updated_at', { withTimezone: true }),

    // Affected products
    vendorProject: text('vendor_project'),
    product: text('product'),

    // References
    references: text('references').array(),

    // Timestamps
    publishedDate: timestamp('published_date'),
    lastModified: timestamp('last_modified'),
    rawData: jsonb('raw_data'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
    syncedAt: timestamp('synced_at'),
}, (table) => ({
    cveIdIdx: index('vulnerabilities_cve_id_idx').on(table.cveId),
    severityIdx: index('vulnerabilities_severity_idx').on(table.severity),
    isExploitedIdx: index('vulnerabilities_is_exploited_idx').on(table.isExploited),
    // EPSS is a common filter ("X critical with EPSS >= 0.7") so a btree
    // index pays back; partial index since most analyst queries are
    // "score >= some threshold" not "score IS NULL".
    epssScoreIdx: index('vulnerabilities_epss_score_idx').on(table.epssScore),
}));

// =============================================================================
// Pulses (AlienVault OTX)
// =============================================================================
export const pulses = pgTable('pulses', {
    id: uuid('id').primaryKey().defaultRandom(),
    otxId: text('otx_id').unique().notNull(),
    name: text('name').notNull(),
    description: text('description'),
    author: text('author'),
    tlp: text('tlp'), // white, green, amber, red

    // Classification
    tags: text('tags').array(),
    adversary: text('adversary'),
    targetedCountries: text('targeted_countries').array(),
    industries: text('industries').array(),
    malwareFamilies: text('malware_families').array(),
    attackIds: text('attack_ids').array(), // MITRE ATT&CK IDs
    // OTX pulses include a `references` array of URLs — primary sources,
    // vendor write-ups, blog posts the analyst published with. Persisting
    // these gives the dashboard a "see also" link list instead of
    // forcing the analyst to bounce out to otx.alienvault.com.
    //
    // SQL column is `reference_urls` (not `references`) because
    // `references` is a reserved keyword in PostgreSQL — using it forced
    // every query to quote `"references"` and routinely caused
    // `syntax error at or near "references"` when an analyst typed an
    // ad-hoc query. The Drizzle JS property stays `references` so
    // dashboard/API/worker code reads naturally. See migration 0042.
    references: text('reference_urls').array(),

    // Metrics
    indicatorCount: integer('indicator_count'),
    subscriberCount: integer('subscriber_count'),

    // Timestamps
    otxCreated: timestamp('otx_created'),
    otxModified: timestamp('otx_modified'),
    rawData: jsonb('raw_data'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at').defaultNow(),
    syncedAt: timestamp('synced_at'),
}, (table) => ({
    otxIdIdx: index('pulses_otx_id_idx').on(table.otxId),
    adversaryIdx: index('pulses_adversary_idx').on(table.adversary),
}));

// Type exports
export type IOC = typeof iocs.$inferSelect;
export type NewIOC = typeof iocs.$inferInsert;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type NewVulnerability = typeof vulnerabilities.$inferInsert;
export type Pulse = typeof pulses.$inferSelect;
export type NewPulse = typeof pulses.$inferInsert;
