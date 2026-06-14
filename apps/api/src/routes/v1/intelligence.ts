/**
 * Intelligence Routes
 *
 * On-demand raw intelligence endpoint for IOC/CVE/Actor detail pages.
 * Returns per-source enrichment results without AI analysis.
 */

import { Hono } from 'hono';
import { enrichIOC } from '@rinjani/core/enrichment';
import type { EnrichmentSource } from '@rinjani/core/enrichment';
import * as opensearch from '../../services/opensearch';
import { createLogger } from '../../lib/logger';
import { IntelligenceIOCQuerySchema } from '../../lib/schemas';

// Note: @rinjani/db and opensearch/vector are dynamically imported inside
// handlers to avoid blocking API startup (DB pool init + ML model loading).

const router = new Hono();
const log = createLogger('Intelligence');

// Source sets per IOC type. `greynoise` joins the IP list (free Community
// classification — drops benign scanners from priority). `urlscan` joins
// both URL and domain lists (URL/domain scan history with screenshot URL).
const SOURCE_MAP: Record<string, EnrichmentSource[]> = {
    ip: ['virustotal', 'abuseipdb', 'greynoise', 'geoip', 'dns', 'threatfox', 'urlhaus', 'shodan', 'zoomeye'],
    domain: ['virustotal', 'urlscan', 'geoip', 'dns', 'whois', 'threatfox', 'urlhaus', 'safebrowsing'],
    url: ['virustotal', 'urlscan', 'threatfox', 'urlhaus', 'safebrowsing'],
    hash: ['virustotal', 'threatfox', 'urlhaus'],
    email: ['virustotal'],
};

/**
 * GET /intelligence/ioc/:value
 * On-demand enrichment for an IOC value — returns raw per-source results.
 * Persists results to PostgreSQL so subsequent requests can skip external APIs.
 */
router.get('/intelligence/ioc/:value', async (c) => {
    const { value } = c.req.param();
    let decodedValue: string;
    try {
        decodedValue = decodeURIComponent(value);
    } catch {
        decodedValue = value; // fallback if URI is malformed (e.g. %s in URLs)
    }
    const forceRefresh = c.req.query('refresh') === 'true';

    log.info('Intelligence request', { value: decodedValue, forceRefresh });

    const { detectIOCType } = await import('@rinjani/core/enrichment');
    const iocType = detectIOCType(decodedValue);

    if (!iocType) {
        return c.json({
            success: false,
            error: `Cannot determine IOC type for: ${decodedValue}`,
        }, 400);
    }

    // ── Check PostgreSQL for cached enrichment (< 1 hour old) ──
    const { db, eq, sql } = await import('@rinjani/db');
    const { iocs, pulses } = await import('@rinjani/db/schema');

    let existingRow: {
        id: string;
        enrichmentScore: number | null;
        enrichmentLevel: string | null;
        enrichmentTags: string[] | null;
        enrichmentData: unknown;
        enrichedAt: Date | null;
        pulseId: string | null;
        source: string | null;
        severity: string | null;
    } | null = null;

    try {
        const rows = await db.select({
            id: iocs.id,
            enrichmentScore: iocs.enrichmentScore,
            enrichmentLevel: iocs.enrichmentLevel,
            enrichmentTags: iocs.enrichmentTags,
            enrichmentData: iocs.enrichmentData,
            enrichedAt: iocs.enrichedAt,
            pulseId: iocs.pulseId,
            source: iocs.source,
            severity: iocs.severity,
        }).from(iocs)
            .where(eq(iocs.value, decodedValue))
            .limit(1);
        existingRow = rows[0] ?? null;
    } catch {
        // DB query is best-effort
    }

    // If we have fresh enrichment data (< 1 hour) and no force refresh, return from DB
    const ENRICHMENT_TTL_MS = 60 * 60 * 1000; // 1 hour
    const hasFreshCachedData = existingRow?.enrichedAt &&
        existingRow.enrichmentData &&
        !forceRefresh &&
        (Date.now() - new Date(existingRow.enrichedAt).getTime()) < ENRICHMENT_TTL_MS;

    if (hasFreshCachedData) {
        log.info('Returning cached enrichment from DB', { value: decodedValue });

        const cached = existingRow!.enrichmentData as {
            sources: Array<{ source: string; success: boolean; timestamp: string; data: unknown; error: string | null }>;
            value: string;
            type: string;
        };

        // Fetch pulse context from DB (same as below)
        let pulseContext = await fetchPulseContext(db, eq, iocs, pulses, decodedValue, existingRow!);

        return c.json({
            success: true,
            data: {
                value: decodedValue,
                type: iocType,
                overallScore: existingRow!.enrichmentScore ?? 0,
                riskLevel: existingRow!.enrichmentLevel ?? 'low',
                tags: existingRow!.enrichmentTags ?? [],
                lastEnrichedAt: existingRow!.enrichedAt,
                sources: cached.sources || [],
                sourceCount: (cached.sources || []).filter((s: { success: boolean }) => s.success).length,
                totalSources: (cached.sources || []).length,
                pulseContext,
                fromCache: true,
            },
        });
    }

    // ── No fresh cache — call external APIs ──
    const allSources = SOURCE_MAP[iocType] || ['virustotal', 'geoip'];

    // Allow selective source filtering via ?sources=shodan,virustotal
    const { sources: sourcesParam } = IntelligenceIOCQuerySchema.parse(c.req.query());
    const sources = sourcesParam
        ? sourcesParam.split(',').filter(s => allSources.includes(s as EnrichmentSource)) as EnrichmentSource[]
        : allSources;

    if (sources.length === 0) {
        return c.json({
            success: false,
            error: `No valid sources specified. Available: ${allSources.join(', ')}`,
            availableSources: allSources,
        }, 400);
    }

    const enriched = await enrichIOC(decodedValue, {
        sources,
        priority: 'comprehensive',
        forceRefresh,
    });

    // Structure the response with per-source breakdown
    const sourceResults = enriched.enrichments.map(e => ({
        source: e.source,
        success: e.success,
        timestamp: e.timestamp,
        data: e.data || null,
        error: e.error || null,
    }));

    // ── Persist enrichment results to PostgreSQL ──
    try {
        const enrichmentPayload = {
            enrichmentScore: enriched.overallScore ?? 0,
            enrichmentLevel: enriched.riskLevel ?? 'low',
            enrichmentTags: enriched.tags ?? [],
            enrichmentData: { sources: sourceResults, value: enriched.value, type: enriched.type },
            enrichedAt: new Date(),
            updatedAt: new Date(),
        };

        if (existingRow) {
            // UPDATE existing IOC record
            await db.update(iocs)
                .set(enrichmentPayload)
                .where(eq(iocs.id, existingRow.id));
            log.info('Updated enrichment in DB', { iocId: existingRow.id });
        } else {
            // INSERT new IOC record (discovered via on-demand enrichment)
            await db.insert(iocs).values({
                type: iocType,
                value: decodedValue,
                source: 'on-demand',
                severity: enriched.riskLevel === 'critical' ? 'critical' :
                    enriched.riskLevel === 'high' ? 'high' :
                        enriched.riskLevel === 'medium' ? 'medium' : 'low',
                confidence: enriched.overallScore ?? 0,
                tags: enriched.tags ?? [],
                firstSeen: new Date(),
                lastSeen: new Date(),
                ...enrichmentPayload,
            }).onConflictDoUpdate({
                target: iocs.value,
                set: enrichmentPayload,
            });
            log.info('Inserted new IOC with enrichment', { value: decodedValue });
        }
    } catch (dbErr) {
        log.warn('Failed to persist enrichment to DB (non-blocking)', {
            value: decodedValue,
            error: (dbErr as Error)?.message,
        });
    }

    // ── Pulse context lookup ──
    let pulseContext = await fetchPulseContext(db, eq, iocs, pulses, decodedValue, existingRow);

    return c.json({
        success: true,
        data: {
            value: enriched.value,
            type: enriched.type,
            overallScore: enriched.overallScore,
            riskLevel: enriched.riskLevel,
            tags: enriched.tags,
            lastEnrichedAt: enriched.lastEnrichedAt,
            sources: sourceResults,
            sourceCount: sourceResults.filter(s => s.success).length,
            totalSources: sourceResults.length,
            pulseContext,
        },
    });
});

/**
 * Helper: fetch pulse context from PostgreSQL (IOC → Pulse → Actor chain)
 */
async function fetchPulseContext(
    db: any,
    eq: any,
    iocsTable: any,
    pulsesTable: any,
    decodedValue: string,
    existingRow: { pulseId: string | null } | null,
) {
    try {
        const pulseId = existingRow?.pulseId;
        if (!pulseId) {
            // Try lookup if existingRow not populated
            const iocRows = await db.select({ pulseId: iocsTable.pulseId })
                .from(iocsTable)
                .where(eq(iocsTable.value, decodedValue))
                .limit(1);
            if (!iocRows[0]?.pulseId) return null;
            const pid = iocRows[0].pulseId;
            const pulseRows = await db.select({
                name: pulsesTable.name,
                adversary: pulsesTable.adversary,
                attackIds: pulsesTable.attackIds,
                malwareFamilies: pulsesTable.malwareFamilies,
                targetedCountries: pulsesTable.targetedCountries,
                tags: pulsesTable.tags,
                indicatorCount: pulsesTable.indicatorCount,
            }).from(pulsesTable)
                .where(eq(pulsesTable.otxId, pid))
                .limit(1);
            if (!pulseRows[0]) return null;
            return {
                pulseName: pulseRows[0].name,
                adversary: pulseRows[0].adversary,
                attackIds: pulseRows[0].attackIds,
                malwareFamilies: pulseRows[0].malwareFamilies,
                targetedCountries: pulseRows[0].targetedCountries,
                tags: pulseRows[0].tags,
                indicatorCount: pulseRows[0].indicatorCount,
            };
        }

        const pulseRows = await db.select({
            name: pulsesTable.name,
            adversary: pulsesTable.adversary,
            attackIds: pulsesTable.attackIds,
            malwareFamilies: pulsesTable.malwareFamilies,
            targetedCountries: pulsesTable.targetedCountries,
            tags: pulsesTable.tags,
            indicatorCount: pulsesTable.indicatorCount,
        }).from(pulsesTable)
            .where(eq(pulsesTable.otxId, pulseId))
            .limit(1);

        if (!pulseRows[0]) return null;
        return {
            pulseName: pulseRows[0].name,
            adversary: pulseRows[0].adversary,
            attackIds: pulseRows[0].attackIds,
            malwareFamilies: pulseRows[0].malwareFamilies,
            targetedCountries: pulseRows[0].targetedCountries,
            tags: pulseRows[0].tags,
            indicatorCount: pulseRows[0].indicatorCount,
        };
    } catch {
        return null;
    }
}

/**
 * GET /intelligence/cve/:cveId
 * Rich intelligence briefing for a CVE — full record + related IOCs + similar entities
 */
router.get('/intelligence/cve/:cveId', async (c) => {
    const { cveId } = c.req.param();
    const normalizedCve = cveId.toUpperCase();

    log.info('CVE intelligence request', { cveId: normalizedCve });

    // 1. Fetch full vulnerability record from PostgreSQL
    const { db, eq, sql } = await import('@rinjani/db');
    const { vulnerabilities, threatActors, mitreRelationships, pulses, iocs } = await import('@rinjani/db/schema');

    const pgRows = await db
        .select()
        .from(vulnerabilities)
        .where(eq(vulnerabilities.cveId, normalizedCve))
        .limit(1);

    const vulnRecord = pgRows[0] || null;

    // 2. Search OpenSearch for IOCs that reference this CVE
    const related = await opensearch.unifiedSearch({
        query: normalizedCve,
        filters: { entityType: ['ioc'] },
        pagination: { page: 1, limit: 20 },
        sort: { field: '_score', order: 'desc' },
    });

    // 3. Vector-similar entities
    let similarResults: Record<string, unknown>[] = [];
    try {
        const { vectorSearch } = await import('../../services/opensearch/vector');
        const similar = await vectorSearch(normalizedCve, 10);
        similarResults = (similar.items || []).filter(
            (r: Record<string, unknown>) => r.id !== vulnRecord?.id
        );
    } catch {
        // Vector search optional
    }

    // 3b. Find linked threat actors via MITRE relationships
    //     Strategy: search for actors whose name/aliases appear in pulse adversary data
    //     referencing CVEs, or actors that use techniques targeting the CVE's product
    let linkedActors: { id: string; name: string; description: string | null; aliases: string[] | null; primaryMotivation: string | null }[] = [];
    try {
        // Find pulses that mention this CVE in tags or title
        const pulsesForCve = await db.select({
            adversary: pulses.adversary,
        }).from(pulses)
            .where(sql`${pulses.name} ILIKE ${'%' + normalizedCve + '%'}
                OR ${normalizedCve} = ANY(${pulses.tags})`)
            .limit(50);

        const adversaryNames = [...new Set(
            pulsesForCve.map(p => p.adversary).filter((a): a is string => !!a)
        )];

        if (adversaryNames.length > 0) {
            // Find actors matching those adversary names via SQL-level filtering
            const nameConditions = adversaryNames.map(n => `name ILIKE '${n.replace(/'/g, "''")}' OR aliases::text ILIKE '%${n.replace(/'/g, "''")}%'`);
            const actorRows = await db.select({
                id: threatActors.id,
                name: threatActors.name,
                description: threatActors.description,
                aliases: threatActors.aliases,
                primaryMotivation: threatActors.primaryMotivation,
            }).from(threatActors)
                .where(sql.raw(`(${nameConditions.join(' OR ')})`))
                .limit(10);

            linkedActors = actorRows;
        }

        // Also search for actors via IOC references to this CVE.
        // Decayed IOCs are excluded — analyst is asking "who's actively
        // exploiting this CVE", not "who has ever been seen with it".
        if (linkedActors.length === 0) {
            const iocResults = await db.select({
                pulseId: iocs.pulseId,
            }).from(iocs)
                .where(sql`${normalizedCve} = ANY(${iocs.tags}) AND ${iocs.decayedAt} IS NULL`)
                .limit(20);

            const cveRelatedPulseIds = [...new Set(
                iocResults.map(i => i.pulseId).filter((p): p is string => !!p)
            )];

            if (cveRelatedPulseIds.length > 0) {
                const { inArray } = await import('@rinjani/db');
                const pulseAdversaries = await db.select({
                    adversary: pulses.adversary,
                }).from(pulses)
                    .where(inArray(pulses.otxId, cveRelatedPulseIds))
                    .limit(50);

                const moreAdversaries = [...new Set(
                    pulseAdversaries.map(p => p.adversary).filter((a): a is string => !!a)
                )];

                if (moreAdversaries.length > 0) {
                    const nameConditions2 = moreAdversaries.map(n => `name ILIKE '${n.replace(/'/g, "''")}' OR aliases::text ILIKE '%${n.replace(/'/g, "''")}%'`);
                    linkedActors = await db.select({
                        id: threatActors.id,
                        name: threatActors.name,
                        description: threatActors.description,
                        aliases: threatActors.aliases,
                        primaryMotivation: threatActors.primaryMotivation,
                    }).from(threatActors)
                        .where(sql.raw(`(${nameConditions2.join(' OR ')})`))
                        .limit(10);
                }
            }
        }
    } catch (actorErr) {
        log.warn('Failed to find linked actors for CVE', { cveId: normalizedCve, error: (actorErr as Error)?.message });
    }

    // 4. Compute a risk assessment score based on available data
    let riskScore = 0;
    let riskLevel = 'low';

    if (vulnRecord) {
        const cvss = vulnRecord.cvssScore ? parseFloat(String(vulnRecord.cvssScore)) : 0;
        riskScore = Math.round(cvss * 10); // 0-100 scale from CVSS 0-10

        if (vulnRecord.isExploited) {
            riskScore = Math.min(100, riskScore + 20); // bump if actively exploited
        }

        if (riskScore >= 90) riskLevel = 'critical';
        else if (riskScore >= 70) riskLevel = 'high';
        else if (riskScore >= 40) riskLevel = 'medium';
        else riskLevel = 'low';
    }

    // 5. Build tags from available data
    const tags: string[] = [];
    if (vulnRecord?.severity) tags.push(vulnRecord.severity.toUpperCase());
    if (vulnRecord?.isExploited) tags.push('ACTIVELY EXPLOITED');
    if (vulnRecord?.cweId) tags.push(vulnRecord.cweId);
    if (vulnRecord?.vendorProject) tags.push(vulnRecord.vendorProject);
    if (vulnRecord?.product) tags.push(vulnRecord.product);

    return c.json({
        success: true,
        data: {
            cveId: normalizedCve,
            riskScore,
            riskLevel,
            tags,

            // Full vulnerability record
            vulnerability: vulnRecord ? {
                description: vulnRecord.description,
                cvssScore: vulnRecord.cvssScore ? parseFloat(String(vulnRecord.cvssScore)) : null,
                cvssVector: vulnRecord.cvssVector,
                severity: vulnRecord.severity,
                cweId: vulnRecord.cweId,
                isExploited: vulnRecord.isExploited || false,
                exploitAddedDate: vulnRecord.exploitAddedDate,
                dueDate: vulnRecord.dueDate,
                vendorProject: vulnRecord.vendorProject,
                product: vulnRecord.product,
                references: vulnRecord.references || [],
                publishedDate: vulnRecord.publishedDate,
                lastModified: vulnRecord.lastModified,
            } : null,

            // Related IOCs
            relatedIOCs: related.items.map((item: Record<string, unknown>) => ({
                id: item.id,
                value: item.value || item.title,
                type: item.type || item.entityType,
                severity: item.severity,
                source: item.source,
                confidence: item.confidence,
                firstSeen: item.createdAt,
                lastSeen: item.updatedAt,
                description: item.description,
            })),
            relatedCount: related.total,

            // Semantically similar vulnerabilities
            similarEntities: similarResults.slice(0, 5).map((r: Record<string, unknown>) => ({
                id: r.id,
                title: r.title || r.value,
                entityType: r.entityType,
                severity: r.severity,
                score: r.score,
                description: r.description ? String(r.description).substring(0, 120) + '...' : null,
            })),

            // Linked threat actors (via MITRE relationships / pulse cross-references)
            linkedActors: linkedActors.map(a => ({
                id: a.id,
                name: a.name,
                description: a.description ? String(a.description).substring(0, 150) : null,
                aliases: a.aliases || [],
                primaryMotivation: a.primaryMotivation,
            })),
        },
    });
});

/**
 * GET /intelligence/actor/:id
 * Rich relationship intelligence for a threat actor.
 * Queries MITRE relationships (techniques, malware) and pulse associations (IOCs).
 */
router.get('/intelligence/actor/:id', async (c) => {
    const { id } = c.req.param();

    log.info('Actor intelligence request', { id });

    const { db, eq, sql, inArray, and, isNull } = await import('@rinjani/db');
    const { threatActors, mitreRelationships, techniques, malware, pulses, iocs } = await import('@rinjani/db/schema');

    // 1. Resolve actor — by UUID or by name
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    const actorRows = await db.select().from(threatActors)
        .where(isUUID ? eq(threatActors.id, id) : eq(threatActors.name, id))
        .limit(1);

    const actor = actorRows[0];
    if (!actor) {
        return c.json({ success: false, error: `Threat actor not found: ${id}` }, 404);
    }

    const actorNames = [actor.name, ...(actor.aliases || [])].filter(Boolean).map(n => n.toLowerCase());

    // Find all STIX IDs connected to this actor (to merge across sources like MISP + MITRE)
    const allMatchingActors = await db.select({
        stixId: threatActors.stixId,
    }).from(threatActors)
        .where(eq(threatActors.name, actor.name));

    const uniqueActorStixIds = Array.from(new Set([actor.stixId, ...allMatchingActors.map(a => a.stixId)]));

    // 2. Query MITRE relationships — techniques and malware this actor uses
    let actorTechniques: { mitreId: string; name: string; description: string | null; relationshipDesc: string | null }[] = [];
    let actorMalware: { stixId: string; name: string; description: string | null }[] = [];

    try {
        const rels = await db.select({
            targetId: mitreRelationships.targetId,
            targetType: mitreRelationships.targetType,
            relType: mitreRelationships.relationshipType,
            confidence: mitreRelationships.confidence,
            description: mitreRelationships.description,
        }).from(mitreRelationships)
            .where(sql`${inArray(mitreRelationships.sourceId, uniqueActorStixIds)}
                AND ${mitreRelationships.relationshipType} = 'uses'`);

        const techTargetIds = rels.filter(r => r.targetType === 'attack-pattern').map(r => r.targetId);
        const malTargetIds = rels.filter(r => r.targetType === 'malware').map(r => r.targetId);

        // Resolve technique names
        if (techTargetIds.length > 0) {
            const allTechs = await db.select({
                mitreId: techniques.mitreId,
                name: techniques.name,
                description: techniques.description,
            }).from(techniques).limit(500);

            // Match by STIX ID pattern (attack-pattern--<uuid> maps to T-codes via the relationships)
            const techMap = new Map(allTechs.map(t => [t.mitreId, t]));
            actorTechniques = rels
                .filter(r => r.targetType === 'attack-pattern')
                .map(r => {
                    // Try direct match first, then iterate
                    for (const [mitreId, tech] of techMap.entries()) {
                        return { mitreId, name: tech.name, description: tech.description, relationshipDesc: r.description };
                    }
                    return null;
                })
                .filter((t): t is NonNullable<typeof t> => t !== null)
                .slice(0, 30);

            // Deduplicate by mitreId
            const seen = new Set<string>();
            actorTechniques = actorTechniques.filter(t => {
                if (seen.has(t.mitreId)) return false;
                seen.add(t.mitreId);
                return true;
            });
        }

        // Resolve malware names
        if (malTargetIds.length > 0) {
            const allMal = await db.select({
                stixId: malware.stixId,
                name: malware.name,
                description: malware.description,
            }).from(malware).limit(200);

            const malStixSet = new Set(malTargetIds);
            actorMalware = allMal.filter(m => malStixSet.has(m.stixId)).slice(0, 20);
        }
    } catch (relErr) {
        log.warn('Failed to query MITRE relationships', { error: (relErr as Error)?.message });
    }

    // 3. Query pulses — where adversary matches this actor's name or aliases
    let relatedPulses: { otxId: string; name: string; description: string | null; tags: string[] | null; attackIds: string[] | null; malwareFamilies: string[] | null; targetedCountries: string[] | null; indicatorCount: number | null }[] = [];
    let relatedIOCs: { id: string; type: string; value: string; source: string; severity: string | null; confidence: number | null; tags: string[] | null }[] = [];

    try {
        // Find pulses that reference this actor
        const pulseRows = await db.select({
            id: pulses.id,
            otxId: pulses.otxId,
            name: pulses.name,
            description: pulses.description,
            tags: pulses.tags,
            adversary: pulses.adversary,
            attackIds: pulses.attackIds,
            malwareFamilies: pulses.malwareFamilies,
            targetedCountries: pulses.targetedCountries,
            indicatorCount: pulses.indicatorCount,
        }).from(pulses).limit(500);

        // Match by adversary name (case-insensitive)
        relatedPulses = pulseRows.filter(p =>
            p.adversary && actorNames.includes(p.adversary.toLowerCase())
        ).map(p => ({
            otxId: p.otxId,
            name: p.name,
            description: p.description,
            tags: p.tags,
            attackIds: p.attackIds,
            malwareFamilies: p.malwareFamilies,
            targetedCountries: p.targetedCountries,
            indicatorCount: p.indicatorCount,
        })).slice(0, 20);

        // Find IOCs linked to matched pulses
        if (relatedPulses.length > 0) {
            const pulseOtxIds = relatedPulses.map(p => p.otxId);
            // "Related IOCs for this pulse" is a current-threats surface
            // (dashboard rendering of "what's still active in this
            // campaign"), so decayed IOCs are excluded — see PR #105's
            // marker layer.
            const iocRows = await db.select({
                id: iocs.id,
                type: iocs.type,
                value: iocs.value,
                source: iocs.source,
                severity: iocs.severity,
                confidence: iocs.confidence,
                tags: iocs.tags,
            }).from(iocs)
                .where(and(
                    inArray(iocs.pulseId, pulseOtxIds),
                    isNull(iocs.decayedAt),
                ))
                .limit(50);

            relatedIOCs = iocRows;
        }
    } catch (pulseErr) {
        log.warn('Failed to query pulse associations', { error: (pulseErr as Error)?.message });
    }

    // 4. Also do a semantic search for related entities
    let semanticResults: Record<string, unknown>[] = [];
    try {
        const related = await opensearch.unifiedSearch({
            query: actor.name,
            filters: {},
            pagination: { page: 1, limit: 10 },
            sort: { field: 'updatedAt', order: 'desc' },
        });
        semanticResults = related.items.filter(
            (item: Record<string, unknown>) => item.id !== actor.id
        );
    } catch {
        // OpenSearch optional
    }

    const relationshipCount = actorTechniques.length + actorMalware.length + relatedIOCs.length + relatedPulses.length;

    return c.json({
        success: true,
        data: {
            actorId: actor.id,
            actorName: actor.name,
            stixId: actor.stixId,

            // MITRE ATT&CK relationships
            techniques: actorTechniques,
            malware: actorMalware,

            // Pulse-derived relationships
            pulses: relatedPulses,
            relatedIOCs: relatedIOCs,

            // Semantic/search-based (supplementary)
            relatedEntities: semanticResults.map((item: Record<string, unknown>) => ({
                id: item.id,
                title: item.title || item.value,
                entityType: item.entityType,
                severity: item.severity,
                source: item.source,
            })),

            relationshipCount,
        },
    });
});

export default router;
