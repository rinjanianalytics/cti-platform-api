/**
 * Neo4j Sync — Pulses + IOCs + Attribution edges
 */

import { db, sql, desc } from '@rinjani/db';
import { pulses, iocs } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncPulsesAndIOCs(
    maxPulses: number = 500,
    maxIOCsPerPulse: number = 50,
    onProgress?: (pct: number) => void,
): Promise<{ pulses: number; iocs: number; links: number }> {
    const driver = getNeo4jDriver();

    // Order NEWEST-FIRST. Without this, `.limit(maxPulses)` returned an
    // arbitrary (insertion-order = oldest) slice, so freshly-ingested pulses
    // never made the cap and the Neo4j Pulse corpus stayed frozen while the
    // Postgres table grew. MERGE accumulates, so syncing newest-first tops up
    // the graph with new pulses each run; older ones already exist as nodes.
    const pulseRows = await db.select({
        id: pulses.id,
        otxId: pulses.otxId,
        name: pulses.name,
        adversary: pulses.adversary,
        tlp: pulses.tlp,
        tags: pulses.tags,
    }).from(pulses).orderBy(desc(pulses.createdAt)).limit(maxPulses);

    if (pulseRows.length === 0) return { pulses: 0, iocs: 0, links: 0 };

    const session = driver.session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (p:Pulse {otxId: row.otxId})
            SET p.pgId = row.id,
                p.name = row.name,
                p.adversary = coalesce(row.adversary, ''),
                p.tlp = coalesce(row.tlp, 'white'),
                p.tags = coalesce(row.tags, []),
                p.syncedAt = datetime()
        `, {
            batch: pulseRows.map(r => ({
                id: r.id,
                otxId: r.otxId,
                name: r.name,
                adversary: r.adversary || '',
                tlp: r.tlp || 'white',
                tags: r.tags || [],
            }))
        });

        onProgress?.(30);

        const pulseAdversaries = pulseRows
            .filter(p => p.adversary && p.adversary.length > 0)
            .map(p => ({ otxId: p.otxId, adversary: p.adversary! }));

        if (pulseAdversaries.length > 0) {
            await session.run(`
                UNWIND $batch AS row
                MATCH (p:Pulse {otxId: row.otxId})
                MATCH (a:Actor) WHERE toLower(a.name) = toLower(row.adversary)
                MERGE (p)-[:ATTRIBUTED_TO]->(a)
            `, { batch: pulseAdversaries });
        }

        onProgress?.(50);

        const pulseIds = pulseRows.map(p => p.otxId);
        const iocRows = await db.select({
            id: iocs.id,
            value: iocs.value,
            type: iocs.type,
            pulseId: iocs.pulseId,
            threatType: iocs.threatType,
            severity: iocs.severity,
        }).from(iocs)
            .where(sql`${iocs.pulseId} IN (${sql.join(pulseIds.map(id => sql`${id}`), sql`,`)})`)
            .limit(maxPulses * maxIOCsPerPulse);

        if (iocRows.length > 0) {
            await session.run(`
                UNWIND $batch AS row
                MERGE (i:IOC {pgId: row.id})
                SET i.value = row.value,
                    i.type = row.type,
                    i.threatType = coalesce(row.threatType, 'unknown'),
                    i.severity = coalesce(row.severity, 'unknown'),
                    i.syncedAt = datetime()
            `, {
                batch: iocRows.map(r => ({
                    id: r.id,
                    value: r.value,
                    type: r.type,
                    threatType: r.threatType || 'unknown',
                    severity: r.severity || 'unknown',
                }))
            });

            const iocPulseLinks = iocRows
                .filter(i => i.pulseId)
                .map(i => ({ iocId: i.id, pulseId: i.pulseId! }));

            if (iocPulseLinks.length > 0) {
                await session.run(`
                    UNWIND $batch AS row
                    MATCH (i:IOC {pgId: row.iocId})
                    MATCH (p:Pulse {otxId: row.pulseId})
                    MERGE (i)-[:FOUND_IN]->(p)
                `, { batch: iocPulseLinks });
            }
        }

        onProgress?.(100);

        const linkCount = pulseAdversaries.length + iocRows.filter(i => i.pulseId).length;
        log.info('Pulse/IOC sync done', { pulses: pulseRows.length, iocs: iocRows.length, links: linkCount });
        return { pulses: pulseRows.length, iocs: iocRows.length, links: linkCount };
    } finally {
        await session.close();
    }
}
