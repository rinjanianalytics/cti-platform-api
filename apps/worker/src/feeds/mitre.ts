/**
 * MITRE ATT&CK Sync Worker
 * 
 * Fetches ATT&CK Enterprise data directly from MITRE's GitHub repository.
 * No Rinjani dependency - pulls STIX 2.1 data from official source.
 * 
 * Source: https://github.com/mitre/cti (STIX 2.1 format)
 */

import { db } from '@rinjani/db';
import { tactics, techniques, mitreTools, mitreRelationships } from '@rinjani/db/schema';
import { threatActors, malware } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('MITRE');

// MITRE ATT&CK Enterprise STIX 2.1 Bundle URL
const ATTACK_ENTERPRISE_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

interface STIXObject {
    type: string;
    id: string;
    name?: string;
    description?: string;
    /** STIX 2.1 common properties — present on every object. `created` is
     *  when the upstream authored the entity, `modified` is when they last
     *  revised it. We map these into `stix_created` / `stix_modified` and
     *  use `modified` as a `last_seen` fallback so the actors list can
     *  sort by recency. */
    created?: string;
    modified?: string;
    /** intrusion-set-specific recency fields. MITRE rarely populates these,
     *  but other STIX feeds do. */
    first_seen?: string;
    last_seen?: string;
    external_references?: Array<{
        source_name: string;
        external_id?: string;
        url?: string;
    }>;
    kill_chain_phases?: Array<{
        kill_chain_name: string;
        phase_name: string;
    }>;
    x_mitre_platforms?: string[];
    x_mitre_permissions_required?: string[];
    x_mitre_data_sources?: string[];
    x_mitre_is_subtechnique?: boolean;
    x_mitre_shortname?: string;
    x_mitre_detection?: string;
    x_mitre_version?: string;
    x_mitre_aliases?: string[];
    aliases?: string[];
    malware_types?: string[];
    source_ref?: string;
    target_ref?: string;
    relationship_type?: string;
    [key: string]: unknown;
}

/**
 * Parse a STIX timestamp into a `Date`. STIX guarantees ISO-8601 with a
 * `Z` suffix on `created`/`modified`; we still defend against malformed
 * input by returning `null` on parse failure rather than throwing.
 */
function stixDate(raw: string | undefined | null): Date | null {
    if (!raw) return null;
    const t = Date.parse(raw);
    return Number.isFinite(t) ? new Date(t) : null;
}

interface STIXBundle {
    type: 'bundle';
    id: string;
    objects: STIXObject[];
}

function getMitreId(obj: STIXObject): string | null {
    const ref = obj.external_references?.find(r => r.source_name === 'mitre-attack');
    return ref?.external_id || null;
}

function getMitreUrl(obj: STIXObject): string | null {
    const ref = obj.external_references?.find(r => r.source_name === 'mitre-attack');
    return ref?.url || null;
}

function getTacticIds(obj: STIXObject): string[] {
    if (!obj.kill_chain_phases) return [];
    return obj.kill_chain_phases
        .filter(p => p.kill_chain_name === 'mitre-attack')
        .map(p => p.phase_name);
}

export async function syncMitreAttack(): Promise<{
    tactics: number;
    techniques: number;
    threatActors: number;
    malware: number;
    tools: number;
    relationships: number;
}> {
    log.info('Fetching ATT&CK Enterprise data');

    const response = await fetch(ATTACK_ENTERPRISE_URL);
    if (!response.ok) {
        throw new Error(`Failed to fetch MITRE ATT&CK: ${response.status}`);
    }

    const bundle = await response.json() as STIXBundle;
    log.info('Received STIX objects', { count: bundle.objects.length });

    const stats = {
        tactics: 0,
        techniques: 0,
        threatActors: 0,
        malware: 0,
        tools: 0,
        relationships: 0,
    };

    // Phase name to tactic ID mapping
    const tacticMap: Record<string, string> = {};

    // ========================================
    // 1. Process Tactics
    // ========================================
    const tacticObjects = bundle.objects.filter(o => o.type === 'x-mitre-tactic');
    log.info('Processing tactics', { count: tacticObjects.length });

    for (const obj of tacticObjects) {
        const mitreId = getMitreId(obj);
        if (!mitreId) continue;

        const shortName = obj.x_mitre_shortname || obj.name?.toLowerCase().replace(/\s+/g, '-');
        if (shortName) {
            tacticMap[shortName] = mitreId;
        }

        try {
            await db.insert(tactics).values({
                mitreId,
                name: obj.name || 'Unknown',
                description: obj.description,
                shortName,
                url: getMitreUrl(obj),
            }).onConflictDoUpdate({
                target: tactics.mitreId,
                set: {
                    name: obj.name || 'Unknown',
                    description: obj.description,
                    updatedAt: new Date(),
                },
            });
            stats.tactics++;
        } catch (e) {
            log.error(`Failed to insert tactic ${mitreId}`, e);
        }
    }

    // ========================================
    // 2. Process Techniques
    // ========================================
    const techniqueObjects = bundle.objects.filter(o => o.type === 'attack-pattern');
    log.info('Processing techniques', { count: techniqueObjects.length });

    for (const obj of techniqueObjects) {
        const mitreId = getMitreId(obj);
        if (!mitreId) continue;

        const phaseNames = getTacticIds(obj);
        const tacticIds = phaseNames.map(p => tacticMap[p]).filter(Boolean);

        try {
            await db.insert(techniques).values({
                mitreId,
                // obj.id is the real STIX ID, e.g. `attack-pattern--<uuid>`.
                // Stored verbatim so the actor TTP changelog can JOIN
                // relationships.target_id against techniques.real_stix_id.
                realStixId: obj.id,
                name: obj.name || 'Unknown',
                description: obj.description,
                detection: obj.x_mitre_detection,
                platforms: obj.x_mitre_platforms,
                permissions: obj.x_mitre_permissions_required,
                dataSources: obj.x_mitre_data_sources,
                isSubtechnique: obj.x_mitre_is_subtechnique || false,
                parentId: obj.x_mitre_is_subtechnique ? mitreId.split('.')[0] : null,
                tacticIds,
                url: getMitreUrl(obj),
                version: obj.x_mitre_version,
            }).onConflictDoUpdate({
                target: techniques.mitreId,
                set: {
                    realStixId: obj.id,
                    name: obj.name || 'Unknown',
                    description: obj.description,
                    tacticIds,
                    updatedAt: new Date(),
                },
            });
            stats.techniques++;
        } catch (e) {
            log.error(`Failed to insert technique ${mitreId}`, e);
        }
    }

    // ========================================
    // 3. Process Threat Actors (Intrusion Sets)
    // ========================================
    const actorObjects = bundle.objects.filter(o => o.type === 'intrusion-set');
    log.info('Processing threat actors', { count: actorObjects.length });

    for (const obj of actorObjects) {
        const mitreId = getMitreId(obj);
        if (!mitreId) continue;

        try {
            // STIX timestamps — MITRE always populates `created`/`modified`
            // and almost never `first_seen`/`last_seen` for groups, so we
            // fall back to created/modified so the actors list can render
            // a meaningful "Last seen" column instead of "—" everywhere.
            const stixCreated = stixDate(obj.created);
            const stixModified = stixDate(obj.modified);
            const firstSeen = stixDate(obj.first_seen) ?? stixCreated;
            const lastSeen  = stixDate(obj.last_seen)  ?? stixModified;

            // Use stixId field with a mitre prefix for MITRE-sourced actors;
            // realStixId carries obj.id (`intrusion-set--<uuid>`) so the
            // relationships table can be joined to resolve actor names.
            await db.insert(threatActors).values({
                stixId: `mitre--${mitreId}`,
                realStixId: obj.id,
                name: obj.name || 'Unknown',
                aliases: obj.aliases || [],
                description: obj.description,
                stixCreated,
                stixModified,
                firstSeen,
                lastSeen,
            }).onConflictDoUpdate({
                target: threatActors.stixId,
                set: {
                    realStixId: obj.id,
                    name: obj.name || 'Unknown',
                    aliases: obj.aliases || [],
                    description: obj.description,
                    stixCreated,
                    stixModified,
                    firstSeen,
                    lastSeen,
                    updatedAt: new Date(),
                },
            });
            stats.threatActors++;
        } catch (e) {
            log.error(`Failed to insert threat actor ${mitreId}`, e);
        }
    }

    // ========================================
    // 4. Process Malware
    // ========================================
    const malwareObjects = bundle.objects.filter(o => o.type === 'malware');
    log.info('Processing malware', { count: malwareObjects.length });

    for (const obj of malwareObjects) {
        const mitreId = getMitreId(obj);
        if (!mitreId) continue;

        try {
            await db.insert(malware).values({
                stixId: `mitre--${mitreId}`,
                realStixId: obj.id,
                name: obj.name || 'Unknown',
                aliases: obj.x_mitre_aliases || obj.aliases || [],
                description: obj.description,
                malwareTypes: obj.malware_types || [],
            }).onConflictDoUpdate({
                target: malware.stixId,
                set: {
                    realStixId: obj.id,
                    name: obj.name || 'Unknown',
                    description: obj.description,
                    updatedAt: new Date(),
                },
            });
            stats.malware++;
        } catch (e) {
            log.error(`Failed to insert malware ${mitreId}`, e);
        }
    }

    // ========================================
    // 5. Process Tools
    // ========================================
    const toolObjects = bundle.objects.filter(o => o.type === 'tool');
    log.info('Processing tools', { count: toolObjects.length });

    for (const obj of toolObjects) {
        const mitreId = getMitreId(obj);
        if (!mitreId) continue;

        try {
            await db.insert(mitreTools).values({
                mitreId,
                name: obj.name || 'Unknown',
                aliases: obj.x_mitre_aliases,
                description: obj.description,
                platforms: obj.x_mitre_platforms,
                url: getMitreUrl(obj),
                source: 'mitre',
            }).onConflictDoUpdate({
                target: mitreTools.mitreId,
                set: {
                    name: obj.name || 'Unknown',
                    description: obj.description,
                    updatedAt: new Date(),
                },
            });
            stats.tools++;
        } catch (e) {
            log.error(`Failed to insert tool ${mitreId}`, e);
        }
    }

    // ========================================
    // 6. Process Relationships (limited set)
    // ========================================
    const relationshipObjects = bundle.objects.filter(o => o.type === 'relationship');
    log.info('Processing relationships (important subset)', { count: relationshipObjects.length });

    const importantRelTypes = ['uses', 'targets', 'attributed-to', 'mitigates'];
    let relCount = 0;

    for (const obj of relationshipObjects) {
        if (!importantRelTypes.includes(obj.relationship_type || '')) continue;
        if (!obj.source_ref || !obj.target_ref) continue;
        if (relCount >= 5000) break; // Limit to avoid overwhelming DB

        try {
            const sourceType = obj.source_ref.split('--')[0];
            const targetType = obj.target_ref.split('--')[0];

            await db.insert(mitreRelationships).values({
                sourceType,
                sourceId: obj.source_ref,
                relationshipType: obj.relationship_type || 'unknown',
                targetType,
                targetId: obj.target_ref,
                description: obj.description,
                source: 'mitre',
            }).onConflictDoNothing();

            relCount++;
            stats.relationships++;
        } catch (e) {
            // Ignore duplicate relationships
        }
    }

    log.info('Sync complete', stats);
    return stats;
}

// Export alias for consistency
export async function syncMITRE() {
    const stats = await syncMitreAttack();
    return {
        success: true,
        processed: stats.tactics + stats.techniques + stats.threatActors + stats.malware + stats.tools,
        failed: 0,
    };
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    syncMitreAttack()
        .then(stats => {
            log.info('ATT&CK sync finished', stats);
            process.exit(0);
        })
        .catch(err => {
            log.error('Sync failed', err);
            process.exit(1);
        });
}
