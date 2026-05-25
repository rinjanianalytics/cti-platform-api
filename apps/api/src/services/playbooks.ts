/**
 * Playbooks Service
 *
 * Event-driven automation: "when EVENT occurs, if CONDITIONS match, run ACTIONS."
 * Integrates with the webhook event system as the trigger source.
 *
 * Supported actions:
 *   - enrich: Queue IOC for enrichment
 *   - notify: Send notification via webhook
 *   - alert: Create an alert
 *   - tag: Add tags to entity
 *   - warninglist_check: Check against warninglists
 */

import { playbooks, playbookExecutions, iocs, type PlaybookAction, type PlaybookActionResult } from '@rinjani/db/schema';
import { and, desc, eq, sql } from '@rinjani/db';
import { getPostgres } from '../lib/db/clients';
import { createLogger } from '../lib/logger';

const log = createLogger('Playbooks');

// ============================================================================
// CRUD Operations
// ============================================================================

export async function getPlaybooks(enabledOnly = false) {
    const db = await getPostgres();

    const condition = enabledOnly ? eq(playbooks.enabled, true) : undefined;
    return db.select().from(playbooks).where(condition).orderBy(desc(playbooks.createdAt));
}

export async function getPlaybookById(id: string) {
    const db = await getPostgres();
    const [pb] = await db.select().from(playbooks).where(eq(playbooks.id, id));
    return pb || null;
}

export async function createPlaybook(data: {
    name: string;
    description?: string;
    triggerEvent: string;
    conditions?: Record<string, unknown>;
    actions: PlaybookAction[];
    createdBy?: string;
}) {
    const db = await getPostgres();

    const [pb] = await db.insert(playbooks).values({
        name: data.name,
        description: data.description,
        triggerEvent: data.triggerEvent,
        conditions: data.conditions || {},
        actions: data.actions,
        createdBy: data.createdBy,
    }).returning();

    log.info('Playbook created', { id: pb.id, name: pb.name, trigger: pb.triggerEvent });
    return pb;
}

export async function updatePlaybook(id: string, data: Partial<{
    name: string;
    description: string;
    triggerEvent: string;
    conditions: Record<string, unknown>;
    actions: PlaybookAction[];
    enabled: boolean;
}>) {
    const db = await getPostgres();

    const [pb] = await db.update(playbooks)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(playbooks.id, id))
        .returning();

    return pb || null;
}

export async function deletePlaybook(id: string) {
    const db = await getPostgres();
    await db.delete(playbooks).where(eq(playbooks.id, id));
    log.info('Playbook deleted', { id });
}

// ============================================================================
// Execution History
// ============================================================================

export async function getExecutions(playbookId: string, limit = 50, offset = 0) {
    const db = await getPostgres();

    const items = await db.select()
        .from(playbookExecutions)
        .where(eq(playbookExecutions.playbookId, playbookId))
        .orderBy(desc(playbookExecutions.startedAt))
        .limit(limit)
        .offset(offset);

    const [{ count }] = await db.select({ count: sql<number>`count(*)::int` })
        .from(playbookExecutions)
        .where(eq(playbookExecutions.playbookId, playbookId));

    return { items, total: count };
}

// ============================================================================
// Playbook Execution
// ============================================================================

export async function executePlaybook(
    playbookId: string,
    triggerData: Record<string, unknown>
): Promise<typeof playbookExecutions.$inferSelect> {
    const db = await getPostgres();

    const pb = await getPlaybookById(playbookId);
    if (!pb) throw new Error(`Playbook ${playbookId} not found`);

    // Create execution record
    const [execution] = await db.insert(playbookExecutions).values({
        playbookId,
        triggerData,
        status: 'running',
    }).returning();

    const results: PlaybookActionResult[] = [];
    let finalStatus: 'completed' | 'failed' = 'failed';
    let finalError: string | null = null;

    try {
        // Execute actions in order
        for (const action of (pb.actions as PlaybookAction[])) {
            const result = await executeAction(action, triggerData);
            results.push(result);

            // Stop on failure (short-circuit)
            if (!result.success) {
                log.warn('Playbook action failed, stopping execution', {
                    playbookId,
                    action: action.type,
                    error: result.error,
                });
                break;
            }
        }

        const allSuccess = results.every(r => r.success);
        finalStatus = allSuccess ? 'completed' : 'failed';
        finalError = allSuccess ? null : results.find(r => !r.success)?.error || null;
    } catch (err) {
        finalStatus = 'failed';
        finalError = (err as Error).message;
        log.error('Playbook execution error', {
            playbookId,
            executionId: execution.id,
            error: finalError,
        });
    }

    // Single update site — return the final row so the client sees the real
    // status (the previous return shape had no status field, which surfaced
    // as "Status: undefined" in the dashboard's run-now toast).
    const [finalRow] = await db.update(playbookExecutions)
        .set({
            status: finalStatus,
            results,
            error: finalError,
            completedAt: new Date(),
        })
        .where(eq(playbookExecutions.id, execution.id))
        .returning();

    log.info('Playbook execution completed', {
        playbookId,
        executionId: execution.id,
        status: finalStatus,
        actionsExecuted: results.length,
    });

    return finalRow;
}

// ============================================================================
// Event Evaluation (called by webhook system)
// ============================================================================

/**
 * Evaluate all enabled playbooks against an incoming event.
 * Returns the IDs of playbooks that were triggered.
 */
export async function evaluatePlaybooks(
    event: string,
    eventData: Record<string, unknown>
): Promise<string[]> {
    const db = await getPostgres();
    const triggeredIds: string[] = [];

    // Find playbooks matching this event
    const matchingPlaybooks = await db.select()
        .from(playbooks)
        .where(
            and(
                eq(playbooks.enabled, true),
                eq(playbooks.triggerEvent, event),
            )
        );

    // Also check wildcard playbooks (e.g., "ioc.*" matches "ioc.created")
    const eventPrefix = event.split('.')[0] + '.*';
    const wildcardPlaybooks = await db.select()
        .from(playbooks)
        .where(
            and(
                eq(playbooks.enabled, true),
                eq(playbooks.triggerEvent, eventPrefix),
            )
        );

    const allMatching = [...matchingPlaybooks, ...wildcardPlaybooks];

    for (const pb of allMatching) {
        // Check conditions
        if (!matchesConditions(pb.conditions as Record<string, unknown>, eventData)) {
            continue;
        }

        // Execute asynchronously (fire-and-forget; execution is tracked in DB)
        executePlaybook(pb.id, eventData).catch(err => {
            log.error('Background playbook execution failed', {
                playbookId: pb.id,
                error: (err as Error).message,
            });
        });

        triggeredIds.push(pb.id);
    }

    if (triggeredIds.length > 0) {
        log.info('Playbooks triggered by event', {
            event,
            triggered: triggeredIds.length,
        });
    }

    return triggeredIds;
}

// ============================================================================
// Action Executor
// ============================================================================

async function executeAction(
    action: PlaybookAction,
    triggerData: Record<string, unknown>
): Promise<PlaybookActionResult> {
    const startTime = new Date();

    try {
        switch (action.type) {
            case 'enrich': {
                // Queue the IOC for enrichment via BullMQ
                const { enrichmentQueue } = await import('../queues/definitions');
                const iocId = (triggerData.iocId || triggerData.id) as string;
                if (iocId) {
                    await enrichmentQueue.add('playbook-enrich', {
                        iocId,
                        source: 'playbook',
                        providers: (action.config.providers as string[]) || ['virustotal'],
                    });
                }
                return {
                    action: 'enrich',
                    success: true,
                    result: { queued: true, iocId },
                    executedAt: startTime.toISOString(),
                };
            }

            case 'notify': {
                const { emitWebhookEvent } = await import('@rinjani/core/webhooks');
                const result = await emitWebhookEvent('playbook.notification', {
                    ...triggerData,
                    message: action.config.message || 'Playbook notification',
                    channel: action.config.channel || 'default',
                });
                return {
                    action: 'notify',
                    success: result.delivered > 0 || result.failed === 0,
                    result: { delivered: result.delivered, failed: result.failed },
                    executedAt: startTime.toISOString(),
                };
            }

            case 'alert': {
                const { alertsQueue } = await import('../queues/definitions');
                await alertsQueue.add('playbook-alert', {
                    title: (action.config.title as string) || 'Playbook Alert',
                    severity: (action.config.severity as string) || 'medium',
                    source: 'playbook',
                    details: triggerData,
                });
                return {
                    action: 'alert',
                    success: true,
                    result: { queued: true },
                    executedAt: startTime.toISOString(),
                };
            }

            case 'tag': {
                const db = await getPostgres();
                const iocId = (triggerData.iocId || triggerData.id) as string;
                const newTags = (action.config.tags as string[]) || [];

                if (iocId && newTags.length > 0) {
                    // Append tags to the IOC's existing tags
                    await db.update(iocs)
                        .set({
                            tags: sql`array_cat(COALESCE(${iocs.tags}, ARRAY[]::text[]), ${newTags}::text[])`,
                        })
                        .where(eq(iocs.id, iocId));
                }

                return {
                    action: 'tag',
                    success: true,
                    result: { iocId, addedTags: newTags },
                    executedAt: startTime.toISOString(),
                };
            }

            case 'warninglist_check': {
                const { checkAgainstWarninglists } = await import('./warninglists');
                const value = (triggerData.value || triggerData.iocValue) as string;
                const iocType = (triggerData.type || triggerData.iocType) as string;

                if (value) {
                    const matches = await checkAgainstWarninglists(value, iocType);
                    return {
                        action: 'warninglist_check',
                        success: true,
                        result: { value, matches, isWarningListed: matches.length > 0 },
                        executedAt: startTime.toISOString(),
                    };
                }

                return {
                    action: 'warninglist_check',
                    success: true,
                    result: { value: null, matches: [], isWarningListed: false },
                    executedAt: startTime.toISOString(),
                };
            }

            default:
                return {
                    action: action.type,
                    success: false,
                    error: `Unknown action type: ${action.type}`,
                    executedAt: startTime.toISOString(),
                };
        }
    } catch (err) {
        return {
            action: action.type,
            success: false,
            error: (err as Error).message,
            executedAt: startTime.toISOString(),
        };
    }
}

// ============================================================================
// Condition Matching
// ============================================================================

/**
 * Simple condition matching: checks if eventData matches all conditions.
 * Supports arrays (any match) and direct value comparison.
 *
 * Example conditions:
 *   { severity: ["high", "critical"] }  → matches if eventData.severity is "high" or "critical"
 *   { source: "alienvault" }            → matches if eventData.source === "alienvault"
 *   { type: ["ip", "domain"] }          → matches if eventData.type is "ip" or "domain"
 */
function matchesConditions(
    conditions: Record<string, unknown>,
    eventData: Record<string, unknown>
): boolean {
    if (!conditions || Object.keys(conditions).length === 0) return true;

    for (const [key, expected] of Object.entries(conditions)) {
        const actual = eventData[key];
        if (actual === undefined) continue; // Skip conditions for missing fields

        if (Array.isArray(expected)) {
            // Array condition: any value must match
            if (!expected.includes(actual)) return false;
        } else {
            // Direct comparison
            if (actual !== expected) return false;
        }
    }

    return true;
}
