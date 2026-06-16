/**
 * Agent run persistence (AA.4 — agent memory).
 *
 * Saves each completed/failed run to agent_runs and reads them back. This is
 * the agent's memory: the full trace + proposed actions are durable, so a run
 * is auditable after the fact and reusable as context later. Kept separate from
 * the orchestrator (which stays a pure function) — the route persists the
 * result, so runAgent has no DB dependency and stays trivially testable.
 */

import { db, eq, desc } from '@rinjani/db';
import { agentRuns } from '@rinjani/db/schema';
import type { AgentRun, AgentRunStatus } from '@rinjani/db/schema';
import type { AgentRunResult } from './orchestrator';
import { createLogger } from '../../lib/logger';

const log = createLogger('AgentRunStore');

/** Persist a completed run; returns the new row id. Never throws into the request. */
export async function saveRun(result: AgentRunResult, createdBy: string): Promise<string | null> {
    try {
        const [row] = await db
            .insert(agentRuns)
            .values({
                question: result.question,
                answer: result.answer,
                steps: result.steps,
                proposedActions: result.proposedActions,
                stopReason: result.stopReason,
                status: 'completed' as AgentRunStatus,
                stepCount: result.meta.steps,
                provider: result.meta.provider || null,
                model: result.meta.model || null,
                createdBy,
            })
            .returning({ id: agentRuns.id });
        return row?.id ?? null;
    } catch (err) {
        // Persistence must not fail the run — the answer is already computed.
        log.warn('failed to persist agent run', { error: (err as Error).message });
        return null;
    }
}

/** Persist a failed run (the orchestrator threw before producing a result). */
export async function saveFailedRun(question: string, error: string, createdBy: string): Promise<string | null> {
    try {
        const [row] = await db
            .insert(agentRuns)
            .values({ question, status: 'failed' as AgentRunStatus, stopReason: 'error', error, createdBy })
            .returning({ id: agentRuns.id });
        return row?.id ?? null;
    } catch (err) {
        log.warn('failed to persist failed agent run', { error: (err as Error).message });
        return null;
    }
}

export async function getRun(id: string): Promise<AgentRun | null> {
    const [row] = await db.select().from(agentRuns).where(eq(agentRuns.id, id)).limit(1);
    return row ?? null;
}

export async function listRuns(limit = 25): Promise<AgentRun[]> {
    const capped = Math.min(100, Math.max(1, limit));
    return db.select().from(agentRuns).orderBy(desc(agentRuns.createdAt)).limit(capped);
}
