/**
 * AA.4 — Agent memory.
 *
 * Migration: drizzle/0064_agent_runs.sql
 *
 * One row per agentic-analytics run: the question, the synthesized answer, the
 * full ReAct step trace, and the writes the agent PROPOSED (staged, not
 * applied). The agent's memory — provenance + a substrate for reusing prior
 * runs as context (AA.4+).
 */
import { pgTable, uuid, varchar, text, integer, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

export type AgentRunStatus = 'completed' | 'failed' | 'running';
export type AgentRunStopReason = 'final' | 'max-steps' | 'no-answer' | 'error';

/** One ReAct step — mirrors the orchestrator's AgentStep. */
export interface AgentRunStep {
    thought?: string;
    tool?: string;
    args?: unknown;
    observation: string;
}

/** A staged (un-applied) write the agent proposed — mirrors AgentProposedAction. */
export interface AgentRunProposedAction {
    tool: string;
    args: unknown;
    summary: string;
}

export const agentRuns = pgTable('agent_runs', {
    id: uuid('id').primaryKey().defaultRandom(),
    question: text('question').notNull(),
    answer: text('answer'),
    steps: jsonb('steps').$type<AgentRunStep[]>().notNull().default([]),
    proposedActions: jsonb('proposed_actions').$type<AgentRunProposedAction[]>().notNull().default([]),
    stopReason: varchar('stop_reason', { length: 20 }).$type<AgentRunStopReason>(),
    status: varchar('status', { length: 20 }).notNull().default('completed').$type<AgentRunStatus>(),
    stepCount: integer('step_count').notNull().default(0),
    provider: varchar('provider', { length: 50 }),
    model: varchar('model', { length: 100 }),
    error: text('error'),
    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    createdAtIdx: index('agent_runs_created_at_idx').on(table.createdAt),
    statusIdx: index('agent_runs_status_idx').on(table.status),
}));

export type AgentRun = typeof agentRuns.$inferSelect;
export type NewAgentRun = typeof agentRuns.$inferInsert;
