-- AA.4 — Agent memory.
--
-- Every agentic-analytics run (POST /v1/agent/run) is persisted here: the
-- question, the synthesized answer, the full ReAct step trace, and any writes
-- the agent PROPOSED (staged, not applied). This is the agent's memory —
-- provenance ("how did it reach this?") + a substrate to reuse prior runs as
-- context later (AA.4+). Mirrors the extracted_reports draft pattern.
--
-- Idempotent: CREATE ... IF NOT EXISTS so it can be applied via db:apply or psql.

CREATE TABLE IF NOT EXISTS "agent_runs" (
    "id"               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "question"         text NOT NULL,
    -- Final synthesized answer. NULL while running / on failure.
    "answer"           text,
    -- The ReAct trace: [{thought, tool, args, observation}, ...].
    "steps"            jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- Writes the agent proposed but did NOT apply — awaiting human commit.
    "proposed_actions" jsonb NOT NULL DEFAULT '[]'::jsonb,
    -- 'final' | 'max-steps' | 'no-answer' | 'error'
    "stop_reason"      varchar(20),
    -- 'completed' | 'failed' (room for 'running' when AA.4b makes runs async).
    "status"           varchar(20) NOT NULL DEFAULT 'completed',
    "step_count"       integer NOT NULL DEFAULT 0,
    "provider"         varchar(50),
    "model"            varchar(100),
    "error"            text,
    "created_by"       text,
    "created_at"       timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT agent_runs_status_check
        CHECK (status IN ('completed', 'failed', 'running'))
);

CREATE INDEX IF NOT EXISTS "agent_runs_created_at_idx"
    ON "agent_runs" ("created_at" DESC);
CREATE INDEX IF NOT EXISTS "agent_runs_status_idx"
    ON "agent_runs" ("status");
