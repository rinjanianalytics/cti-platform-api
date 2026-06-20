/**
 * Alerts store — DB-backed (table `alerts`), replacing the in-memory array that
 * reset on every restart. Adds server-side faceting (severity / source / type /
 * read) while keeping the route response shape a superset of the old object.
 */
import { db, and, eq, inArray, desc, count, sql, alerts, type AlertRow, type NewAlertRow } from '@rinjani/db';

export interface AlertListFilters {
    page: number;
    limit: number;
    severity?: string;
    source?: string;
    type?: string;
    unread?: boolean;          // legacy alias: unread=true → read=false
    read?: boolean;
}

function whereClause(f: Pick<AlertListFilters, 'severity' | 'source' | 'type' | 'unread' | 'read'>) {
    const conds = [];
    if (f.severity) conds.push(eq(alerts.severity, f.severity));
    if (f.source) conds.push(eq(alerts.source, f.source));
    if (f.type) conds.push(eq(alerts.type, f.type));
    if (f.unread === true) conds.push(eq(alerts.read, false));
    if (typeof f.read === 'boolean') conds.push(eq(alerts.read, f.read));
    return conds.length ? and(...conds) : undefined;
}

export async function listAlerts(f: AlertListFilters): Promise<{ items: AlertRow[]; total: number }> {
    const where = whereClause(f);
    const [items, [total]] = await Promise.all([
        db.select().from(alerts).where(where).orderBy(desc(alerts.createdAt)).limit(f.limit).offset((f.page - 1) * f.limit),
        db.select({ n: count() }).from(alerts).where(where),
    ]);
    return { items, total: total?.n ?? 0 };
}

export async function unreadCounts(): Promise<{ unread: number; highSeverity: number }> {
    const [[u], [h]] = await Promise.all([
        db.select({ n: count() }).from(alerts).where(eq(alerts.read, false)),
        db.select({ n: count() }).from(alerts).where(and(eq(alerts.read, false), inArray(alerts.severity, ['high', 'critical']))),
    ]);
    return { unread: u?.n ?? 0, highSeverity: h?.n ?? 0 };
}

/** Distinct facet values (for the dashboard's filter rails). */
export async function alertFacets(): Promise<{ sources: { value: string; count: number }[]; types: { value: string; count: number }[] }> {
    const [sources, types] = await Promise.all([
        db.select({ value: sql<string>`COALESCE(${alerts.source}, 'unknown')`, count: count() }).from(alerts).groupBy(sql`COALESCE(${alerts.source}, 'unknown')`),
        db.select({ value: alerts.type, count: count() }).from(alerts).groupBy(alerts.type),
    ]);
    return { sources, types: types.map((t) => ({ value: t.value, count: t.count })) };
}

export async function getAlert(id: string): Promise<AlertRow | null> {
    const [row] = await db.select().from(alerts).where(eq(alerts.id, id)).limit(1);
    return row ?? null;
}

/** Insert (idempotent on id — the worker reuses the BullMQ job id). */
export async function insertAlert(a: NewAlertRow): Promise<AlertRow | null> {
    const [row] = await db.insert(alerts).values(a).onConflictDoNothing().returning();
    return row ?? (a.id ? getAlert(a.id) : null);
}

export async function alertExistsForIoc(iocId: string): Promise<boolean> {
    const [row] = await db.select({ id: alerts.id }).from(alerts)
        .where(and(eq(alerts.type, 'high_risk_ioc'), sql`${alerts.metadata}->>'iocId' = ${iocId}`)).limit(1);
    return !!row;
}

const touch = () => ({ updatedAt: new Date() });

export async function markRead(id: string): Promise<boolean> {
    const r = await db.update(alerts).set({ read: true, ...touch() }).where(eq(alerts.id, id)).returning({ id: alerts.id });
    return r.length > 0;
}

export async function markAllRead(): Promise<number> {
    const r = await db.update(alerts).set({ read: true, ...touch() }).where(eq(alerts.read, false)).returning({ id: alerts.id });
    return r.length;
}

export async function acknowledge(id: string): Promise<boolean> {
    const r = await db.update(alerts).set({ read: true, acknowledged: true, acknowledgedAt: new Date(), ...touch() }).where(eq(alerts.id, id)).returning({ id: alerts.id });
    return r.length > 0;
}

export async function bulkAcknowledge(ids: string[]): Promise<number> {
    const r = await db.update(alerts).set({ read: true, acknowledged: true, acknowledgedAt: new Date(), ...touch() })
        .where(and(inArray(alerts.id, ids), eq(alerts.acknowledged, false))).returning({ id: alerts.id });
    return r.length;
}

export async function deleteAlert(id: string): Promise<boolean> {
    const r = await db.delete(alerts).where(eq(alerts.id, id)).returning({ id: alerts.id });
    return r.length > 0;
}

export async function updateAlert(id: string, updates: Partial<Pick<AlertRow, 'severity' | 'title' | 'message' | 'read'>> & { metadata?: Record<string, unknown> }): Promise<AlertRow | null> {
    const current = await getAlert(id);
    if (!current) return null;
    const [row] = await db.update(alerts).set({
        ...(updates.severity ? { severity: updates.severity } : {}),
        ...(updates.title ? { title: updates.title } : {}),
        ...(updates.message ? { message: updates.message } : {}),
        ...(typeof updates.read === 'boolean' ? { read: updates.read } : {}),
        ...(updates.metadata ? { metadata: { ...current.metadata, ...updates.metadata } } : {}),
        ...touch(),
    }).where(eq(alerts.id, id)).returning();
    return row ?? null;
}

/** Escalate: bump severity, re-flag unread, merge escalation metadata. */
export async function escalateAlert(id: string, patch: { priority: string; escalatedBy?: string; assignee?: string; notes?: string; tags?: string[] }): Promise<AlertRow | null> {
    const current = await getAlert(id);
    if (!current) return null;
    const [row] = await db.update(alerts).set({
        severity: patch.priority,
        read: false,
        metadata: {
            ...current.metadata,
            escalated: true,
            escalatedAt: new Date().toISOString(),
            escalatedBy: patch.escalatedBy ?? 'unknown',
            assignee: patch.assignee,
            escalationNotes: patch.notes,
            escalationTags: patch.tags,
        },
        ...touch(),
    }).where(eq(alerts.id, id)).returning();
    return row ?? null;
}
