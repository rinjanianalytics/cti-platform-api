/**
 * YARA Rule Management Routes
 *
 * REST API for managing and executing YARA-like pattern matching rules.
 *
 *   GET  /v1/yara/rules         → List all loaded rules
 *   GET  /v1/yara/rules/:name   → Get rule details
 *   POST /v1/yara/rules         → Add a new rule
 *   POST /v1/yara/scan          → Scan a value against all rules
 *   POST /v1/yara/batch-scan    → Scan multiple values
 *   PUT  /v1/yara/rules/:name/toggle → Toggle rule enabled/disabled
 *   DELETE /v1/yara/rules/:name → Remove a rule
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    listRules, getRule, addRule, removeRule, toggleRule,
    scanValue, batchScan,
} from '../../services/yaraEngine';
import {
    AddYaraRuleSchema, ToggleYaraRuleSchema, YaraScanSchema, YaraBatchScanSchema,
} from '../../lib/schemas';

const router = new Hono();

// ── List all rules ──────────────────────────────────────────────────

router.get('/yara/rules', requireAuth, (c) => {
    const rules = listRules();
    return c.json({
        success: true,
        data: {
            total: rules.length,
            enabled: rules.filter(r => r.enabled).length,
            rules: rules.map(r => ({
                name: r.name,
                description: r.description,
                severity: r.severity,
                tags: r.tags,
                stringsCount: r.strings.length,
                condition: r.condition,
                enabled: r.enabled,
            })),
        },
    });
});

// ── Get rule detail ─────────────────────────────────────────────────

router.get('/yara/rules/:name', requireAuth, (c) => {
    const name = c.req.param('name')!; // route-guaranteed by :name pattern
    const rule = getRule(name);
    if (!rule) {
        throw new NotFoundError('YARA rule', name);
    }
    return c.json({ success: true, data: rule });
});

// ── Add rule ────────────────────────────────────────────────────────

router.post('/yara/rules', requireAuth, requireRole('admin'), async (c) => {
    const body = AddYaraRuleSchema.parse(await c.req.json());

    const rule = {
        ...body,
        createdAt: new Date().toISOString(),
    };

    addRule(rule);
    return c.json({ success: true, data: rule }, 201);
});

// ── Toggle rule ─────────────────────────────────────────────────────

router.put('/yara/rules/:name/toggle', requireAuth, requireRole('admin'), async (c) => {
    const name = c.req.param('name')!; // route-guaranteed by :name pattern
    const { enabled } = ToggleYaraRuleSchema.parse(await c.req.json());

    const success = toggleRule(name, enabled);
    if (!success) {
        throw new NotFoundError('YARA rule', name);
    }

    return c.json({ success: true, message: `Rule "${name}" ${enabled ? 'enabled' : 'disabled'}` });
});

// ── Delete rule ─────────────────────────────────────────────────────

router.delete('/yara/rules/:name', requireAuth, requireRole('admin'), (c) => {
    const name = c.req.param('name')!; // route-guaranteed by :name pattern
    const deleted = removeRule(name);

    if (!deleted) {
        throw new NotFoundError('YARA rule', name);
    }
    return c.json({ success: true, message: `Rule "${name}" deleted` });
});

// ── Scan a single value ─────────────────────────────────────────────

router.post('/yara/scan', requireAuth, async (c) => {
    const { value } = YaraScanSchema.parse(await c.req.json());

    const result = scanValue(value);
    return c.json({ success: true, data: result });
});

// ── Batch scan ──────────────────────────────────────────────────────

router.post('/yara/batch-scan', requireAuth, async (c) => {
    const { values } = YaraBatchScanSchema.parse(await c.req.json());

    const result = batchScan(values);
    return c.json({ success: true, data: result });
});

export default router;
