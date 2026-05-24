/**
 * Admin Routes — Dashboard Management API
 *
 * All handler logic has been decomposed into sub-modules under ./admin/.
 * Provides: queues, events, jobs, DLQ, users, audit logs, config/settings.
 */

import { Hono } from 'hono';
import queueRoutes from './admin/queues';
import eventRoutes from './admin/events';
import jobRoutes from './admin/jobs';
import dlqRoutes from './admin/dlq';
import userRoutes from './admin/users';
import auditRoutes from './admin/audit';
import configRoutes from './admin/config';
import sandboxRoutes from './admin/sandbox';
import streamRoutes from './admin/streams';
import federationRoutes from './admin/federation';
import rbacRoutes from './admin/rbac';
import servicesRoutes from './admin/services';
import schedulesRoutes from './admin/schedules';
import activityRoutes from './admin/activity';
import feedsRoutes from './admin/feeds';

export const adminRouter = new Hono();

// Bull Board dashboard + stats
adminRouter.route('/', queueRoutes);

// SSE event streams
adminRouter.route('/', eventRoutes);

// Job trigger endpoints
adminRouter.route('/', jobRoutes);

// Dead Letter Queue inspection
adminRouter.route('/', dlqRoutes);

// User management CRUD
adminRouter.route('/', userRoutes);

// Audit log inspection
adminRouter.route('/', auditRoutes);

// Config & settings management
adminRouter.route('/', configRoutes);

// API Sandbox (connectivity tester)
adminRouter.route('/', sandboxRoutes);

// Redis Streams event monitoring
adminRouter.route('/', streamRoutes);

// Federation & Migrations management
adminRouter.route('/', federationRoutes);

// RBAC — role permissions, access matrix, Keycloak mapping
adminRouter.route('/rbac', rbacRoutes);

// Service health aggregator — datastores + workers + queues + feeds + LLM
adminRouter.route('/', servicesRoutes);

// Scheduled-job control — enable/disable + interval-preset overrides
adminRouter.route('/', schedulesRoutes);

// Live job activity feed — rolling buffer + SSE stream + per-queue throughput
adminRouter.route('/', activityRoutes);

// Feed-centric management — wraps schedules + feed_sync_runs history
adminRouter.route('/', feedsRoutes);

export default adminRouter;
