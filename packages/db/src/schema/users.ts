/**
 * Database Schema - Users & Authentication
 * 
 * Core tables for user management and authentication.
 */

import { pgTable, uuid, varchar, text, timestamp, boolean, jsonb, integer, pgEnum, uniqueIndex } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

// ============================================================================
// Users Table
// ============================================================================

export const users = pgTable('users', {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 255 }).notNull(),
    passwordHash: text('password_hash'),
    apiToken: varchar('api_token', { length: 64 }).unique(),
    avatarUrl: text('avatar_url'),
    isActive: boolean('is_active').default(true).notNull(),
    roles: jsonb('roles').$type<string[]>().default([]),
    permissions: jsonb('permissions').$type<string[]>().default([]),
    lastLogin: timestamp('last_login', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// Organizations Table
// ============================================================================

export const organizationPlanEnum = pgEnum('organization_plan', ['free', 'pro', 'enterprise']);

export const organizations = pgTable('organizations', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 255 }).notNull(),
    slug: varchar('slug', { length: 128 }).unique(),
    description: text('description'),
    plan: organizationPlanEnum('plan').default('free').notNull(),
    settings: jsonb('settings').$type<Record<string, unknown>>().default({}),
    isDefault: boolean('is_default').default(false),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// Organization Quotas Table
// ============================================================================

export const organizationQuotas = pgTable('organization_quotas', {
    id: uuid('id').primaryKey().defaultRandom(),
    orgId: uuid('org_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }).unique(),
    maxIocs: integer('max_iocs').default(10000).notNull(),
    maxWebhooks: integer('max_webhooks').default(3).notNull(),
    maxApiCalls: integer('max_api_calls').default(10000).notNull(),
    maxExportSize: integer('max_export_size').default(1000).notNull(),
});

// ============================================================================
// User Organizations (Many-to-Many)
// ============================================================================

export const userOrganizations = pgTable('user_organizations', {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    role: varchar('role', { length: 50 }).notNull().default('member'),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// API Keys
// ============================================================================

export const apiKeys = pgTable('api_keys', {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    name: varchar('name', { length: 255 }).notNull(),
    keyHash: varchar('key_hash', { length: 64 }).notNull().unique(),
    keyPrefix: varchar('key_prefix', { length: 8 }).notNull(), // For display: "sk_live_xxxx..."
    permissions: jsonb('permissions').$type<string[]>().default([]),
    expiresAt: timestamp('expires_at', { withTimezone: true }),
    lastUsedAt: timestamp('last_used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// OAuth identities — links an external provider account (Google, GitHub, …)
// to a Rinjani user. One user can have multiple identities (sign in with
// either provider, same account). `subject` is the provider's stable user id.
// ============================================================================

export const oauthIdentities = pgTable('oauth_identities', {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    provider: varchar('provider', { length: 32 }).notNull(), // 'google' | 'github' | …
    subject: varchar('subject', { length: 128 }).notNull(),  // provider's user id
    emailAtLink: varchar('email_at_link', { length: 255 }),  // email at time of linking
    linkedAt: timestamp('linked_at', { withTimezone: true }).defaultNow().notNull(),
    lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
}, (table) => ({
    // A provider's subject is unique per provider — one Google sub → one user.
    providerSubjectUnique: uniqueIndex('oauth_identities_provider_subject_unique').on(table.provider, table.subject),
}));

export const oauthIdentitiesRelations = relations(oauthIdentities, ({ one }) => ({
    user: one(users, { fields: [oauthIdentities.userId], references: [users.id] }),
}));

// ============================================================================
// Sessions
// ============================================================================

export const sessions = pgTable('sessions', {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    token: varchar('token', { length: 255 }).notNull().unique(),
    userAgent: text('user_agent'),
    ipAddress: varchar('ip_address', { length: 45 }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// Relations
// ============================================================================

export const usersRelations = relations(users, ({ many }) => ({
    organizations: many(userOrganizations),
    apiKeys: many(apiKeys),
    sessions: many(sessions),
    oauthIdentities: many(oauthIdentities),
}));

export const organizationsRelations = relations(organizations, ({ one, many }) => ({
    members: many(userOrganizations),
    quotas: one(organizationQuotas, {
        fields: [organizations.id],
        references: [organizationQuotas.orgId],
    }),
}));

export const organizationQuotasRelations = relations(organizationQuotas, ({ one }) => ({
    organization: one(organizations, {
        fields: [organizationQuotas.orgId],
        references: [organizations.id],
    }),
}));

export const userOrganizationsRelations = relations(userOrganizations, ({ one }) => ({
    user: one(users, { fields: [userOrganizations.userId], references: [users.id] }),
    organization: one(organizations, { fields: [userOrganizations.organizationId], references: [organizations.id] }),
}));

export const apiKeysRelations = relations(apiKeys, ({ one }) => ({
    user: one(users, { fields: [apiKeys.userId], references: [users.id] }),
}));

export const sessionsRelations = relations(sessions, ({ one }) => ({
    user: one(users, { fields: [sessions.userId], references: [users.id] }),
}));
