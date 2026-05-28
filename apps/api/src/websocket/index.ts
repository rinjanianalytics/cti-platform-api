/**
 * WebSocket Subscriptions for Real-Time Threat Updates
 * 
 * Provides real-time push notifications for:
 * - New vulnerabilities (CVEs)
 * - New IOCs detected
 * - Critical alerts
 * - Sync status updates
 * 
 * Note: This module requires Bun runtime for WebSocket support.
 * For Node.js, use ws or socket.io instead.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { createLogger } from '../lib/logger';

const log = createLogger('WebSocket');

// ============================================================================
// Types
// ============================================================================

export interface WSMessage {
    type: 'vulnerability' | 'ioc' | 'alert' | 'sync' | 'heartbeat' | 'subscribe' | 'unsubscribe';
    channel?: string;
    data?: unknown;
    timestamp: string;
}

export interface WSClient {
    id: string;
    subscriptions: Set<string>;
    connectedAt: Date;
    lastPing?: Date;
}

export interface ConnectionStats {
    totalClients: number;
    channels: Record<string, number>;
}

// ============================================================================
// WebSocket Manager (in-memory for single instance)
// ============================================================================

class WebSocketManager {
    private clients: Map<string, WSClient> = new Map();
    private channels: Map<string, Set<string>> = new Map();
    private messageBuffer: Map<string, WSMessage[]> = new Map();

    constructor() {
        // Initialize default channels
        this.channels.set('vulnerabilities', new Set());
        this.channels.set('iocs', new Set());
        this.channels.set('alerts', new Set());
        this.channels.set('sync', new Set());
        this.channels.set('webint', new Set());    // Web intelligence items
        this.channels.set('socmint', new Set());   // Social media intelligence
        this.channels.set('campaign', new Set());  // Campaign activity
        this.channels.set('all', new Set());
    }

    /**
     * Register a new client (for SSE or polling fallback)
     */
    registerClient(clientId?: string): string {
        const id = clientId || crypto.randomUUID();
        const client: WSClient = {
            id,
            subscriptions: new Set(['all']),
            connectedAt: new Date(),
        };

        this.clients.set(id, client);
        this.channels.get('all')?.add(id);
        this.messageBuffer.set(id, []);

        log.info('Client registered', { clientId: id, totalClients: this.clients.size });
        return id;
    }

    /**
     * Unregister a client
     */
    unregisterClient(id: string): void {
        const client = this.clients.get(id);
        if (client) {
            for (const channel of client.subscriptions) {
                this.channels.get(channel)?.delete(id);
            }
            this.clients.delete(id);
            this.messageBuffer.delete(id);
            log.info('Client unregistered', { clientId: id, remaining: this.clients.size });
        }
    }

    /**
     * Subscribe client to a channel
     */
    subscribe(clientId: string, channel: string): boolean {
        const client = this.clients.get(clientId);
        if (!client) return false;

        if (!this.channels.has(channel)) {
            this.channels.set(channel, new Set());
        }

        client.subscriptions.add(channel);
        this.channels.get(channel)?.add(clientId);
        log.info('Client subscribed', { clientId, channel });
        return true;
    }

    /**
     * Unsubscribe client from a channel
     */
    unsubscribe(clientId: string, channel: string): boolean {
        const client = this.clients.get(clientId);
        if (!client) return false;

        client.subscriptions.delete(channel);
        this.channels.get(channel)?.delete(clientId);
        log.info('Client unsubscribed', { clientId, channel });
        return true;
    }

    /**
     * Broadcast message to all subscribers of a channel
     */
    broadcast(channel: string, message: Omit<WSMessage, 'timestamp'>): void {
        const fullMessage: WSMessage = {
            ...message,
            channel,
            timestamp: new Date().toISOString(),
        };

        const subscribers = this.channels.get(channel);
        const allSubscribers = this.channels.get('all');

        const recipients = new Set<string>();
        if (subscribers) {
            for (const id of subscribers) recipients.add(id);
        }
        if (allSubscribers && channel !== 'all') {
            for (const id of allSubscribers) recipients.add(id);
        }

        // Buffer messages for polling clients
        for (const clientId of recipients) {
            const buffer = this.messageBuffer.get(clientId);
            if (buffer) {
                buffer.push(fullMessage);
                // Keep last 100 messages per client
                if (buffer.length > 100) buffer.shift();
            }
        }

        log.info('Broadcast', { channel, recipients: recipients.size });
    }

    /**
     * Get pending messages for a client (polling)
     */
    getMessages(clientId: string): WSMessage[] {
        const buffer = this.messageBuffer.get(clientId);
        if (!buffer) return [];

        const messages = [...buffer];
        buffer.length = 0; // Clear buffer
        return messages;
    }

    /**
     * Get connection stats
     */
    getStats(): ConnectionStats {
        return {
            totalClients: this.clients.size,
            channels: Object.fromEntries(
                Array.from(this.channels.entries()).map(([name, subs]) => [name, subs.size])
            ),
        };
    }
}

// Singleton instance
export const wsManager = new WebSocketManager();

// ============================================================================
// Hono REST Routes (SSE + Polling fallback)
// ============================================================================

export const wsApp = new Hono();

// Register new client
wsApp.post('/ws/connect', (c: Context) => {
    const clientId = wsManager.registerClient();
    return c.json({
        success: true,
        data: {
            clientId,
            message: 'Connected to V3 Threat Intel',
            channels: ['all', 'vulnerabilities', 'iocs', 'alerts', 'sync', 'webint', 'socmint', 'campaign'],
        },
    });
});

// Disconnect client
wsApp.post('/ws/disconnect', async (c: Context) => {
    const body = await c.req.json() as { clientId: string };
    wsManager.unregisterClient(body.clientId);
    return c.json({ success: true });
});

// Subscribe to channel
wsApp.post('/ws/subscribe', async (c: Context) => {
    const body = await c.req.json() as { clientId: string; channel: string };
    const success = wsManager.subscribe(body.clientId, body.channel);
    return c.json({ success });
});

// Unsubscribe from channel
wsApp.post('/ws/unsubscribe', async (c: Context) => {
    const body = await c.req.json() as { clientId: string; channel: string };
    const success = wsManager.unsubscribe(body.clientId, body.channel);
    return c.json({ success });
});

// Poll for messages (long-polling alternative)
wsApp.get('/ws/poll/:clientId', (c: Context) => {
    const clientId = c.req.param('clientId');
    if (!clientId) return c.json({ success: false, error: 'clientId required' }, 400);
    const messages = wsManager.getMessages(clientId);
    return c.json({
        success: true,
        data: { messages, count: messages.length },
    });
});

// Get stats
wsApp.get('/ws/stats', (c: Context) => {
    return c.json({
        success: true,
        data: wsManager.getStats(),
    });
});

// ============================================================================
// Helper functions for broadcasting events
// ============================================================================

/**
 * Broadcast a new vulnerability notification
 */
export function notifyNewVulnerability(vuln: {
    cveId: string;
    severity: string;
    description: string;
}): void {
    wsManager.broadcast('vulnerabilities', {
        type: 'vulnerability',
        data: { event: 'new', ...vuln },
    });
}

/**
 * Broadcast a new IOC notification
 */
export function notifyNewIOC(ioc: {
    type: string;
    value: string;
    source: string;
    threatType?: string;
}): void {
    wsManager.broadcast('iocs', {
        type: 'ioc',
        data: { event: 'new', ...ioc },
    });
}

/**
 * Broadcast a critical alert
 */
export function notifyCriticalAlert(alert: {
    title: string;
    message: string;
    severity: 'critical' | 'high' | 'medium';
    source: string;
}): void {
    wsManager.broadcast('alerts', {
        type: 'alert',
        data: alert,
    });
}

/**
 * Broadcast sync status update
 */
export function notifySyncStatus(status: {
    feed: string;
    status: 'started' | 'completed' | 'failed';
    processed?: number;
    failed?: number;
    message?: string;
}): void {
    wsManager.broadcast('sync', {
        type: 'sync',
        data: status,
    });
}

export default wsApp;
