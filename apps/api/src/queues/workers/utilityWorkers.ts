/**
 * Utility Workers — AI Analysis, Notifications, Alerts
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import { analyzeIOC } from '../../services/aiAnalysis';
import { sendSlackNotification, sendEmailNotification, createInAppNotification } from '../../services/notifications';
import type { NotificationPayload } from '../../services/notifications';
import type { AIAnalysisJobData, NotificationJobData, AlertJobData } from '../index';
import { notificationQueue } from '../index';
import { createLogger } from '../../lib/logger';
import { runJobWithSpan } from '../tracing';
import { insertAlert } from '../../services/alertsStore';

// ============================================================================
// AI Analysis Worker
// ============================================================================

export const aiAnalysisWorker = new Worker<AIAnalysisJobData>(
    'ai-analysis',
    async (job: Job<AIAnalysisJobData>) => runJobWithSpan('ai-analysis', job, async () => {
        const log = createLogger('AIAnalysis');
        log.info('Processing job', { jobId: job.id, iocValue: job.data.iocValue });

        const { iocId, iocValue, analysisType } = job.data;

        try {
            await job.updateProgress(10);

            log.info('Running analysis', { analysisType, iocValue });
            await job.updateProgress(30);

            const result = await analyzeIOC({
                iocId,
                iocValue,
                analysisType,
            });

            await job.updateProgress(100);

            return result;
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            throw error;
        }
    }),
    {
        connection,
        concurrency: 3,
    }
);

// ============================================================================
// Notification Worker
// ============================================================================

export const notificationWorker = new Worker<NotificationJobData>(
    'notifications',
    async (job: Job<NotificationJobData>) => runJobWithSpan('notifications', job, async () => {
        const log = createLogger('Notification');
        log.info('Processing job', { jobId: job.id, channel: job.data.channel, target: job.data.target });

        const { channel, target, payload } = job.data;

        try {
            await job.updateProgress(10);

            let result: { success: boolean; error?: string };

            switch (channel) {
                case 'slack':
                    log.info('Sending Slack notification', { target });
                    result = await sendSlackNotification(target, payload as NotificationPayload);
                    break;

                case 'email':
                    log.info('Sending Email notification', { target });
                    result = await sendEmailNotification(target, payload as NotificationPayload);
                    break;

                case 'webhook':
                    log.info('Sending webhook', { target });
                    const response = await fetch(target, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload),
                    });
                    result = { success: response.ok, error: response.ok ? undefined : `HTTP ${response.status}` };
                    break;

                default:
                    throw new Error(`Unknown notification channel: ${channel}`);
            }

            await job.updateProgress(100);

            if (!result.success) {
                throw new Error(result.error || 'Notification delivery failed');
            }

            return {
                success: true,
                channel,
                target,
                deliveredAt: new Date().toISOString(),
            };
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            throw error;
        }
    }),
    {
        connection,
        concurrency: 10, // Higher concurrency for notification delivery
    }
);

// ============================================================================
// Alerts Worker
// ============================================================================

export const alertsWorker = new Worker<AlertJobData>(
    'alerts',
    async (job: Job<AlertJobData>) => runJobWithSpan('alerts', job, async () => {
        const log = createLogger('Alerts');
        log.info('Processing job', { jobId: job.id, title: job.data.title });

        const { severity, type, title, message, source, metadata } = job.data;

        try {
            // Persist the alert to the durable store (table `alerts`). Best-effort
            // so a not-yet-migrated table can't fail the job or block the in-app
            // notification below (which powers the bell).
            let stored: Awaited<ReturnType<typeof insertAlert>> = null;
            try {
                stored = await insertAlert({ id: job.id as string, severity, type, title, message, source, metadata: metadata ?? {} });
                log.info('Alert stored', { alertId: job.id, title, severity });
            } catch (err) {
                log.warn('alert persist deferred (table migrated?)', { err: String(err) });
            }

            // Persist to DB so the dashboard notification bell shows it
            await createInAppNotification({
                type: severity === 'critical' || severity === 'high' ? 'warning' : 'info',
                title,
                message,
                source,
                metadata: { ...metadata, severity, alertType: type },
            });

            // For high/critical severity, trigger notification delivery
            if (severity === 'high' || severity === 'critical') {
                const webhookUrl = process.env.ALERT_WEBHOOK_URL;
                if (webhookUrl) {
                    log.info('High severity alert, queueing notifications', { severity });
                    await notificationQueue.add(`alert-notify-${job.id}`, {
                        channel: 'webhook',
                        target: webhookUrl,
                        payload: {
                            type: 'alert',
                            severity,
                            title,
                            message,
                            data: metadata,
                        },
                    });
                } else {
                    log.debug('High severity alert stored (no ALERT_WEBHOOK_URL configured)', { severity, title });
                }
            }

            return {
                success: true,
                alertId: job.id,
                severity,
                storedAt: (stored?.createdAt ?? new Date()).toISOString(),
            };
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            throw error;
        }
    }),
    {
        connection,
        concurrency: 20, // Fast processing for alerts
    }
);
