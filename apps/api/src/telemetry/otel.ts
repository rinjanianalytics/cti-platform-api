/**
 * OpenTelemetry Instrumentation — Rinjani CTI API
 *
 * Full-stack observability: traces, metrics, and log correlation.
 *
 * When OTEL_EXPORTER_OTLP_ENDPOINT is set, exports to Tempo/Grafana stack.
 * Otherwise runs as a no-op (zero overhead in dev).
 *
 * Usage: import this file FIRST in the entry point:
 *   import './telemetry/otel';
 *
 * Environment:
 *   OTEL_EXPORTER_OTLP_ENDPOINT - e.g. http://v3-tempo:4318
 *   OTEL_SERVICE_NAME           - e.g. rinjani-api
 *   OTEL_ENABLED                - set to 'false' to disable (default: true if endpoint set)
 */

import { createLogger } from '../lib/logger';

const log = createLogger('OTEL');

// ============================================================================
// Lazy initialization — only load heavy OTEL deps if endpoint is configured
// ============================================================================

const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
const serviceName = process.env.OTEL_SERVICE_NAME || 'rinjani-api';
const enabled = process.env.OTEL_ENABLED !== 'false' && !!endpoint;

if (enabled) {
    log.info('OpenTelemetry initializing', { endpoint, serviceName });

    // Dynamic import to avoid loading OTEL in development
    Promise.all([
        import('@opentelemetry/sdk-node'),
        import('@opentelemetry/auto-instrumentations-node'),
        import('@opentelemetry/exporter-trace-otlp-http'),
        import('@opentelemetry/exporter-metrics-otlp-http'),
        import('@opentelemetry/sdk-metrics'),
        import('@opentelemetry/resources'),
        import('@opentelemetry/semantic-conventions'),
    ]).then(([
        { NodeSDK },
        { getNodeAutoInstrumentations },
        { OTLPTraceExporter },
        { OTLPMetricExporter },
        { PeriodicExportingMetricReader },
        { resourceFromAttributes },
        { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION },
    ]) => {
        const resource = resourceFromAttributes({
            [ATTR_SERVICE_NAME]: serviceName,
            [ATTR_SERVICE_VERSION]: '1.0.0',
            'deployment.environment': process.env.NODE_ENV || 'development',
        });

        const traceExporter = new OTLPTraceExporter({
            url: `${endpoint}/v1/traces`,
        });

        const metricExporter = new OTLPMetricExporter({
            url: `${endpoint}/v1/metrics`,
        });

        const metricReader = new PeriodicExportingMetricReader({
            exporter: metricExporter,
            exportIntervalMillis: 30_000,
        });

        const sdk = new NodeSDK({
            resource,
            traceExporter,
            metricReaders: [metricReader],
            instrumentations: [
                getNodeAutoInstrumentations({
                    // Suppress noisy FS instrumentation
                    '@opentelemetry/instrumentation-fs': { enabled: false },
                    // HTTP spans for all requests
                    '@opentelemetry/instrumentation-http': { enabled: true },
                    // pg instrumentation for DB queries
                    '@opentelemetry/instrumentation-pg': { enabled: true },
                    // ioredis instrumentation
                    '@opentelemetry/instrumentation-ioredis': { enabled: true },
                }),
            ],
        });

        sdk.start();
        log.info('OpenTelemetry started', { endpoint, serviceName });

        // Graceful shutdown
        process.on('SIGTERM', () => {
            sdk.shutdown().then(
                () => log.info('OTEL SDK shut down'),
                (err) => log.error('OTEL shutdown error', err),
            );
        });
    }).catch((err) => {
        log.warn('OpenTelemetry failed to initialize — install OTEL packages to enable', {
            error: (err as Error).message,
            hint: 'Run: pnpm add @opentelemetry/sdk-node @opentelemetry/auto-instrumentations-node @opentelemetry/exporter-trace-otlp-http @opentelemetry/exporter-metrics-otlp-http @opentelemetry/sdk-metrics @opentelemetry/resources @opentelemetry/semantic-conventions',
        });
    });
} else {
    log.info('OpenTelemetry disabled (no OTEL_EXPORTER_OTLP_ENDPOINT set)');
}

// ============================================================================
// Custom Metrics API (usable even without OTEL)
// ============================================================================

export interface MetricsSnapshot {
    requestCount: number;
    errorCount: number;
    avgResponseTime: number;
    activeConnections: number;
}

const counters = {
    requests: 0,
    errors: 0,
    totalResponseTime: 0,
    activeConnections: 0,
};

export function recordRequest(durationMs: number, isError: boolean): void {
    counters.requests++;
    counters.totalResponseTime += durationMs;
    if (isError) counters.errors++;
}

export function recordConnection(delta: 1 | -1): void {
    counters.activeConnections += delta;
}

export function getMetricsSnapshot(): MetricsSnapshot {
    return {
        requestCount: counters.requests,
        errorCount: counters.errors,
        avgResponseTime: counters.requests > 0
            ? Math.round(counters.totalResponseTime / counters.requests * 100) / 100
            : 0,
        activeConnections: counters.activeConnections,
    };
}
