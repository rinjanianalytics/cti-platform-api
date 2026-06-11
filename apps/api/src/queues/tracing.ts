/**
 * OpenTelemetry trace propagation across BullMQ queue boundaries.
 *
 * Auto-instrumentation already covers HTTP requests, postgres queries, and
 * Redis commands. The gap is between them: when an HTTP handler enqueues a
 * BullMQ job, the worker that picks it up off Redis runs in a separate
 * trace, so the worker's DB queries appear as orphan spans not linked to
 * the original request.
 *
 * Two helpers close that gap with W3C traceparent propagation:
 *
 *   - `injectTraceContext(data)` on the producer side: serialize the
 *     active span's traceparent (and tracestate) into a non-business
 *     `_otel` field on the job data. Use at every `queue.add()` call site
 *     where the trace is worth following downstream.
 *
 *   - `runJobWithSpan(queueName, job, processor)` on the consumer side:
 *     extract the traceparent, start a CONSUMER-kind span as a child of
 *     the producer's span, and run the worker processor inside it.
 *     Every span the processor creates (or that auto-instrumentation
 *     creates from its DB / HTTP / Redis calls) attaches to that span.
 *
 * The result: one trace ID flows from the original HTTP POST through the
 * Redis ZADD, through the BullMQ worker's BRPOP, through every DB query
 * the handler issues, all the way to the eventual upserts. Tempo /
 * Grafana renders it as a single waterfall.
 *
 * Footgun avoided: span context lives in `data._otel` as a plain object
 * of header strings. We don't serialize Span objects themselves — they're
 * not stable across process boundaries and BullMQ stores job data as
 * JSON in Redis. Headers are stable, small, and the W3C standard.
 */

import {
    context,
    propagation,
    SpanKind,
    SpanStatusCode,
    trace,
} from '@opentelemetry/api';

const tracer = trace.getTracer('rinjani-bullmq', '1.0.0');

/**
 * Field on job data where W3C trace context lives. Prefixed with an
 * underscore so a quick grep can find every site that stamps it, and so
 * downstream code can ignore the key without colliding with business
 * fields.
 */
const TRACE_FIELD = '_otel';

/**
 * Stamp the currently-active trace context onto job data before enqueueing.
 *
 * No-op when no span is active (auto-instrumentation isn't running, or
 * we're outside an HTTP request). The returned object is a shallow
 * clone — never mutates the input.
 *
 *     await queue.add(name, injectTraceContext({ ...payload }), opts);
 */
export function injectTraceContext<T extends Record<string, unknown>>(
    data: T,
): T & { [TRACE_FIELD]?: Record<string, string> } {
    const carrier: Record<string, string> = {};
    propagation.inject(context.active(), carrier);
    if (Object.keys(carrier).length === 0) return data;
    return { ...data, [TRACE_FIELD]: carrier };
}

/**
 * Run a worker processor inside a span linked to the producer's trace.
 *
 * Use as a one-liner wrapper inside the Worker constructor:
 *
 *     new Worker('queue-name', async (job) =>
 *         runJobWithSpan('queue-name', job, async () => {
 *             switch (job.name) { ... }
 *         }),
 *     );
 *
 * Captures success / failure / duration on the span automatically.
 * Re-throws exceptions so BullMQ's normal retry / dead-letter logic
 * still runs unchanged.
 */
export async function runJobWithSpan<R>(
    queueName: string,
    job: {
        name: string;
        id?: string | undefined;
        // `unknown` rather than a structural type so the helper accepts every
        // worker's strongly-typed `Job<TData>`. We read `_otel` defensively
        // below; the field is invisible to typed job payloads anyway.
        data?: unknown;
    },
    processor: () => Promise<R>,
): Promise<R> {
    const carrier =
        (job.data && typeof job.data === 'object'
            ? (job.data as Record<string, unknown>)[TRACE_FIELD] as Record<string, string> | undefined
            : undefined) ?? {};
    const parentContext = propagation.extract(context.active(), carrier);

    return tracer.startActiveSpan(
        `bullmq.process ${queueName}.${job.name}`,
        {
            kind: SpanKind.CONSUMER,
            attributes: {
                'messaging.system': 'bullmq',
                'messaging.destination.name': queueName,
                'messaging.operation': 'process',
                'messaging.message.id': job.id ?? 'unknown',
                'bullmq.job.name': job.name,
            },
        },
        parentContext,
        async (span) => {
            try {
                const result = await processor();
                span.setStatus({ code: SpanStatusCode.OK });
                return result;
            } catch (err) {
                span.recordException(err as Error);
                span.setStatus({
                    code: SpanStatusCode.ERROR,
                    message: (err as Error).message,
                });
                throw err;
            } finally {
                span.end();
            }
        },
    );
}
