/**
 * K6 Load Test Suite for Rinjani API
 * 
 * Run with: k6 run apps/api/k6/loadtest.js
 * 
 * Environment variables:
 *   API_URL   - Base API URL (default: http://localhost:3001)
 *   API_KEY   - API key for authentication (required; configure via API_KEYS env on the server)
 */

import http from 'k6/http';
import { sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const httpErrors = new Rate('http_errors');
const healthLatency = new Trend('health_latency');
const iocListLatency = new Trend('ioc_list_latency');
const searchLatency = new Trend('search_latency');
const stixLatency = new Trend('stix_latency');

export const options = {
    stages: [
        { duration: '30s', target: 10 },
        { duration: '1m', target: 10 },
        { duration: '30s', target: 50 },
        { duration: '2m', target: 50 },
        { duration: '30s', target: 0 },
    ],
    thresholds: {
        http_req_duration: ['p(95)<500'],
        http_errors: ['rate<0.05'],
        health_latency: ['p(95)<100'],
        ioc_list_latency: ['p(95)<500'],
    },
};

const API_URL = __ENV.API_URL || 'http://localhost:3001';
const API_KEY = __ENV.API_KEY;
if (!API_KEY) {
    throw new Error('API_KEY env var is required (e.g. API_KEY=xxx k6 run loadtest.js)');
}

// Shared request params with auth header
const authParams = {
    headers: { 'X-API-Key': API_KEY },
};

export default function () {
    // Health Check (no auth required)
    group('Health', () => {
        const start = Date.now();
        const res = http.get(`${API_URL}/health`);
        healthLatency.add(Date.now() - start);
        httpErrors.add(res.status >= 500 ? 1 : 0);
    });

    sleep(1);

    // IOC List
    group('IOC', () => {
        const start = Date.now();
        const res = http.get(`${API_URL}/v1/iocs?limit=20`, authParams);
        iocListLatency.add(Date.now() - start);
        httpErrors.add(res.status >= 500 ? 1 : 0);

        http.get(`${API_URL}/v1/iocs?type=ip&limit=10`, authParams);
    });

    sleep(0.5);

    // Stats
    group('Stats', () => {
        const res = http.get(`${API_URL}/v1/stats`, authParams);
        httpErrors.add(res.status >= 500 ? 1 : 0);
    });

    sleep(0.5);

    // STIX Export
    group('STIX', () => {
        const start = Date.now();
        const res = http.get(`${API_URL}/v2/stix/bundle?iocLimit=10`, authParams);
        stixLatency.add(Date.now() - start);
        httpErrors.add(res.status >= 500 ? 1 : 0);
    });

    sleep(0.5);

    // Search
    group('Search', () => {
        const terms = ['malware', 'google', '192.168'];
        const term = terms[Math.floor(Math.random() * terms.length)];
        const start = Date.now();
        http.get(`${API_URL}/v1/search?q=${term}`, authParams);
        searchLatency.add(Date.now() - start);
    });

    sleep(0.5);
}

export function handleSummary(data) {
    const m = data.metrics;
    return {
        'stdout': `
========================================
  RINJANI API LOAD TEST RESULTS
========================================
Requests:    ${m.http_reqs.values.count}
Throughput:  ${m.http_reqs.values.rate.toFixed(1)} req/s
Errors:      ${((m.http_errors?.values.rate || 0) * 100).toFixed(1)}%

Response Times (p95):
  Health:    ${(m.health_latency?.values['p(95)'] || 0).toFixed(0)}ms
  IOC List:  ${(m.ioc_list_latency?.values['p(95)'] || 0).toFixed(0)}ms
  STIX:      ${(m.stix_latency?.values['p(95)'] || 0).toFixed(0)}ms
  Search:    ${(m.search_latency?.values['p(95)'] || 0).toFixed(0)}ms
========================================
`,
        'apps/api/k6/summary.json': JSON.stringify(data),
    };
}
