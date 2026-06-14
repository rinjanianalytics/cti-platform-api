/**
 * Confidence Decay Unit Tests
 *
 * Tests the pure mathematical functions for IOC score aging.
 * No DB calls — tests only the decay curve, refresh boost, and batch processing.
 */

import { describe, it, expect } from 'vitest';
import { calculateDecayedScore, refreshConfidence, batchDecay, getDecayConfig } from '../services/confidenceDecay';

// ============================================================================
// calculateDecayedScore
// ============================================================================

describe('calculateDecayedScore', () => {
    it('should return original score for very recent lastSeen', () => {
        const result = calculateDecayedScore(80, new Date().toISOString(), 'ip');
        expect(result.score).toBeGreaterThanOrEqual(79);
        expect(result.isStale).toBe(false);
    });

    it('should decay IP addresses faster than file hashes', () => {
        const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
        const ipResult = calculateDecayedScore(100, thirtyDaysAgo, 'ip');
        const hashResult = calculateDecayedScore(100, thirtyDaysAgo, 'hash-sha256');

        expect(ipResult.score).toBeLessThan(hashResult.score);
    });

    it('should respect minimum score floor', () => {
        const yearAgo = new Date(Date.now() - 365 * 86400000).toISOString();
        const config = getDecayConfig();

        const result = calculateDecayedScore(100, yearAgo, 'ip');
        expect(result.score).toBe(config['ip'].minScore);
    });

    it('should flag IOCs as stale past staleDays threshold', () => {
        const config = getDecayConfig();
        const daysOverStale = config['url'].staleDays + 1;
        const overStale = new Date(Date.now() - daysOverStale * 86400000).toISOString();

        const result = calculateDecayedScore(100, overStale, 'url');
        expect(result.isStale).toBe(true);
    });

    it('should not flag fresh IOCs as stale', () => {
        const result = calculateDecayedScore(100, new Date().toISOString(), 'url');
        expect(result.isStale).toBe(false);
    });

    it('should handle Date object input', () => {
        const result = calculateDecayedScore(50, new Date(), 'domain');
        expect(result.score).toBeGreaterThanOrEqual(49);
    });

    it('should report days since last seen', () => {
        const tenDaysAgo = new Date(Date.now() - 10 * 86400000).toISOString();
        const result = calculateDecayedScore(100, tenDaysAgo, 'ip');
        expect(result.daysSinceLastSeen).toBeGreaterThanOrEqual(9.9);
        expect(result.daysSinceLastSeen).toBeLessThanOrEqual(10.1);
    });

    it('should use default config for unknown IOC types', () => {
        const result = calculateDecayedScore(100, new Date().toISOString(), 'unknown-type');
        expect(result.score).toBeGreaterThanOrEqual(99);
    });
});

// ============================================================================
// refreshConfidence
// ============================================================================

describe('refreshConfidence', () => {
    it('should boost score by default factor', () => {
        const result = refreshConfidence(50);
        expect(result).toBe(60); // 50 × 1.2 = 60
    });

    it('should clamp to max score', () => {
        const result = refreshConfidence(95);
        expect(result).toBeLessThanOrEqual(100);
    });

    it('should respect custom boost factor', () => {
        const result = refreshConfidence(50, 1.5);
        expect(result).toBe(75); // 50 × 1.5 = 75
    });

    it('should respect custom max score', () => {
        const result = refreshConfidence(80, 1.5, 90);
        expect(result).toBe(90); // clamped to max
    });
});

// ============================================================================
// batchDecay
// ============================================================================

describe('batchDecay', () => {
    it('should process batch of IOCs', () => {
        const iocs = [
            { id: '1', riskScore: 80, lastSeen: new Date().toISOString(), type: 'ip' },
            { id: '2', riskScore: 60, lastSeen: new Date(Date.now() - 30 * 86400000).toISOString(), type: 'domain' },
        ];

        const results = batchDecay(iocs);
        expect(results).toHaveLength(2);
        expect(results[0].originalScore).toBe(80);
        expect(results[1].originalScore).toBe(60);
        expect(results[1].decayedScore).toBeLessThan(60);
    });

    it('should return empty array for empty input', () => {
        expect(batchDecay([])).toEqual([]);
    });

    it('should handle mixed IOC types', () => {
        const thirtyDaysAgo = new Date(Date.now() - 30 * 86400000).toISOString();
        const iocs = [
            { id: 'ip1', riskScore: 100, lastSeen: thirtyDaysAgo, type: 'ip' },
            { id: 'hash1', riskScore: 100, lastSeen: thirtyDaysAgo, type: 'hash-sha256' },
            { id: 'url1', riskScore: 100, lastSeen: thirtyDaysAgo, type: 'url' },
        ];

        const results = batchDecay(iocs);

        // URL should decay fastest, then IP, then hash (slowest)
        const urlScore = results.find(r => r.id === 'url1')!.decayedScore;
        const ipScore = results.find(r => r.id === 'ip1')!.decayedScore;
        const hashScore = results.find(r => r.id === 'hash1')!.decayedScore;

        expect(urlScore).toBeLessThan(ipScore);
        expect(ipScore).toBeLessThan(hashScore);
    });
});
