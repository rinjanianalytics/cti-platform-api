/**
 * Quick CVSS Enrichment Script
 * 
 * Fetches CVSS scores from NVD for CVEs that are missing them,
 * prioritizing CISA KEV (exploited) vulnerabilities.
 */

import { db } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { eq, isNull, and } from '@rinjani/db';

// Accept either name — NVD_API_KEY matches NIST's docs, CVE_API_KEY is the
// legacy codebase name. NVD_API_KEY wins if both are set.
const NVD_API_KEY = process.env.NVD_API_KEY || process.env.CVE_API_KEY || '';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RATE_LIMIT_MS = 700; // Slightly faster with API key for single CVE lookups
const BATCH_SIZE = 50; // How many CVEs to enrich per run

interface NVDCVEResponse {
    vulnerabilities: Array<{
        cve: {
            id: string;
            metrics?: {
                cvssMetricV31?: Array<{
                    cvssData: {
                        baseScore: number;
                        baseSeverity: string;
                        vectorString: string;
                    };
                }>;
                cvssMetricV30?: Array<{
                    cvssData: {
                        baseScore: number;
                        baseSeverity: string;
                        vectorString: string;
                    };
                }>;
                cvssMetricV2?: Array<{
                    cvssData: {
                        baseScore: number;
                        vectorString: string;
                    };
                }>;
            };
        };
    }>;
}

async function fetchCVSS(cveId: string): Promise<{ score: number; vector: string } | null> {
    try {
        const url = new URL(NVD_BASE_URL);
        url.searchParams.append('cveId', cveId);

        const response = await fetch(url.toString(), {
            headers: NVD_API_KEY ? { 'apiKey': NVD_API_KEY } : {},
        });

        if (!response.ok) {
            console.log(`  ⚠️  ${cveId}: API error ${response.status}`);
            return null;
        }

        const data = await response.json() as NVDCVEResponse;

        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
            return null;
        }

        const cve = data.vulnerabilities[0].cve;
        const metrics = cve.metrics;

        // Try CVSS v3.1 first
        if (metrics?.cvssMetricV31?.[0]) {
            const cvss = metrics.cvssMetricV31[0].cvssData;
            return { score: cvss.baseScore, vector: cvss.vectorString };
        }

        // Try CVSS v3.0
        if (metrics?.cvssMetricV30?.[0]) {
            const cvss = metrics.cvssMetricV30[0].cvssData;
            return { score: cvss.baseScore, vector: cvss.vectorString };
        }

        // Try CVSS v2
        if (metrics?.cvssMetricV2?.[0]) {
            const cvss = metrics.cvssMetricV2[0].cvssData;
            return { score: cvss.baseScore, vector: cvss.vectorString };
        }

        return null;
    } catch (error) {
        console.log(`  ⚠️  ${cveId}: ${error}`);
        return null;
    }
}

async function enrichCVSS() {
    console.log('🔧 CVSS Enrichment - Fetching missing CVSS scores for CISA KEV entries');

    if (!NVD_API_KEY) {
        console.warn('⚠️  No NVD API key configured - using slower rate limit');
    }

    // Get CVEs that are exploited but missing CVSS scores
    const missingCVSS = await db.select({
        id: vulnerabilities.id,
        cveId: vulnerabilities.cveId,
    })
        .from(vulnerabilities)
        .where(and(
            eq(vulnerabilities.isExploited, true),
            isNull(vulnerabilities.cvssScore)
        ))
        .limit(BATCH_SIZE);

    console.log(`📋 Found ${missingCVSS.length} CVEs missing CVSS scores`);

    let enriched = 0;
    let notFound = 0;

    for (const vuln of missingCVSS) {
        const cvssData = await fetchCVSS(vuln.cveId);

        if (cvssData) {
            await db.update(vulnerabilities)
                .set({
                    cvssScore: cvssData.score.toString(),
                    cvssVector: cvssData.vector,
                    updatedAt: new Date(),
                })
                .where(eq(vulnerabilities.id, vuln.id));

            console.log(`✅ ${vuln.cveId}: CVSS ${cvssData.score}`);
            enriched++;
        } else {
            console.log(`❌ ${vuln.cveId}: No CVSS data available`);
            notFound++;
        }

        // Rate limiting
        await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_MS));
    }

    console.log(`\n📊 Summary: ${enriched} enriched, ${notFound} not found`);
}

// Run
enrichCVSS()
    .then(() => {
        console.log('✅ CVSS enrichment complete!');
        process.exit(0);
    })
    .catch(error => {
        console.error('❌ Enrichment failed:', error);
        process.exit(1);
    });
