/**
 * Enrich Published Dates from NVD
 * 
 * Fetches published dates for CVEs that are missing them.
 */

import { db } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { eq, isNull } from '@rinjani/db';

// Accept either name — NVD_API_KEY matches NIST's docs, CVE_API_KEY is the
// legacy codebase name. NVD_API_KEY wins if both are set.
const NVD_API_KEY = process.env.NVD_API_KEY || process.env.CVE_API_KEY || '';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RATE_LIMIT_MS = 700;
const BATCH_SIZE = 50;

interface NVDCVEResponse {
    vulnerabilities: Array<{
        cve: {
            id: string;
            published: string;
            lastModified: string;
        };
    }>;
}

async function fetchPublishedDate(cveId: string): Promise<{ published: Date; lastModified: Date } | null> {
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
        return {
            published: new Date(cve.published),
            lastModified: new Date(cve.lastModified),
        };
    } catch (error) {
        console.log(`  ⚠️  ${cveId}: ${error}`);
        return null;
    }
}

async function enrichPublishedDates() {
    console.log('🔧 Published Date Enrichment - Fetching dates from NVD');

    // Get CVEs that are missing published dates
    const missingDates = await db.select({
        id: vulnerabilities.id,
        cveId: vulnerabilities.cveId,
    })
        .from(vulnerabilities)
        .where(isNull(vulnerabilities.publishedDate))
        .limit(BATCH_SIZE);

    console.log(`📋 Found ${missingDates.length} CVEs missing published dates`);

    let enriched = 0;
    let notFound = 0;

    for (const vuln of missingDates) {
        const dateData = await fetchPublishedDate(vuln.cveId);

        if (dateData) {
            await db.update(vulnerabilities)
                .set({
                    publishedDate: dateData.published,
                    lastModified: dateData.lastModified,
                    updatedAt: new Date(),
                })
                .where(eq(vulnerabilities.id, vuln.id));

            console.log(`✅ ${vuln.cveId}: ${dateData.published.toISOString().split('T')[0]}`);
            enriched++;
        } else {
            console.log(`❌ ${vuln.cveId}: No date data available`);
            notFound++;
        }

        await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_MS));
    }

    console.log(`\n📊 Summary: ${enriched} enriched, ${notFound} not found`);
}

// Run
enrichPublishedDates()
    .then(() => {
        console.log('✅ Published date enrichment complete!');
        process.exit(0);
    })
    .catch(error => {
        console.error('❌ Enrichment failed:', error);
        process.exit(1);
    });
