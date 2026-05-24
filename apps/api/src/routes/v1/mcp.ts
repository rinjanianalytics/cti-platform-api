/**
 * MCP Tools Route — /v1/mcp/tools
 *
 * Returns the list of AI/automation tools available on the platform.
 * These are derived from the AI middleware providers and built-in capabilities.
 */

import { Hono } from 'hono';
import { requireAuth } from '../../middleware/auth';
import { getProviderStatus } from '../../services/aiMiddleware';

const mcp = new Hono();

interface MCPTool {
    name: string;
    description: string;
    category: string;
    enabled: boolean;
    inputSchema?: Record<string, unknown>;
}

// Built-in MCP tools that the platform exposes
function getBuiltinTools(): MCPTool[] {
    const providerStatus = getProviderStatus();
    const hasLLM = providerStatus.providers.some(p => p.available);

    return [
        // AI Analysis tools
        {
            name: 'ai.analyze',
            description: 'Analyze a threat entity (IOC, vulnerability, threat actor) using LLM-powered intelligence analysis with RAG context from the platform.',
            category: 'ai-analysis',
            enabled: hasLLM,
            inputSchema: {
                type: 'object',
                properties: {
                    entityType: { type: 'string', enum: ['ioc', 'vulnerability', 'actor', 'campaign'] },
                    entityId: { type: 'string' },
                    entityData: { type: 'object' },
                    forceRefresh: { type: 'boolean', default: false },
                },
                required: ['entityType', 'entityId'],
            },
        },
        {
            name: 'ai.summarize',
            description: 'Generate a RAG-enhanced threat briefing using real platform data (IOC counts, severity trends, recent indicators).',
            category: 'ai-analysis',
            enabled: hasLLM,
            inputSchema: {
                type: 'object',
                properties: {
                    context: { type: 'string', default: 'daily briefing' },
                },
            },
        },
        {
            name: 'ai.query',
            description: 'Natural language query interface — ask questions about your threat intelligence data and get RAG-enhanced answers.',
            category: 'ai-analysis',
            enabled: hasLLM,
            inputSchema: {
                type: 'object',
                properties: {
                    query: { type: 'string', description: 'Natural language question about threat intelligence' },
                },
                required: ['query'],
            },
        },
        // Enrichment tools
        {
            name: 'enrich.ioc',
            description: 'Enrich an IOC (IP, domain, hash, URL) using configured enrichment providers (VirusTotal, AbuseIPDB, Shodan, etc.).',
            category: 'enrichment',
            enabled: true,
            inputSchema: {
                type: 'object',
                properties: {
                    value: { type: 'string' },
                    type: { type: 'string', enum: ['ip', 'domain', 'hash', 'url'] },
                    providers: { type: 'array', items: { type: 'string' } },
                },
                required: ['value'],
            },
        },
        {
            name: 'enrich.batch',
            description: 'Bulk enrich multiple IOCs in a single request using the enrichment queue.',
            category: 'enrichment',
            enabled: true,
        },
        // Search tools
        {
            name: 'search.unified',
            description: 'Full-text search across all entity types with faceted filtering, severity and type breakdowns.',
            category: 'search',
            enabled: true,
            inputSchema: {
                type: 'object',
                properties: {
                    query: { type: 'string' },
                    filters: { type: 'object' },
                    pagination: { type: 'object' },
                },
                required: ['query'],
            },
        },
        {
            name: 'search.vector',
            description: 'Semantic vector search — find similar entities by meaning, not just keyword match.',
            category: 'search',
            enabled: hasLLM,
        },
        // Correlation tools
        {
            name: 'correlate.entity',
            description: 'Find correlations between an IOC and other entities in the platform using graph analysis.',
            category: 'correlation',
            enabled: true,
        },
        {
            name: 'correlate.batch',
            description: 'Batch correlation — find relations across multiple IOCs simultaneously.',
            category: 'correlation',
            enabled: true,
        },
        // Export tools
        {
            name: 'export.stix',
            description: 'Export entities as STIX 2.1 bundles for interoperability with other CTI platforms.',
            category: 'export',
            enabled: true,
        },
        {
            name: 'export.csv',
            description: 'Export search results or entity lists as CSV files.',
            category: 'export',
            enabled: true,
        },
        {
            name: 'export.misp',
            description: 'Export intelligence data in MISP event format.',
            category: 'export',
            enabled: true,
        },
        // YARA
        {
            name: 'yara.match',
            description: 'Run YARA rules against indicators to identify malware families and threat patterns.',
            category: 'detection',
            enabled: true,
        },
        // Playbooks
        {
            name: 'playbook.execute',
            description: 'Execute automated response playbooks triggered by entity events or manual invocation.',
            category: 'automation',
            enabled: true,
        },
        // Graph
        {
            name: 'graph.query',
            description: 'Query the Neo4j knowledge graph for entity relationships, attack paths, and threat intelligence linkage.',
            category: 'graph',
            enabled: !!process.env.NEO4J_URI,
        },
    ];
}

// GET /mcp/tools
mcp.get('/mcp/tools', requireAuth, (c) => {
    const tools = getBuiltinTools();
    return c.json({
        tools,
        meta: {
            total: tools.length,
            enabled: tools.filter(t => t.enabled).length,
            categories: [...new Set(tools.map(t => t.category))],
        },
    });
});

export default mcp;
