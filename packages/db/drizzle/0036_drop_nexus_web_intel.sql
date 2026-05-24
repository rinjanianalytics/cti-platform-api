-- Drop the Nexus / web-intelligence stack.
--
-- We removed the Nexus surface entirely: 0 production data outside manual
-- testing (120 osint-scrape items from Feb–Mar 2026), 0 campaign_indicators,
-- 0 exa_websets, and no dashboard surface. The ingest path (Exa websets +
-- monitors) was never bootstrapped in production, and the SearXNG-fed
-- scraping fell out of use 2.5 months ago. Easier to ship from clean
-- foundations than to maintain a dormant feature.
--
-- Dependency order matters — campaign_indicators FKs web_intel_mentions and
-- campaigns; mentions FK items; items FK exa_websets. Drop in reverse.

DROP TABLE IF EXISTS campaign_indicators CASCADE;
DROP TABLE IF EXISTS campaigns CASCADE;
DROP TABLE IF EXISTS web_intel_mentions CASCADE;
DROP TABLE IF EXISTS web_intel_items CASCADE;
DROP TABLE IF EXISTS exa_websets CASCADE;
