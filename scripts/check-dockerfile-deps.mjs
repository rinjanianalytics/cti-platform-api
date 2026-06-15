#!/usr/bin/env node
/**
 * Dockerfile workspace-dependency guard.
 *
 * Catches the exact class of bug that took production down on 2026-06-15:
 * a new workspace package (`@rinjani/feed-engine`) became an API dependency
 * via apps/api/package.json, but the Dockerfile was never updated to COPY
 * it into the image. `pnpm install --frozen-lockfile` succeeds anyway
 * (the package is a leaf in the dep graph), and `docker build` exits 0 —
 * the failure only surfaces at runtime as ERR_MODULE_NOT_FOUND when the
 * first import resolves. CI's tsc/test/build jobs all run against the host
 * pnpm workspace, so none of them see the container's missing COPY.
 *
 * This check is static + deterministic: for every `workspace:*` dependency
 * of the apps the Dockerfile serves (api + worker — both run from the same
 * image via the shared CMD), assert the Dockerfile has a COPY line bringing
 * that package's directory into the image.
 *
 * Exits non-zero with an actionable message if any dep is unwired. No Docker
 * required — runs in ~50ms.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const DOCKERFILE = join(repoRoot, 'Dockerfile');

// Apps whose code runs from the v3-api image. Both api and worker share the
// single image (see Dockerfile CMD + the retired v3-worker container note);
// a missing COPY breaks whichever app imports the unwired package.
const APPS_SERVED_BY_IMAGE = ['apps/api', 'apps/worker'];

function readJson(path) {
    return JSON.parse(readFileSync(path, 'utf8'));
}

// Build a map of @rinjani/<name> → relative package dir by scanning the
// workspace package globs (packages/*, apps/*).
function buildPackageNameMap() {
    const map = new Map();
    for (const group of ['packages', 'apps']) {
        const groupDir = join(repoRoot, group);
        if (!existsSync(groupDir)) continue;
        for (const entry of readdirSync(groupDir)) {
            const pkgJson = join(groupDir, entry, 'package.json');
            if (existsSync(pkgJson)) {
                const { name } = readJson(pkgJson);
                if (name) map.set(name, `${group}/${entry}`);
            }
        }
    }
    return map;
}

function main() {
    if (!existsSync(DOCKERFILE)) {
        console.error('✗ Dockerfile not found at repo root');
        process.exit(2);
    }

    const dockerfile = readFileSync(DOCKERFILE, 'utf8');
    const nameMap = buildPackageNameMap();

    // Collect the union of workspace deps across the apps served by the image.
    const requiredDeps = new Set();
    for (const app of APPS_SERVED_BY_IMAGE) {
        const pkgPath = join(repoRoot, app, 'package.json');
        if (!existsSync(pkgPath)) continue;
        const pkg = readJson(pkgPath);
        const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [dep, version] of Object.entries(allDeps)) {
            if (String(version).startsWith('workspace:')) requiredDeps.add(dep);
        }
    }

    const failures = [];
    for (const dep of [...requiredDeps].sort()) {
        const pkgDir = nameMap.get(dep);
        if (!pkgDir) {
            failures.push(`  ${dep} — workspace dep declared but no package dir found (broken workspace?)`);
            continue;
        }
        // A COPY of either the package.json (install layer) OR the package dir
        // root counts as "wired". We specifically require the package.json copy
        // because that's what `pnpm install` needs to resolve the workspace link.
        const copyPkgJson = new RegExp(
            `COPY\\b[^\\n]*\\b${escapeRegex(pkgDir)}/package\\.json\\b`,
        );
        if (!copyPkgJson.test(dockerfile)) {
            failures.push(
                `  ${dep} (${pkgDir}) — no \`COPY ... ${pkgDir}/package.json\` line in Dockerfile`,
            );
        }
    }

    if (failures.length > 0) {
        console.error('✗ Dockerfile is missing COPY lines for workspace dependencies:\n');
        console.error(failures.join('\n'));
        console.error(
            '\nEach workspace package an app imports must be COPY\'d into the image,' +
            '\nor the container crash-loops at runtime with ERR_MODULE_NOT_FOUND.' +
            '\nAdd the package.json to the install layer AND the src to the source layer.' +
            '\nSee the feed-engine entries in the Dockerfile for the pattern.',
        );
        process.exit(1);
    }

    console.log(
        `✓ Dockerfile wires all ${requiredDeps.size} workspace dependencies ` +
        `(${[...requiredDeps].sort().join(', ')})`,
    );
}

function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

main();
