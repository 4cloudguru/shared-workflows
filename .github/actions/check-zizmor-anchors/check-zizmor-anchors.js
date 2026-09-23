#!/usr/bin/env node
// Usage: node check-zizmor-anchors.js <root> --findings <zizmor-json>
//
// Fails a repository whose zizmor config declares an ignore that suppresses
// nothing.
//
// WHY THIS EXISTS. An ignore is written against coordinates that were true on
// the day it was written, and nothing re-checks them. Two things rot it, and
// only one of them is loud:
//
//   1. The finding stays and the file moves. The ignore stops matching, the
//      finding resurfaces, CI fails. Annoying, self-announcing, safe.
//      azure-pipelines-terraform's config records this happening FIVE times
//      (2026-08-20, 08-24, 08-31, 09-01, 09-04), each time re-derived by hand.
//
//   2. The finding is fixed at source and the ignore is left behind. Nothing
//      resurfaces, so nothing fails, and the entry stays armed over coordinates
//      that now hold unrelated code. The next finding of that rule at that spot
//      is swallowed silently.
//
// (2) is the one that matters and the one nobody sees. It had already happened:
// sethbacon/azure-pipelines-release-docs declared nine ignores and zizmor was
// applying two, the other five anchored onto `contents: read`, a comment, a
// `package-manager-cache: false`, a `subject-path:` and a `cosign sign-blob`.
// Both failure modes reduce to one invariant, which is all this gate asserts:
//
//      EVERY DECLARED IGNORE MUST SUPPRESS AT LEAST ONE REAL FINDING.
//
// WHY IT TAKES FINDINGS AS A FILE rather than running zizmor itself. The lint
// this gate guards runs zizmor from a digest-pinned container
// (`zizmorcore/zizmor-action` shells to Docker; it leaves no binary on PATH).
// A gate that installed its own zizmor could disagree with the lint about what
// a finding is, and would then report a dead anchor that is not dead. The
// caller runs the SAME image and hands the JSON over, so the two cannot
// disagree. It also means this file is testable without zizmor, Docker or a
// network, which is why its self-test is fixtures rather than mocks.
'use strict';

const fs = require('fs');
const path = require('path');

function fail(msg) {
    console.error(msg);
    process.exit(2);
}

// --- config reader -------------------------------------------------------
// A targeted reader for the shape zizmor configs actually take, rather than a
// YAML dependency: this runs on whatever node the caller's job already has,
// with no install step to hang a package off. Same call this repository makes
// in signature-replay.yml, which parses action.yml with a block-YAML subset
// reader rather than importing PyYAML.
//
//   rules:
//     <rule>:
//       ignore:
//         - <entry>   # optional trailing comment
//       config: ...   # not an ignore list; skipped
//
// Returns [{ rule, entry, line }] in file order. `line` is the 1-based line of
// the entry in the config, so a failure can point at the text to delete.
function readIgnores(configPath) {
    const lines = fs.readFileSync(configPath, 'utf8').split(/\r?\n/);
    const out = [];

    let rulesIndent = null;
    let rule = null;
    let ruleIndent = null;
    let inIgnore = false;
    let ignoreIndent = null;

    for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        if (!raw.trim() || /^\s*#/.test(raw)) continue;
        const indent = raw.length - raw.replace(/^\s*/, '').length;
        const text = raw.trim();

        if (rulesIndent === null) {
            if (/^rules:/.test(text)) rulesIndent = indent;
            continue;
        }
        if (indent <= rulesIndent && !/^-/.test(text)) {
            rulesIndent = /^rules:/.test(text) ? indent : null;
            rule = null;
            inIgnore = false;
            continue;
        }

        if (inIgnore && /^-/.test(text) && indent >= ignoreIndent) {
            const entry = text
                .replace(/^-\s*/, '')
                .replace(/\s+#.*$/, '')
                .replace(/^['"]|['"]$/g, '')
                .trim();
            if (entry) out.push({ rule, entry, line: i + 1 });
            continue;
        }
        if (inIgnore && indent <= ignoreIndent) inIgnore = false;

        if (rule !== null && indent > ruleIndent) {
            if (/^ignore:\s*$/.test(text)) { inIgnore = true; ignoreIndent = indent; }
            continue;
        }

        const m = text.match(/^([A-Za-z0-9_.-]+):\s*$/);
        if (m) { rule = m[1]; ruleIndent = indent; inIgnore = false; }
    }
    return out;
}

// --- findings ------------------------------------------------------------
// Every finding, reduced to the coordinates an ignore can address.
//
// An ignore addresses the PRIMARY location only. Measured against zizmor
// 1.30.1: a finding carries `Related` and `Hidden` locations too, and an
// anchor on one of those suppresses nothing. Matching on any location would
// accept an anchor zizmor itself rejects, which is the exact failure this gate
// exists to catch.
function siteIndex(findings) {
    const sites = [];
    for (const f of findings) {
        for (const loc of f.locations || []) {
            if (!loc.symbolic || loc.symbolic.kind !== 'Primary') continue;
            const key = loc.symbolic.key;
            const p = key && key.Local && key.Local.verbatim_path;
            if (!p || !loc.concrete) continue;
            const sp = loc.concrete.location.start_point;
            sites.push({
                rule: f.ident,
                // json-v1 is 0-based; ignore syntax is 1-based.
                base: path.basename(p.replace(/\\/g, '/')),
                line: sp.row + 1,
                col: sp.column + 1,
            });
        }
    }
    return sites;
}

function parseArgs(argv) {
    const rest = [];
    let findings = null;
    for (let i = 0; i < argv.length; i++) {
        if (argv[i] === '--findings') { findings = argv[++i]; continue; }
        rest.push(argv[i]);
    }
    return { root: rest[0] || '.', findings };
}

function main() {
    const { root: rootArg, findings: findingsArg } = parseArgs(process.argv.slice(2));
    const root = path.resolve(rootArg);

    if (!findingsArg) {
        fail('--findings <zizmor-json> is required. Produce it with:\n'
            + '  zizmor --no-ignores --no-exit-codes --format=json .github/ > findings.json\n'
            + 'A run without it would have to guess at the findings, and a gate that '
            + 'guesses is a gate that passes.');
    }
    if (!fs.existsSync(findingsArg)) fail(`no findings file at '${findingsArg}'.`);

    let findings;
    try {
        findings = JSON.parse(fs.readFileSync(findingsArg, 'utf8'));
    } catch (e) {
        fail(`'${findingsArg}' is not parseable zizmor JSON: ${e.message}`);
    }
    if (!Array.isArray(findings)) {
        fail(`'${findingsArg}' is not a zizmor json-v1 array. `
            + 'Note that --format=sarif is a different shape and reports no ignores.');
    }

    const configPath = ['.github/zizmor.yml', '.github/zizmor.yaml', 'zizmor.yml', '.zizmor.yml']
        .map((p) => path.join(root, p))
        .find((p) => fs.existsSync(p));

    if (!configPath) {
        console.log('no zizmor config in this repository — no ignores, nothing to rot.');
        process.exit(0);
    }

    const rel = path.relative(root, configPath).replace(/\\/g, '/');
    const entries = readIgnores(configPath);
    if (entries.length === 0) {
        console.log(`${rel}: declares no ignores — nothing to rot.`);
        process.exit(0);
    }

    const sites = siteIndex(findings);
    const dead = [];

    for (const e of entries) {
        // zizmor 1.30.1 matches the file part of an ignore on BASENAME.
        // Measured, not assumed: against a real config, `release.yml`
        // suppressed 4 of 7 findings while `workflows/release.yml` and
        // `.github/workflows/release.yml` each suppressed 0. A path therefore
        // reads as careful and does nothing, which is worth its own message.
        if (e.entry.includes('/')) {
            dead.push({
                ...e,
                why: 'zizmor matches the file part on basename alone, so a path suppresses '
                    + `nothing — write '${path.posix.basename(e.entry)}'`,
            });
            continue;
        }

        const m = e.entry.match(/^([^:]+)(?::(\d+))?(?::(\d+))?$/);
        if (!m) { dead.push({ ...e, why: 'not a `file[:line[:col]]` ignore entry' }); continue; }
        const [, base, lineStr, colStr] = m;
        const line = lineStr ? Number(lineStr) : null;
        const col = colStr ? Number(colStr) : null;

        const hit = sites.some((s) => s.rule === e.rule
            && s.base === base
            && (line === null || s.line === line)
            && (col === null || s.col === col));
        if (hit) continue;

        const inFile = sites.filter((s) => s.rule === e.rule && s.base === base);
        dead.push({
            ...e,
            why: inFile.length === 0
                ? `no \`${e.rule}\` finding in ${base} at all — it was fixed at source, `
                  + 'and this entry outlived it'
                : `\`${e.rule}\` fires in ${base}, but not at `
                  + `${line}${col !== null ? `:${col}` : ''} — it is at `
                  + `${inFile.map((s) => `${s.line}:${s.col}`).join(', ')}`,
        });
    }

    if (dead.length === 0) {
        console.log(`${rel}: ${entries.length} ignore(s), every one suppressing a real finding.`);
        process.exit(0);
    }

    console.error(`${rel}: ${dead.length} of ${entries.length} ignore(s) suppress nothing.\n`);
    console.error('A suppression that matches no finding is not inert. It stays armed over');
    console.error('those coordinates, and the next finding of that rule there is swallowed');
    console.error('without a word.\n');
    for (const d of dead) {
        console.error(`  ${rel}:${d.line}  rules.${d.rule}.ignore: ${d.entry}`);
        console.error(`      ${d.why}\n`);
    }
    console.error('Delete the entry if the finding is gone, or re-derive it with:');
    console.error('  zizmor --no-ignores --format=plain .github/');
    process.exit(1);
}

main();
