#!/usr/bin/env node
'use strict';
// Tooling pin drift: actionlint and zizmor.
//
// Neither is a dependency any package manager tracks, so nothing proposes an
// upgrade and a pin only moves if somebody remembers. azure-pipelines-terraform
// used to watch this with a weekly canary that grepped its OWN unit-test.yml;
// migrating that repo onto workflow-security.yml removed the pins it was
// reading, so the canary went with them and would have failed with "Could not
// resolve the actionlint version pinned in unit-test.yml" on its next run
// (4cloudguru/shared-workflows#23).
//
// The check belongs where the pins now live, and one job here covers every
// consumer at once -- which matters more than it did before: a zizmor bump
// changes what a REQUIRED check enforces in all of them simultaneously, so
// noticing it is not optional.
//
// Reading and comparing are separated from fetching so the logic is testable
// without a network: `--versions <json>` supplies the upstream answers.

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const SECURITY = '.github/workflows/workflow-security.yml';
const RECORD = '.github/workflows/workflow-security-record.yml';

/** Every zizmor `version:` pin, with the file it came from. */
function zizmorPins(root) {
    const out = [];
    for (const rel of [SECURITY, RECORD]) {
        const p = path.join(root, rel);
        if (!fs.existsSync(p)) continue;
        const text = fs.readFileSync(p, 'utf8');
        // Only a pin that belongs to the zizmor action, not any `version:` key.
        const re = /zizmorcore\/zizmor-action@[0-9a-f]{40}[^\n]*\n(?:\s*(?:#[^\n]*|with:)\n)*?(?:[^\n]*\n)*?\s*version:\s*["']([0-9.]+)["']/g;
        let m;
        while ((m = re.exec(text)) !== null) out.push({ file: rel, version: m[1] });
    }
    return out;
}

/** The actionlint release the workflow downloads, and the checksum it asserts. */
function actionlintPin(root) {
    const text = fs.readFileSync(path.join(root, SECURITY), 'utf8');
    const url = /actionlint\/releases\/download\/v([0-9.]+)\/actionlint_([0-9.]+)_([a-z0-9_]+)\.tar\.gz/.exec(text);
    const sum = /^\s*echo\s+"([0-9a-f]{64})\s+actionlint_([0-9.]+)_/m.exec(text);
    return {
        urlVersion: url ? url[1] : null,
        assetVersion: url ? url[2] : null,
        platform: url ? url[3] : null,
        sha256: sum ? sum[1] : null,
        sumVersion: sum ? sum[2] : null,
    };
}

function problems(root, latest) {
    const found = [];
    const zizmor = zizmorPins(root);

    if (zizmor.length === 0) {
        found.push(`no zizmor version pin found in ${SECURITY} or ${RECORD}. The pin has moved or been dropped; ` +
            'this check cannot be read as clean when it resolved nothing.');
    }
    // Internal consistency first: two files pinning different scanners would
    // make the gate and the recorder disagree about what they scanned, which no
    // upstream comparison would surface.
    const distinct = [...new Set(zizmor.map((z) => z.version))];
    if (distinct.length > 1) {
        found.push(`zizmor is pinned at ${distinct.length} different versions: ` +
            zizmor.map((z) => `${z.version} in ${z.file}`).join(', ') +
            '. The blocking gate and the recorder must run the same scanner.');
    }
    if (distinct.length === 1 && latest.zizmor && distinct[0] !== latest.zizmor) {
        found.push(`zizmor is pinned to ${distinct[0]} but the latest release is ${latest.zizmor}. ` +
            'Bump `version:` in both workflow-security.yml and workflow-security-record.yml.');
    }

    const al = actionlintPin(root);
    if (!al.urlVersion || !al.sha256) {
        found.push(`could not resolve the actionlint download URL and checksum in ${SECURITY} ` +
            `(url=${al.urlVersion ?? 'none'}, checksum=${al.sha256 ? 'present' : 'none'}).`);
    } else {
        // A URL and a checksum naming different versions is the failure a bump
        // makes when only half of it lands: the download succeeds and the
        // checksum rejects it, or worse the reverse.
        const versions = new Set([al.urlVersion, al.assetVersion, al.sumVersion].filter(Boolean));
        if (versions.size > 1) {
            found.push(`the actionlint pin is internally inconsistent: URL says v${al.urlVersion}, ` +
                `asset says ${al.assetVersion}, checksum line says ${al.sumVersion}.`);
        } else if (latest.actionlint && al.urlVersion !== latest.actionlint) {
            found.push(`actionlint is pinned to ${al.urlVersion} but the latest release is ${latest.actionlint}. ` +
                'Bump the version, the tarball URL and the SHA256 together.');
        }
    }
    return found;
}

async function fetchLatest() {
    const gh = await fetch('https://api.github.com/repos/rhysd/actionlint/releases/latest', {
        headers: { accept: 'application/vnd.github+json', 'user-agent': 'shared-workflows-tooling-pins' },
    });
    if (!gh.ok) throw new Error(`actionlint releases API returned ${gh.status}`);
    const actionlint = String((await gh.json()).tag_name || '').replace(/^v/, '');

    const pypi = await fetch('https://pypi.org/pypi/zizmor/json', { headers: { accept: 'application/json' } });
    if (!pypi.ok) throw new Error(`PyPI returned ${pypi.status} for zizmor`);
    const zizmor = String((await pypi.json()).info?.version || '');

    if (!actionlint || !zizmor) throw new Error(`could not resolve upstream versions (actionlint=${actionlint}, zizmor=${zizmor})`);
    return { actionlint, zizmor };
}

async function main() {
    const idx = process.argv.indexOf('--versions');
    let latest;
    if (idx !== -1) {
        latest = JSON.parse(process.argv[idx + 1]);
    } else {
        try {
            latest = await fetchLatest();
        } catch (err) {
            // A canary that cannot reach upstream has not found the pins current;
            // it has found out nothing. Exit 2 rather than 0.
            console.error(`check-tooling-pins: ${err.message}`);
            return 2;
        }
    }
    const root = process.argv[2] && !process.argv[2].startsWith('--') ? path.resolve(process.argv[2]) : ROOT;
    const found = problems(root, latest);
    const zp = zizmorPins(root);
    console.log(`enumerated: ${zp.length} zizmor pin(s), actionlint ${actionlintPin(root).urlVersion ?? 'unresolved'}; ` +
        `upstream actionlint ${latest.actionlint ?? '?'}, zizmor ${latest.zizmor ?? '?'}`);
    if (found.length === 0) {
        console.log('OK: every tooling pin matches its latest published release, and agrees with itself.');
        return 0;
    }
    for (const f of found) console.error(`::error::${f}`);
    return 1;
}

module.exports = { zizmorPins, actionlintPin, problems };
if (require.main === module) main().then((c) => process.exit(c));
