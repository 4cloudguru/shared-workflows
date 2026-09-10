#!/usr/bin/env node
'use strict';
// Tooling pin drift: actionlint, zizmor, and the osv-scanner image.
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
const OSV_ACTION = '.github/actions/osv-scan/action.yml';

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
    // THE OWNER IS PART OF THE PIN, and this reader used to drop it. The old
    // pattern began at `actionlint/releases/download/`, so it matched
    // rhysd/actionlint and any fork identically -- and `fetchLatest` then asked
    // a HARDCODED rhysd for the latest version. Point the workflow at a fork and
    // the checker would compare that fork's pinned version against rhysd's
    // latest and report the difference as drift, or agreement as currency.
    // Neither answer would be about the binary the gate actually runs.
    const url = /github\.com\/([A-Za-z0-9._-]+)\/actionlint\/releases\/download\/v([0-9.]+)\/actionlint_([0-9.]+)_([a-z0-9_]+)\.tar\.gz/.exec(text);
    const sum = /^\s*echo\s+"([0-9a-f]{64})\s+actionlint_([0-9.]+)_/m.exec(text);
    return {
        owner: url ? url[1] : null,
        urlVersion: url ? url[2] : null,
        assetVersion: url ? url[3] : null,
        platform: url ? url[4] : null,
        sha256: sum ? sum[1] : null,
        sumVersion: sum ? sum[2] : null,
    };
}

/**
 * Every `zizmorcore/zizmor-action` pin, with the file and the tag comment.
 *
 * THE PIN THIS EXISTS FOR IS THE ACTION'S, NOT THE SCANNER'S, and the two are
 * not the same knob. The action ships a FROZEN TABLE of the zizmor releases it
 * can install -- `support/versions` at whatever commit the SHA names -- and
 * `version:` selects a row from that table. A `version:` naming a release the
 * pinned action has never heard of does not fall back and does not warn: the
 * step dies with `Unknown version: <x>`.
 *
 * That happened, and it is why this reader is here. #47 bumped `version:` to
 * 1.30.0, this checker reported "every tooling pin matches its latest published
 * release", and both zizmor jobs failed on the first real run -- v0.6.2's table
 * stops at 1.29.0. The checker was comparing the pin against PyPI and had no
 * opinion about whether the thing doing the installing could honour it, so it
 * was green about a configuration that could not run at all.
 */
function zizmorActionPins(root) {
    const out = [];
    for (const rel of [SECURITY, RECORD]) {
        const p = path.join(root, rel);
        if (!fs.existsSync(p)) continue;
        const text = fs.readFileSync(p, 'utf8');
        const re = /zizmorcore\/zizmor-action@([0-9a-f]{40})[ \t]*(?:#[ \t]*(v?[0-9][0-9.]*))?/g;
        let m;
        while ((m = re.exec(text)) !== null) out.push({ file: rel, sha: m[1], tag: m[2] || null });
    }
    return out;
}

/**
 * The osv-scanner image the shared scan action runs, split into its parts.
 *
 * WHY THIS IS HERE (terraform-registry-backend#894). This pin used to live in
 * eight consumers' weekly-security.yml, and one of them sat two releases behind
 * for months with nothing reporting it -- because this reader covered actionlint
 * and zizmor and nothing else. The osv-scan action consolidated the eight copies
 * into the one below, which makes the pin watchable for the first time; leaving
 * it unwatched would reproduce the original defect in a single place instead of
 * eight.
 *
 * Anchored on the `image:` INPUT KEY at its own indentation, not on the image
 * name. The same `ghcr.io/google/osv-scanner-action:v2.5.1` string appears in
 * that file's header prose without a digest, so a pattern matching the name
 * would resolve the COMMENT and report it as the pin -- a reader that finds
 * something and is wrong about what, which reads exactly like a clean one.
 */
function osvScannerPin(root) {
    const empty = { file: OSV_ACTION, ref: null, registry: null, repo: null, tag: null, digest: null };
    const file = path.join(root, OSV_ACTION);
    if (!fs.existsSync(file)) return empty;
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    const start = lines.findIndex((l) => /^ {2}image:\s*$/.test(l));
    if (start === -1) return empty;
    let ref = null;
    for (let i = start + 1; i < lines.length; i++) {
        // Stop at the next input, or at any top-level key. Scanning past them
        // would let a LATER input's default answer for this one.
        if (/^ {0,2}\S/.test(lines[i])) break;
        const m = /^ {4}default:\s*["']([^"']+)["']\s*$/.exec(lines[i]);
        if (m) { ref = m[1]; break; }
    }
    if (!ref) return empty;
    const parsed = /^([a-z0-9.-]+)\/(\S+?):([^@\s]+)(?:@(sha256:[0-9a-f]{64}))?$/.exec(ref);
    if (!parsed) return { ...empty, ref };
    return { file: OSV_ACTION, ref, registry: parsed[1], repo: parsed[2], tag: parsed[3], digest: parsed[4] || null };
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

    // The action pin, and whether it can actually install the scanner pin.
    const actionPins = zizmorActionPins(root);
    if (actionPins.length === 0) {
        found.push(`no zizmorcore/zizmor-action pin found in ${SECURITY} or ${RECORD}. ` +
            'This check cannot be read as clean when it resolved nothing.');
    }
    const distinctSha = [...new Set(actionPins.map((a) => a.sha))];
    if (distinctSha.length > 1) {
        found.push(`zizmor-action is pinned at ${distinctSha.length} different commits: ` +
            actionPins.map((a) => `${a.sha.slice(0, 8)} in ${a.file}`).join(', ') +
            '. The blocking gate and the recorder must run the same action.');
    }
    if (distinctSha.length === 1 && distinct.length === 1 && Array.isArray(latest.zizmorActionSupports)) {
        // THE CHECK THAT WAS MISSING. Everything above compares a pin to
        // upstream; this one asks whether the two pins can work together.
        if (latest.zizmorActionSupports.length === 0) {
            found.push('resolved an EMPTY list of zizmor versions for the pinned zizmor-action. ' +
                'That is a failed read, not an action that supports nothing, and it must not be ' +
                'mistaken for agreement.');
        } else if (!latest.zizmorActionSupports.includes(distinct[0])) {
            found.push(`zizmor-action ${actionPins[0].tag || actionPins[0].sha.slice(0, 8)} cannot install ` +
                `zizmor ${distinct[0]}: its frozen version table offers ` +
                `${latest.zizmorActionSupports.slice(-4).join(', ')}. The step would fail with ` +
                `"Unknown version: ${distinct[0]}". Bump the action pin as well as \`version:\`.`);
        }
    }
    if (distinctSha.length === 1 && latest.zizmorActionTag && actionPins[0].tag &&
        actionPins[0].tag.replace(/^v/, '') !== latest.zizmorActionTag.replace(/^v/, '')) {
        found.push(`zizmor-action is pinned to ${actionPins[0].tag} but the latest release is ` +
            `${latest.zizmorActionTag}. A scanner release usually needs the action release published ` +
            'alongside it, so this pin rots into the failure above.');
    }

    const al = actionlintPin(root);
    // Owner and version come out of ONE match, so `urlVersion` resolving implies
    // `owner` resolved too -- an `|| !al.owner` clause here would be a condition
    // that cannot fire, which this repository has spent enough effort removing
    // from other people's gates to not add one to its own. The owner is still
    // REPORTED, because "which project" is the useful half of a failed read.
    if (!al.urlVersion || !al.sha256) {
        found.push(`could not resolve the actionlint download URL and checksum in ${SECURITY} ` +
            `(owner=${al.owner ?? 'none'}, url=${al.urlVersion ?? 'none'}, checksum=${al.sha256 ? 'present' : 'none'}).`);
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

    // ── the osv-scanner image the shared scan action runs
    const osv = osvScannerPin(root);
    if (!osv.ref) {
        found.push(`no osv-scanner image pin found in ${OSV_ACTION}. The action has moved, been renamed, ` +
            'or stopped declaring its image as an input default; this check cannot be read as clean ' +
            'when it resolved nothing.');
    } else if (!osv.repo) {
        found.push(`the osv-scanner image pin in ${OSV_ACTION} is \`${osv.ref}\`, which is not a ` +
            'registry/repository:tag reference this check can resolve.');
    } else if (!osv.digest) {
        found.push(`the osv-scanner image is pinned to \`${osv.ref}\` with no digest, so the tag alone ` +
            'decides what runs. A tag is mutable; the digest is what makes the scan reproducible.');
    } else {
        // Does the digest still name the release the tag names? This is the
        // half-landed bump -- tag comment moved, digest did not, or the reverse
        // -- and it is invisible to every other check here, because BOTH halves
        // look correct on their own. Same failure the actionlint URL/checksum
        // pair has, where the download succeeds and the checksum rejects it.
        if (latest.osvTagDigest === '') {
            found.push(`resolved an EMPTY digest for ${osv.repo}:${osv.tag}. That is a failed read, not ` +
                'agreement, and it must not be mistaken for a pin that matches.');
        } else if (latest.osvTagDigest && latest.osvTagDigest !== osv.digest) {
            found.push(`the osv-scanner pin is internally inconsistent: it names ${osv.tag} but carries ` +
                `${osv.digest.slice(0, 19)}…, while ${osv.tag} currently resolves to ` +
                `${latest.osvTagDigest.slice(0, 19)}…. Either a bump landed only half way, or upstream ` +
                're-pushed the tag. The digest is what runs, so the version comment is the half that lies.');
        }
        if (latest.osvTag && osv.tag.replace(/^v/, '') !== latest.osvTag.replace(/^v/, '')) {
            found.push(`osv-scanner-action is pinned to ${osv.tag} but the latest release is ${latest.osvTag}. ` +
                `Bump both the tag and the digest in ${OSV_ACTION}; nothing else in the estate pins this ` +
                'image any more, so this is the only place it moves.');
        }
    }
    return found;
}

async function fetchLatest(root) {
    // ASK THE OWNER THE TREE IS ACTUALLY PINNED TO, not a name compiled in here.
    // A hardcoded owner silently answers a question about a different project
    // the moment the pin moves, and a URL edit is exactly the kind of change
    // that would move it.
    const owner = actionlintPin(root).owner;
    if (!owner) throw new Error(`could not read the actionlint owner from the download URL in ${SECURITY}`);
    const gh = await fetch(`https://api.github.com/repos/${owner}/actionlint/releases/latest`, {
        headers: { accept: 'application/vnd.github+json', 'user-agent': 'shared-workflows-tooling-pins' },
    });
    if (!gh.ok) throw new Error(`actionlint releases API returned ${gh.status} for ${owner}/actionlint`);
    const release = await gh.json();
    const actionlint = String(release.tag_name || '').replace(/^v/, '');
    const actionlintPublishedAt = String(release.published_at || '') || null;

    const pypi = await fetch('https://pypi.org/pypi/zizmor/json', { headers: { accept: 'application/json' } });
    if (!pypi.ok) throw new Error(`PyPI returned ${pypi.status} for zizmor`);
    const zizmor = String((await pypi.json()).info?.version || '');

    if (!actionlint || !zizmor) throw new Error(`could not resolve upstream versions (actionlint=${actionlint}, zizmor=${zizmor})`);

    // What the PINNED action can install, read at the pinned commit rather than
    // from a tag, so this describes the action that will actually run.
    const pins = zizmorActionPins(root);
    let zizmorActionSupports = null;
    let zizmorActionTag = null;
    if (pins.length > 0) {
        const url = `https://raw.githubusercontent.com/zizmorcore/zizmor-action/${pins[0].sha}/support/versions`;
        const table = await fetch(url, { headers: { 'user-agent': 'shared-workflows-tooling-pins' } });
        if (!table.ok) throw new Error(`zizmor-action support/versions returned ${table.status} at ${pins[0].sha}`);
        zizmorActionSupports = (await table.text())
            .split('\n')
            .map((line) => line.trim().split(/\s+/)[0])
            .filter((v) => /^[0-9]+\.[0-9]+\.[0-9]+$/.test(v))
            // Numeric, not lexicographic. A string sort puts 1.9.0 after
            // 1.29.0, so the "table offers ..." message would name the four
            // OLDEST rows while claiming to show what is available.
            .sort((a, b) => {
                const x = a.split('.').map(Number);
                const y = b.split('.').map(Number);
                return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
            });

        const rel = await fetch('https://api.github.com/repos/zizmorcore/zizmor-action/releases/latest', {
            headers: { accept: 'application/vnd.github+json', 'user-agent': 'shared-workflows-tooling-pins' },
        });
        if (!rel.ok) throw new Error(`zizmor-action releases API returned ${rel.status}`);
        zizmorActionTag = String((await rel.json()).tag_name || '') || null;
    }

    // THE OSV-SCANNER IMAGE. Owner and repository come out of the pin itself,
    // never compiled in here -- same reasoning as the actionlint owner above.
    // For a ghcr.io-published action the registry path and the GitHub repository
    // coincide; if that ever stops being true the releases call 404s and this
    // function throws, which exits 2 (could not ask) rather than 0 (current).
    const osv = osvScannerPin(root);
    let osvTag = null;
    let osvTagDigest = null;
    if (osv.repo && osv.registry) {
        const rel = await fetch(`https://api.github.com/repos/${osv.repo}/releases/latest`, {
            headers: { accept: 'application/vnd.github+json', 'user-agent': 'shared-workflows-tooling-pins' },
        });
        if (!rel.ok) throw new Error(`osv-scanner-action releases API returned ${rel.status} for ${osv.repo}`);
        osvTag = String((await rel.json()).tag_name || '') || null;

        if (osv.tag) {
            // Anonymous pull token, then a HEAD for the manifest the TAG points
            // at today. The Accept list has to name the index media types as
            // well as the manifest ones: a multi-arch image answers with an
            // index, and a registry offered only the single-arch types returns
            // 404 for a tag that plainly exists.
            const tokenUrl = `https://${osv.registry}/token?scope=repository:${osv.repo}:pull` +
                `&service=${osv.registry}`;
            const tokenRes = await fetch(tokenUrl, { headers: { 'user-agent': 'shared-workflows-tooling-pins' } });
            if (!tokenRes.ok) throw new Error(`${osv.registry} token endpoint returned ${tokenRes.status}`);
            const token = String((await tokenRes.json()).token || '');
            if (!token) throw new Error(`${osv.registry} returned no pull token for ${osv.repo}`);

            const manifest = await fetch(`https://${osv.registry}/v2/${osv.repo}/manifests/${osv.tag}`, {
                method: 'HEAD',
                headers: {
                    authorization: `Bearer ${token}`,
                    'user-agent': 'shared-workflows-tooling-pins',
                    accept: [
                        'application/vnd.oci.image.index.v1+json',
                        'application/vnd.docker.distribution.manifest.list.v2+json',
                        'application/vnd.oci.image.manifest.v1+json',
                        'application/vnd.docker.distribution.manifest.v2+json',
                    ].join(','),
                },
            });
            if (!manifest.ok) {
                throw new Error(`${osv.registry} manifest HEAD returned ${manifest.status} for ${osv.repo}:${osv.tag}`);
            }
            // Empty string, not null, when the header is absent: `problems`
            // distinguishes "asked and got nothing" from "did not ask", and
            // collapsing them would let a failed read report as agreement.
            osvTagDigest = manifest.headers.get('docker-content-digest') || '';
        }
    }

    return {
        actionlint, actionlintOwner: owner, actionlintPublishedAt, zizmor,
        zizmorActionSupports, zizmorActionTag, osvTag, osvTagDigest,
    };
}

async function main() {
    const root = process.argv[2] && !process.argv[2].startsWith('--') ? path.resolve(process.argv[2]) : ROOT;
    const idx = process.argv.indexOf('--versions');
    let latest;
    if (idx !== -1) {
        latest = JSON.parse(process.argv[idx + 1]);
    } else {
        try {
            latest = await fetchLatest(root);
        } catch (err) {
            // A canary that cannot reach upstream has not found the pins current;
            // it has found out nothing. Exit 2 rather than 0.
            console.error(`check-tooling-pins: ${err.message}`);
            return 2;
        }
    }
    const found = problems(root, latest);
    const zp = zizmorPins(root);
    const ap = zizmorActionPins(root);
    const alp = actionlintPin(root);
    console.log(`enumerated: ${zp.length} zizmor pin(s), ${ap.length} zizmor-action pin(s) ` +
        `(${ap[0] ? ap[0].tag || ap[0].sha.slice(0, 8) : 'none'}, offering ` +
        `${latest.zizmorActionSupports ? latest.zizmorActionSupports.length : '?'} scanner version(s)), ` +
        `actionlint ${alp.urlVersion ?? 'unresolved'} from ${alp.owner ?? 'unresolved'}/actionlint; ` +
        `upstream actionlint ${latest.actionlint ?? '?'}, zizmor ${latest.zizmor ?? '?'}`);
    // The osv-scanner pin is REPORTED whether or not it is a finding, for the
    // same reason the others are: a check that resolved nothing looks identical
    // to a clean one in its exit code, and this line is where that shows.
    const op = osvScannerPin(root);
    console.log(`enumerated: osv-scanner image ${op.ref ? `${op.repo}:${op.tag}` : 'UNRESOLVED'} ` +
        `${op.digest ? `at ${op.digest.slice(0, 19)}…` : '(no digest)'}; ` +
        `upstream ${latest.osvTag ?? '?'}, that tag resolves to ` +
        `${latest.osvTagDigest ? `${latest.osvTagDigest.slice(0, 19)}…` : '?'}`);

    // SAY HOW OLD THE UPSTREAM IS, because "matches its latest published
    // release" is true of a dead project and reads as currency. rhysd/actionlint
    // last released 2026-03-30 and last committed 2026-04-19 while its author
    // stayed active elsewhere, so this check is green for a reason that has
    // nothing to do with the pin being current -- the thing it watches stopped
    // moving. That is worth printing, and it is NOT worth failing on: a
    // permanently red canary is as uninformative as a permanently green one, and
    // the comparison above still fires the moment that upstream releases again,
    // which is the event that would actually change anything.
    if (latest.actionlintPublishedAt) {
        const days = Math.floor((Date.now() - Date.parse(latest.actionlintPublishedAt)) / 86400000);
        const when = latest.actionlintPublishedAt.slice(0, 10);
        console.log(`upstream liveness: ${latest.actionlintOwner}/actionlint last released ${latest.actionlint} on ${when} (${days} days ago).` +
            (days > 120
                ? ' A pin matching a latest release that old means the upstream stopped, not that the pin is fresh.'
                : ''));
    }
    if (found.length === 0) {
        console.log('OK: every tooling pin matches its latest published release, and agrees with itself.');
        return 0;
    }
    for (const f of found) console.error(`::error::${f}`);
    return 1;
}

module.exports = { zizmorPins, zizmorActionPins, actionlintPin, osvScannerPin, problems };
if (require.main === module) main().then((c) => process.exit(c));
