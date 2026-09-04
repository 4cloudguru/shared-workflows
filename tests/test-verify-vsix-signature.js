// Self-test for .github/actions/verify-vsix-signature.
//
// EXTRACTS the action's own `run:` body from action.yml and executes it
// against a stubbed `cosign`, the same idiom test-osv-scan-action.js and
// test-release-pr-closing-keywords.js already use: a test carrying its own
// copy of the shell logic passes while the real one rots.
//
// The property under test is auto-discovery + the exact invocation shape --
// this action replaces a shell block that was hand-copied into
// azure-pipelines-terraform and azure-pipelines-release-docs (and MISSING
// entirely from azure-pipelines-packer, found by comparing the three jobs
// line by line while centralizing publish-marketplace, 2026-09-04).
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ACTION = path.join(__dirname, '..', '.github', 'actions', 'verify-vsix-signature', 'action.yml');

let failures = 0;
let assertions = 0;
const report = (ok, message) => {
    assertions += 1;
    if (ok) {
        console.log(`  OK   ${message}`);
    } else {
        console.error(`  FAIL ${message}`);
        failures += 1;
    }
};

/** Same extraction idiom as test-osv-scan-action.js: find the ONE `run: |` block by indentation. */
function extractRunBlock(yaml) {
    const lines = yaml.split('\n');
    const start = lines.findIndex((l) => /^\s+run: \|\s*$/.test(l));
    if (start === -1) return null;
    const indent = lines[start].match(/^(\s*)/)[1].length + 2;
    const body = [];
    for (let i = start + 1; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim() === '') {
            body.push('');
            continue;
        }
        const lead = line.match(/^(\s*)/)[1].length;
        if (lead < indent) break;
        body.push(line.slice(indent));
    }
    return body.join('\n');
}

const actionYaml = fs.readFileSync(ACTION, 'utf8');
const runBlock = extractRunBlock(actionYaml);
if (!runBlock) {
    console.error('FAIL: could not extract the run: block from action.yml -- has its shape changed?');
    process.exit(1);
}
report(runBlock.includes('cosign verify-blob'), 'the extracted block actually invokes cosign verify-blob');

const workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-vsix-signature-selftest-'));

/** Writes a fake `cosign` on PATH that records argv and exits with the given code. */
function makeFakeCosign(dir, exitCode) {
    const binDir = path.join(dir, 'bin');
    fs.mkdirSync(binDir, { recursive: true });
    const logFile = path.join(dir, 'cosign-calls.jsonl');
    const script = path.join(binDir, 'cosign');
    fs.writeFileSync(
        script,
        `#!/usr/bin/env node\nconst fs = require('fs');\nfs.appendFileSync(${JSON.stringify(logFile)}, JSON.stringify(process.argv.slice(2)) + '\\n');\nprocess.exit(${exitCode});\n`,
        { mode: 0o755 },
    );
    return { binDir, logFile };
}

/**
 * Runs the extracted block in a scratch working directory, optionally with a
 * .vsix present, scripted env inputs, and a scripted cosign exit code.
 */
function run(name, { vsixPresent = true, exitCode = 0, env = {} } = {}) {
    const dir = path.join(workRoot, name);
    fs.mkdirSync(dir, { recursive: true });
    if (vsixPresent) {
        fs.writeFileSync(path.join(dir, 'extension.vsix'), 'fake vsix bytes');
        fs.writeFileSync(path.join(dir, 'extension.vsix.bundle'), 'fake bundle');
    }
    const { binDir, logFile } = makeFakeCosign(dir, exitCode);
    const scriptPath = path.join(dir, 'run.sh');
    fs.writeFileSync(scriptPath, `#!/usr/bin/env bash\n${runBlock}\n`, { mode: 0o755 });
    const res = spawnSync('bash', [scriptPath], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            PATH: `${binDir}:${process.env.PATH}`,
            CERTIFICATE_IDENTITY_REGEXP: '^https://example\\.invalid/.*$',
            CERTIFICATE_OIDC_ISSUER: 'https://token.actions.githubusercontent.com',
            VSIX_PATH: '',
            BUNDLE_PATH: '',
            ...env,
        },
    });
    const calls = fs.existsSync(logFile)
        ? fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
        : [];
    return { res, calls, out: `${res.stdout}${res.stderr}` };
}

// ── the happy path ───────────────────────────────────────────────────────
{
    const { res, calls } = run('happy-path');
    report(res.status === 0, 'a successful cosign verify-blob exits 0');
    report(calls.length === 1, 'cosign is invoked exactly once');
    const argv = calls[0] || [];
    report(argv.includes('verify-blob'), 'invokes cosign verify-blob');
    report(argv.includes('--certificate-identity-regexp'), 'passes --certificate-identity-regexp');
    report(argv.includes('--certificate-oidc-issuer'), 'passes --certificate-oidc-issuer');
    // `find . -maxdepth 1 ...` prepends "./" -- the same shape every consumer's
    // original inline block already produced, so this is what cosign has
    // always actually been invoked with, not a property of this action.
    report(argv[argv.length - 1] === './extension.vsix', 'the auto-discovered .vsix path is the final positional argument');
    const bundleIdx = argv.indexOf('--bundle');
    report(bundleIdx !== -1 && argv[bundleIdx + 1] === './extension.vsix.bundle',
        'the bundle path defaults to <vsix>.bundle when not overridden');
}

// ── a failed verification propagates ────────────────────────────────────
{
    const { res } = run('cosign-rejects', { exitCode: 1 });
    report(res.status !== 0, 'a cosign rejection fails the step -- never swallowed');
}

// ── auto-discovery fails closed when no .vsix is present ───────────────
{
    const { res, calls, out } = run('no-vsix', { vsixPresent: false });
    report(res.status !== 0, 'no .vsix in the working directory fails closed');
    report(calls.length === 0, 'cosign is never invoked when there is nothing to verify');
    report(/No \.vsix file found/.test(out), 'the failure names what was missing');
}

// ── explicit vsix-path / bundle-path override discovery ────────────────
{
    const dir = path.join(workRoot, 'explicit-paths');
    fs.mkdirSync(dir, { recursive: true });
    const nested = path.join(dir, 'artifacts');
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, 'my.vsix'), 'fake');
    fs.writeFileSync(path.join(nested, 'my.custom.bundle'), 'fake bundle');
    const { binDir, logFile } = makeFakeCosign(dir, 0);
    const scriptPath = path.join(dir, 'run.sh');
    fs.writeFileSync(scriptPath, `#!/usr/bin/env bash\n${runBlock}\n`, { mode: 0o755 });
    const res = spawnSync('bash', [scriptPath], {
        cwd: dir,
        encoding: 'utf8',
        env: {
            PATH: `${binDir}:${process.env.PATH}`,
            CERTIFICATE_IDENTITY_REGEXP: '^https://example\\.invalid/.*$',
            CERTIFICATE_OIDC_ISSUER: 'https://token.actions.githubusercontent.com',
            VSIX_PATH: 'artifacts/my.vsix',
            BUNDLE_PATH: 'artifacts/my.custom.bundle',
        },
    });
    const calls = fs.existsSync(logFile)
        ? fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
        : [];
    report(res.status === 0, 'an explicit vsix-path/bundle-path pair is honored');
    const argv = calls[0] || [];
    report(argv[argv.length - 1] === 'artifacts/my.vsix', 'the explicit vsix-path is used verbatim, not auto-discovered');
    const bundleIdx = argv.indexOf('--bundle');
    report(bundleIdx !== -1 && argv[bundleIdx + 1] === 'artifacts/my.custom.bundle',
        'the explicit bundle-path is used verbatim rather than defaulting to <vsix>.bundle');
}

fs.rmSync(workRoot, { recursive: true, force: true });

const ASSERTION_FLOOR = 10;
if (assertions < ASSERTION_FLOOR) {
    console.error(`  FAIL harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
    failures += 1;
} else {
    console.log(`  OK   harness: made ${assertions} assertion(s), floor is ${ASSERTION_FLOOR}`);
}

if (failures > 0) {
    console.error(`\ntest-verify-vsix-signature: ${failures} failure(s).`);
    process.exit(1);
}
console.log('\ntest-verify-vsix-signature: all cases pass.');
