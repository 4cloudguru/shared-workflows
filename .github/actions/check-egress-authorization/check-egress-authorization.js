#!/usr/bin/env node
// EGRESS-AUTHORIZATION SIGNATURE (#161 / #191, sibling azure-pipelines-packer #161).
//
// Defect class
// ------------
//   An egress destination is authorized by inspecting its TEXTUAL form rather
//   than its RESOLVED address, and the authorization is not re-applied to every
//   hop or at connect time.
//
// That shape produced five separate regressions in one audit: a dotted-quad
// blocklist that `127.1`, `2130706433`, `0x7f000001` and `[::ffff:127.0.0.1]`
// all walk past (they are 127.0.0.1 to the socket), RFC6598 100.64.0.0/10 that
// was never listed at all, and a redirect-hop callback that re-checked only the
// literal blocklist while the initial-host check also resolved DNS.
//
// What this script enforces
// -------------------------
//   1. Every DYNAMIC-destination network sink (a download/fetch whose URL is not
//      a constant host) must sit in a function that routes the host through
//      `assertEgressHostAllowed` — the single helper that applies the allowlist
//      OR the numeric private/reserved + DNS check, identically for the initial
//      URL and for every redirect hop.
//   2. A site that authorizes with the raw primitives (`isPrivateOrLinkLocalHost`
//      / `isRegistryHostAllowed`) but not the helper is reported as TEXTUAL-ONLY
//      and FAILS: that is exactly the half-applied shape that regressed, where an
//      initial check and a per-hop check could drift apart.
//   3. Address classification may only live in the shared allowlist module. A
//      dotted-quad regex or a hardcoded loopback/metadata literal anywhere else
//      in a src/ tree is reported as a SUSPECT textual blocklist and FAILS.
//
// Repo-agnostic: it discovers `**/src/**/*.ts` under the repo root, so it runs
// unchanged in azure-pipelines-terraform and azure-pipelines-packer (and in any
// sibling that grows an installer). Usage:
//
//     node scripts/check-egress-authorization.js [repoRoot]
//
// Exit 0 = no residual instances of the class. Exit 1 = residuals, listed.

const fs = require('fs');
const path = require('path');

// `--json` prints the machine-readable finding list (used by the class test's
// per-site table) instead of the human report; the exit code is identical.
const JSON_OUTPUT = process.argv.includes('--json');
const ROOT = path.resolve(process.argv.filter(a => a !== '--json')[2] || process.cwd());

// The helper that IS the fix. A site routed through it is authorized.
const AUTHORIZER = 'assertEgressHostAllowed';

// The raw primitives. Present WITHOUT the authorizer = the half-applied shape.
const RAW_PRIMITIVES = ['isPrivateOrLinkLocalHost', 'isRegistryHostAllowed', 'resolvesToPrivateOrLinkLocalAddress'];

// The one module allowed to contain address-classification logic.
const CLASSIFIER_MODULE = 'registry-allowlist.ts';

// Outbound network sinks. Deliberately broad: any of these initiating a request
// to a destination this process did not fix at build time is in the class.
const SINKS = [
    'downloadToFile', 'downloadTool', 'downloadToolWithTimeout', 'downloadTo',
    'downloadFromMirrorUrl', 'fetchWithTimeout', 'fetchJson', 'fetchText',
    'fetchTextAllow404', 'fetchBuffer', 'fetchBufferAllow404',
    // This repo's own transports (#124): neither is a CLI-tool-installer
    // download, so neither matched anything above until added here. snRequest's
    // signature is (method, url, options?) -- url is its 2nd argument.
    // adoRequest's is (connection, method, url, body?, transport?) -- url is
    // its 3rd.
    { name: 'snRequest', urlArgIndex: 1 }, { name: 'adoRequest', urlArgIndex: 2 },
];

// Normalized {name, urlArgIndex} form. A bare string keeps the default (index 0)
// every sink used before adoRequest needed something else.
const SINK_ENTRIES = SINKS.map(s => (typeof s === 'string' ? { name: s, urlArgIndex: 0 } : { name: s.name, urlArgIndex: s.urlArgIndex ?? 0 }));


// A host built by calling a small local helper is not itself runtime-allowlist
// material when that helper's OWN doc comment carries this marker: the review
// lives with the one function that actually knows why (a value the platform
// supplies with no operator or attacker path to it, or an identifier already
// checked against a restrictive charset before use), rather than being
// asserted at every call site that happens to use it. This is a NARROWER
// promise than a fixed literal: it is reported, never silent, so a reviewer
// still sees every one of these in the printed output and can re-open the
// question by reading the cited helper.
function egressReviewedHelperReason(expr, allSource) {
    const call = expr.match(/\$\{\s*(\w+)\s*\(/);
    if (!call) return null;
    const defRe = new RegExp(`(?:export\\s+)?(?:async\\s+)?function\\s+${call[1]}\\s*\\(`);
    const dm = defRe.exec(allSource);
    if (!dm) return null;
    // Bounded look-back for the doc comment immediately preceding the function
    // (anchored to end right where the function starts) -- NOT a lazy scan over
    // the whole corpus, which can backtrack through unrelated comments/functions
    // and return the WRONG helper's marker when several are defined nearby.
    const before = allSource.slice(Math.max(0, dm.index - 1000), dm.index);
    const doc = before.match(/\/\*\*([\s\S]*?)\*\/\s*$/);
    if (!doc) return null;
    const marker = doc[1].match(/@egress-reviewed:\s*([^\n*]+)/);
    return marker ? marker[1].trim() : null;
}

// A function may authorize by INVOKING an authorizer its caller injects, rather
// than by calling assertEgressHostAllowed itself. Recognized structurally -- a
// parameter declared to take a hostname and return a promise -- not by name.
// Callers of such a function are separately required to pass the real authorizer
// (see AUTHORIZER_ARG below); recognizing the parameter alone would let a caller
// hand over a no-op and still read as authorized.
const AUTHORIZER_PARAM = /(\w+)\s*:\s*\(\s*(?:hostname|host)\s*:\s*string\s*\)\s*=>\s*Promise\s*<\s*void\s*>/g;

function authorizerParams(header) {
    return [...header.matchAll(AUTHORIZER_PARAM)].map(m => m[1]);
}

function invokesInjectedAuthorizer(fn) {
    return authorizerParams(fn.header).some(p => new RegExp(`await\\s+${p}\\s*\\(`).test(fn.text));
}

function walk(dir, out = []) {
    let entries;
    try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
        return out;
    }
    for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'build') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full, out);
        else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts') && full.includes(`${path.sep}src${path.sep}`)) out.push(full);
    }
    return out;
}

/** Index of the matching ')' for the '(' at `open`. */
function matchParen(text, open) {
    let depth = 0;
    for (let i = open; i < text.length; i++) {
        const c = text[i];
        if (c === '(' || c === '[' || c === '{') depth++;
        else if (c === ')' || c === ']' || c === '}') {
            depth--;
            if (depth === 0) return i;
        }
    }
    return text.length;
}

// ---- Units: the functions, and class members, a file is analysed as ----------
//
// Everything from here to topLevelFunctions() reads the MASKED text, plus the
// source where a blanked string has to be told apart from a blanked comment.

/** The top-level `{ }` pairs of the masked text, by brace depth. */
function topLevelBlocks(masked) {
    const blocks = [];
    let depth = 0;
    let openIndex = -1;
    for (let i = 0; i < masked.length; i++) {
        const c = masked[i];
        if (c === '{') {
            if (depth === 0) openIndex = i;
            depth++;
        } else if (c === '}') {
            depth--;
            if (depth === 0 && openIndex >= 0) {
                blocks.push([openIndex, i]);
                openIndex = -1;
            }
        }
    }
    return blocks;
}

/**
 * Index of the `}` closing the `{` at `open`, counting braces only -- the way
 * topLevelBlocks() does, so a body ends where its block does. Counting
 * parentheses too let an unmatched `(` carry one function on over every block
 * after it: the masker has no regex-literal state, so `/url\s*\(/` leaves one.
 */
function closingBrace(masked, open) {
    let depth = 0;
    for (let i = open; i < masked.length; i++) {
        if (masked[i] === '{') depth++;
        else if (masked[i] === '}' && --depth === 0) return i;
    }
    return masked.length;
}

// A line break ends a statement (or a class member) when the next line starts a
// new one -- a name, a keyword, a decorator -- rather than an operator that
// carries the expression on.
const STARTS_STATEMENT = /^\s*(?!(?:instanceof|in|of|as|satisfies|extends|implements)(?![\w$]))[A-Za-z_$#@]/;

// Words after which an expression or a type cannot have ended.
const CONTINUES = new Set(['instanceof', 'in', 'of', 'as', 'satisfies', 'typeof', 'keyof', 'new', 'delete',
    'await', 'yield', 'extends', 'implements', 'infer', 'is', 'readonly', 'unique', 'asserts']);

/**
 * The last token before `i`: `=>`, a word, one punctuation character, or `'` for
 * a string literal -- which is blank in the masked text and is recognised by the
 * closing quote the source still has there.
 */
function lastToken(masked, source, i) {
    let j = i - 1;
    while (j >= 0 && /\s/.test(masked[j])) j--;
    if (/['"`]$/.test(source.slice(j + 1, i).trimEnd())) return "'";
    if (j < 0) return '';
    if (masked[j] === '>' && masked[j - 1] === '=') return '=>';
    const word = /[\w$]+$/.exec(masked.slice(Math.max(0, j - 40), j + 1));
    return word ? word[0] : masked[j];
}

/** Whether `token` can end a value or a type, i.e. nothing more of it has to follow. */
const endsValue = (token) => token === "'" || token === ')' || token === ']' || token === '}' || token === '>'
    || (/^[\w$]+$/.test(token) && !CONTINUES.has(token));

/**
 * Index just past the statement (or class member) that continues at `from`: past
 * its `;`, or at the line break the next one starts after, or at the `}` closing
 * the block it sits in. Braces only, for closingBrace()'s reason: a `;` that does
 * not end the statement can only sit in a body or a type literal.
 */
function statementEnd(masked, source, from) {
    let depth = 0;
    for (let i = from; i < masked.length; i++) {
        const c = masked[i];
        if (c === '{') depth++;
        else if (c === '}') {
            if (--depth < 0) return i;
        } else if (depth === 0 && c === ';') return i + 1;
        else if (depth === 0 && c === '\n' && STARTS_STATEMENT.test(masked.slice(i + 1, i + 80))
            && endsValue(lastToken(masked, source, i))) return i;
    }
    return masked.length;
}

/**
 * Index of the `{` opening the body of the declaration whose head continues at
 * `from` -- after its parameter list, or after a class's name -- or -1 when the
 * head ends first: at a `;`, or at the line break a new statement follows (an
 * overload, an abstract member). A `{` in a type position is a type literal and
 * is stepped over: `Promise<{ a: T }>`, `: { a: T }`, `() => { a: T }`.
 */
function bodyAfter(masked, source, from) {
    let depth = 0;
    for (let i = from; i < masked.length; i++) {
        const c = masked[i];
        if (c === '(' || c === '[' || c === '<') depth++;
        else if (c === ')' || c === ']' || (c === '>' && masked[i - 1] !== '=')) depth--;
        else if (c === '{') {
            if (depth === 0 && endsValue(lastToken(masked, source, i))) return i;
            i = closingBrace(masked, i);
        } else if (c === '}' || (depth === 0 && c === ';')) return -1;
        else if (depth === 0 && c === '\n' && STARTS_STATEMENT.test(masked.slice(i + 1, i + 80))
            && endsValue(lastToken(masked, source, i))) return -1;
    }
    return -1;
}

/** Index of the `>` closing the type parameter list whose `<` is at `open`. */
function closingAngle(masked, open) {
    let depth = 0;
    for (let i = open; i < masked.length; i++) {
        const c = masked[i];
        if (c === '<' || c === '(' || c === '[' || c === '{') depth++;
        else if (c === ')' || c === ']' || c === '}' || (c === '>' && masked[i - 1] !== '=')) {
            if (--depth === 0) return i;
        }
    }
    return masked.length;
}

/**
 * The parameter names of the list whose `(` is at `open`, split only at commas no
 * bracket, type argument or callback type encloses.
 *
 * Read as `[^)]*` and split at every comma, a list stopped at the first `)` -- and
 * a callback-typed parameter puts one inside it -- and split inside `Map<K, V>`
 * and `(a: A, b: B) => C`, so a parameter could be lost or found at the wrong
 * position.
 */
function paramNames(masked, open) {
    const close = matchParen(masked, open);
    const params = [];
    let depth = 0;
    let start = open + 1;
    for (let i = open + 1; i < close; i++) {
        const c = masked[i];
        if (c === '(' || c === '[' || c === '{' || c === '<') depth++;
        else if (c === ')' || c === ']' || c === '}' || (c === '>' && masked[i - 1] !== '=')) depth--;
        else if (c === ',' && depth === 0) {
            params.push(masked.slice(start, i));
            start = i + 1;
        }
    }
    params.push(masked.slice(start, close));
    // A constructor's parameter properties carry an access modifier.
    return params.map((p) => p.trim().split(':')[0].trim()
        .replace(/^(?:@[\w$.]+(?:\([^)]*\))?\s*)*(?:(?:public|private|protected|readonly|override)\s+)*/, ''))
        .filter(Boolean);
}

/**
 * If the expression at `at` is itself a function -- `function (...)`, `(...) =>`
 * or `x =>`, each optionally async -- its parameter names, else null.
 */
function functionParamsAt(masked, at) {
    const lead = /\s*(?:async\s+)?(function(?![\w$])\s*\*?\s*(?:[A-Za-z_$][\w$]*)?)?\s*/y;
    lead.lastIndex = at;
    const m = lead.exec(masked);
    let i = lead.lastIndex;
    if (masked[i] === '<') {
        i = closingAngle(masked, i) + 1;
        while (/\s/.test(masked[i])) i++;
    }
    if (masked[i] === '(') {
        if (m[1]) return paramNames(masked, i);
        // An arrow: the list, an optional return type, then `=>`.
        let j = matchParen(masked, i) + 1;
        while (/\s/.test(masked[j])) j++;
        if (masked[j] === ':') {
            for (let depth = 0; ++j < masked.length;) {
                const c = masked[j];
                if (depth === 0 && c === '=' && masked[j + 1] === '>') break;
                if (c === '(' || c === '[' || c === '{' || c === '<') depth++;
                else if (c === ')' || c === ']' || c === '}' || (c === '>' && masked[j - 1] !== '=')) {
                    if (--depth < 0) return null;
                } else if (depth === 0 && (c === ';' || c === ',')) return null;
            }
        }
        return masked[j] === '=' && masked[j + 1] === '>' ? paramNames(masked, i) : null;
    }
    const one = /([A-Za-z_$][\w$]*)\s*=>/y;
    one.lastIndex = i;
    const single = m[1] ? null : one.exec(masked);
    return single ? [single[1]] : null;
}

/**
 * The declarators of the `const`/`let`/`var` statement whose names begin at
 * `from` and which ends at `end`: each one's name (null for a destructuring
 * pattern), its range, and -- when its initializer is itself a function -- that
 * function's parameters.
 */
function declaratorsOf(masked, from, end) {
    const out = [];
    for (let i = from; i < end;) {
        const head = /\s*(?:([A-Za-z_$][\w$]*)|[{[])/y;
        head.lastIndex = i;
        const m = head.exec(masked);
        if (!m) break;
        const start = head.lastIndex - (m[1] ? m[1].length : 1);
        let j = m[1] ? head.lastIndex : matchParen(masked, start) + 1;
        // Its type, if annotated -- where type arguments nest and `=>` is not `=`.
        let eq = -1;
        for (let depth = 0; j < end; j++) {
            const c = masked[j];
            if (c === '(' || c === '[' || c === '{' || c === '<') depth++;
            else if (c === ')' || c === ']' || c === '}' || (c === '>' && masked[j - 1] !== '=')) depth--;
            else if (depth === 0 && c === '=' && masked[j + 1] !== '>') { eq = j; break; }
            else if (depth === 0 && c === ',') break;
        }
        // Its initializer, to the next comma no bracket encloses that a
        // declarator follows -- the comma in `<K, V>(k: K) =>` or `new Map<K, V>()`
        // separates type arguments.
        if (eq >= 0) {
            let depth = 0;
            for (j = eq + 1; j < end; j++) {
                const c = masked[j];
                if (c === '(' || c === '[' || c === '{') depth++;
                else if (c === ')' || c === ']' || c === '}') depth--;
                else if (depth === 0 && c === ','
                    && /^\s*(?:[A-Za-z_$][\w$]*\s*(?:[:=,;!]|$)|[{[])/.test(masked.slice(j + 1, end))) break;
            }
        }
        out.push({ name: m[1] || null, start, end: Math.min(j, end), params: eq >= 0 ? functionParamsAt(masked, eq + 1) || [] : [] });
        i = j + 1;
    }
    return out;
}

/**
 * Every top-level declaration that can own a block, with the range it spans: a
 * function, a class (with the `{` of its body), each declarator of a
 * `const`/`let`/`var`, and -- as kind `type` -- the declarations that hold no
 * code: an interface, a type alias, an enum, anything `declare`d, an overload.
 *
 * A keyword is only an anchor where it is at the top level, which is read off a
 * copy with every top-level block's inside blanked -- so the `const` of a local
 * variable can no longer name the block after the function it is in.
 */
function declarationsOf(source, masked, blocks) {
    const flat = masked.split('');
    for (const [open, close] of blocks) {
        for (let i = open + 1; i < close; i++) if (flat[i] !== '\n') flat[i] = ' ';
    }
    const top = flat.join('');
    const decls = [];
    const keyword = /(?<![\w$.])((?:(?:export|default|declare|abstract|async)\s+)*)(function|class|const|let|var|interface|type|enum|namespace|module|global)(?![\w$])/g;
    let parens = 0;
    let scanned = 0;
    for (const m of top.matchAll(keyword)) {
        for (; scanned < m.index; scanned++) {
            if (top[scanned] === '(' || top[scanned] === '[') parens++;
            else if (top[scanned] === ')' || top[scanned] === ']') parens--;
        }
        const [, prefix, kind] = m;
        const start = m.index;
        const at = m.index + m[0].length;
        const declared = /declare/.test(prefix);
        const byDefault = /default/.test(prefix) ? 'default' : null;
        const extent = (from) => {
            const body = bodyAfter(masked, source, from);
            return { body, end: body < 0 ? statementEnd(masked, source, from) : closingBrace(masked, body) + 1 };
        };
        if (kind === 'function') {
            const head = /\s*\*?\s*([A-Za-z_$][\w$]*)?\s*/y;
            head.lastIndex = at;
            const name = head.exec(masked)[1] || byDefault;
            let open = head.lastIndex;
            if (masked[open] === '<') {
                open = closingAngle(masked, open) + 1;
                while (/\s/.test(masked[open])) open++;
            }
            if (masked[open] !== '(') continue;
            const { body, end } = extent(matchParen(masked, open) + 1);
            decls.push(declared || body < 0 ? { kind: 'type', start, end }
                : { kind: 'function', name, start, end, params: paramNames(masked, open) });
        } else if (kind === 'class') {
            const head = /\s+(?!(?:extends|implements)(?![\w$]))([A-Za-z_$][\w$]*)/y;
            head.lastIndex = at;
            const named = head.exec(masked);
            const { body, end } = extent(named ? head.lastIndex : at);
            if (body < 0) continue;
            decls.push(declared ? { kind: 'type', start, end } : { kind: 'class', name: named ? named[1] : byDefault, start, end, body });
        } else if (kind === 'const' || kind === 'let' || kind === 'var') {
            if (parens !== 0) continue;
            if (declared || /^\s+enum(?![\w$])/.test(masked.slice(at, at + 12))) {
                decls.push({ kind: 'type', start, end: declared ? statementEnd(masked, source, at) : extent(at).end });
                continue;
            }
            declaratorsOf(masked, at, statementEnd(masked, source, at)).forEach((d, n) =>
                decls.push({ kind: 'var', name: d.name, start: n === 0 ? start : d.start, end: d.end, params: d.params }));
        } else if (kind === 'type') {
            if (/^\s+[A-Za-z_$][\w$]*\s*[<=]/.test(masked.slice(at, at + 200))) {
                decls.push({ kind: 'type', start, end: statementEnd(masked, source, at) });
            }
        } else if (kind === 'interface' || kind === 'enum' || declared) {
            decls.push({ kind: 'type', start, end: extent(at).end });
        }
    }
    return decls;
}

/**
 * The declaration that owns the block opening at `open`: a variable whose
 * initializer holds it, however deep, or else the innermost function, class or
 * type declaration that spans it. Null when none does -- a statement that ended
 * before the `{` cannot name it.
 */
function ownerOf(decls, open) {
    const spanning = decls.filter((d) => d.start < open && open < d.end);
    return spanning.find((d) => d.kind === 'var') || spanning[spanning.length - 1] || null;
}

/**
 * The members of the class whose body is masked[open..close]: each one's name,
 * where that name is (`at`), the blocks inside it, and the parameters of the
 * function it is -- a method, or a property whose initializer is a function. A
 * static block, or anything the scan cannot read, belongs to the class and is
 * named after it.
 */
function classMembers(source, masked, open, close, className) {
    const inner = [];
    for (let i = open + 1, depth = 0, from = -1; i < close; i++) {
        if (masked[i] === '{') {
            if (depth++ === 0) from = i;
        } else if (masked[i] === '}' && --depth === 0) inner.push([from, i]);
    }
    const members = [];
    // Whitespace and comments, read off the source: a member can be named by a
    // string literal, which the masked copy blanks exactly as it does a comment.
    const skip = (k) => {
        for (;;) {
            while (k < close && /\s/.test(source[k])) k++;
            const past = source.startsWith('//', k) ? source.indexOf('\n', k)
                : source.startsWith('/*', k) ? source.indexOf('*/', k) + 2 : k;
            if (past === k) return k;
            if (past < k) return close;
            k = past;
        }
    };
    const modifier = /(?:public|private|protected|static|readonly|override|abstract|declare|accessor|async|get|set)\s+(?=[^\s(<=:;?!,)}])/y;
    for (let i = skip(open + 1); i < close; i = skip(i)) {
        if (masked[i] === ';') {
            i++;
            continue;
        }
        const head = i;
        for (let more = true; more;) {
            more = false;
            if (masked[i] === '@') {
                const decorator = /@[\w$.]*\s*/y;
                decorator.lastIndex = i;
                decorator.exec(masked);
                i = masked[decorator.lastIndex] === '(' ? skip(matchParen(masked, decorator.lastIndex) + 1) : decorator.lastIndex;
                more = true;
            }
            modifier.lastIndex = i;
            if (modifier.test(masked)) {
                i = modifier.lastIndex;
                more = true;
            }
        }
        if (masked[i] === '{') {
            const end = closingBrace(masked, i) + 1;
            members.push({ name: className, at: null, head, end, params: [] });
            i = end;
            continue;
        }
        if (masked[i] === '*') i = skip(i + 1);
        const at = i;
        let name = null;
        const id = /#?[A-Za-z_$][\w$]*|\d[\w.]*/y;
        id.lastIndex = i;
        const word = id.exec(masked);
        if (word) {
            name = word[0];
            i = id.lastIndex;
        } else if (masked[i] === '[') {
            const e = matchParen(masked, i);
            name = source.slice(i, e + 1);
            i = e + 1;
        } else if (/['"]/.test(source[i])) {
            let e = i + 1;
            while (e < close && source[e] !== source[i]) e += source[e] === '\\' ? 2 : 1;
            name = source.slice(i + 1, e);
            i = e + 1;
        }
        i = skip(i);
        if (masked[i] === '?' || masked[i] === '!') i = skip(i + 1);
        let params = [];
        let end;
        if (name !== null && (masked[i] === '(' || masked[i] === '<')) {
            if (masked[i] === '<') i = skip(closingAngle(masked, i) + 1);
            const body = masked[i] === '(' ? bodyAfter(masked, source, matchParen(masked, i) + 1) : -1;
            if (masked[i] === '(') params = paramNames(masked, i);
            end = body >= 0 ? closingBrace(masked, body) + 1 : statementEnd(masked, source, i);
        } else {
            end = statementEnd(masked, source, i);
            const eq = /^\s*(?::[^=]*?)?=(?!>)/.exec(masked.slice(i, end));
            if (name !== null && eq) params = functionParamsAt(masked, i + eq[0].length) || [];
        }
        end = Math.max(end, i + 1);
        members.push({ name: name === null ? className : name, at: name === null ? null : at, head, end, params });
        i = end;
    }
    for (const m of members) m.blocks = inner.filter(([o]) => o >= m.head && o < m.end);
    const orphans = inner.filter(([o]) => !members.some((m) => o >= m.head && o < m.end));
    if (orphans.length) members.push({ name: className, at: null, head: orphans[0][0], end: close, params: [], blocks: orphans });
    return members;
}

/**
 * Splits a file into the units a sink is attributed to, each named after the
 * declaration that OWNS its block -- a top-level function or variable or, in a
 * class, the member: the unit responsible for authorizing it. Returns
 * [{ name, start, end, text, header, params, member }].
 *
 * Anchoring on the declaration keyword instead of reading a fixed two lines
 * back from the `{` is what stopped a signature wrapped over more lines from
 * parsing as <anonymous> and taking every sink inside it out of this gate. But
 * the anchor was the nearest `function` or `const` in the 2000 characters above,
 * and `class` was not a declaration: a class body had no name and was skipped,
 * or borrowed one -- `const TIMEOUT_MS` above `export class Puller` named every
 * sink in Puller's methods. A declaration now names only a block it CONTAINS,
 * and a class body is split into its members, each named after the member. A
 * block no declaration owns -- a top-level `if`, a callback handed to a call --
 * is `<module>` and is still verdicted, where it used to borrow the name of
 * whatever came before it. An interface, type alias, enum or `declare` body
 * holds no code, so a method signature in one is not a sink.
 */
function topLevelFunctions(source) {
    const masked = maskCommentsAndStrings(source);
    const blocks = topLevelBlocks(masked);
    const decls = declarationsOf(source, masked, blocks);
    const units = [];
    const unit = (name, [open, close], head, params, member) => units.push({
        name,
        start: open,
        end: close + 1,
        text: source.slice(open, close + 1),
        header: source.slice(head, open),
        params,
        member,
    });
    for (const block of blocks) {
        const owner = ownerOf(decls, block[0]);
        if (owner && owner.kind === 'type') continue;
        if (owner && owner.kind === 'class') {
            if (block[0] !== owner.body) continue;
            for (const m of classMembers(source, masked, block[0], block[1], owner.name || '<module>')) {
                for (const b of m.blocks) unit(m.name, b, m.head, m.params, true);
            }
        } else if (owner && owner.name) unit(owner.name, block, owner.start, owner.params, false);
        else unit('<module>', block, block[0], [], false);
    }
    return units;
}

/**
 * A predicate: does index `i` of `source` DECLARE a name rather than call it --
 * a class member's name, or anything inside an interface, type alias or
 * `declare` -- so a method's own signature `name(url, authorize: ...) {` is not
 * read as a call site handing over its parameter declaration as the authorizer.
 */
function declarationHeads(source) {
    const masked = maskCommentsAndStrings(source);
    const decls = declarationsOf(source, masked, topLevelBlocks(masked));
    const names = new Set();
    for (const d of decls) {
        if (d.kind !== 'class') continue;
        for (const m of classMembers(source, masked, d.body, closingBrace(masked, d.body), d.name)) names.add(m.at);
    }
    const types = decls.filter((d) => d.kind === 'type');
    return (i) => names.has(i) || types.some((d) => i >= d.start && i < d.end);
}

/**
 * Returns a copy of `source` with every comment and string/template literal
 * blanked out (offsets preserved), so a sink NAME appearing in prose — e.g. the
 * comment "fetchJson() guards against a non-JSON body" — is never scanned as a
 * call. Argument text is still read from the original source.
 */
function maskCommentsAndStrings(source) {
    const out = source.split('');
    let inLine = false, inBlock = false, quote = null;
    for (let i = 0; i < source.length; i++) {
        const c = source[i], next = source[i + 1];
        if (inLine) { if (c === '\n') inLine = false; else out[i] = ' '; continue; }
        if (inBlock) { if (c === '*' && next === '/') { out[i] = out[i + 1] = ' '; inBlock = false; i++; } else if (c !== '\n') out[i] = ' '; continue; }
        if (quote) {
            if (c === '\\') { out[i] = ' '; if (source[i + 1] !== '\n') out[i + 1] = ' '; i++; continue; }
            if (c === quote) { out[i] = ' '; quote = null; continue; }
            if (c !== '\n') out[i] = ' ';
            continue;
        }
        if (c === '/' && next === '/') { out[i] = out[i + 1] = ' '; inLine = true; i++; continue; }
        if (c === '/' && next === '*') { out[i] = out[i + 1] = ' '; inBlock = true; i++; continue; }
        if (c === '"' || c === "'" || c === '`') { out[i] = ' '; quote = c; continue; }
    }
    return out.join('');
}

/** Extracts every argument of the call whose '(' is at or after `index`. */
function allArguments(source, index) {
    const open = source.indexOf('(', index);
    if (open < 0) return [];
    const args = [];
    let depth = 0, start = open + 1;
    for (let i = open; i < source.length; i++) {
        const c = source[i];
        if (c === '(' || c === '[' || c === '{') depth++;
        else if (c === ')' || c === ']' || c === '}') {
            depth--;
            if (depth === 0) { args.push(source.slice(start, i)); break; }
        } else if (c === ',' && depth === 1) { args.push(source.slice(start, i)); start = i + 1; }
    }
    return args.map(a => a.trim());
}

/** Extracts argument `n` (0-based) of the call whose '(' is at or after `index`. */
function argumentAt(source, index, n) {
    const open = source.indexOf('(', index);
    if (open < 0) return '';
    const args = [];
    let depth = 0, start = open + 1;
    for (let i = open; i < source.length; i++) {
        const c = source[i];
        if (c === '(' || c === '[' || c === '{') depth++;
        else if (c === ')' || c === ']' || c === '}') {
            depth--;
            if (depth === 0) { args.push(source.slice(start, i)); break; }
        } else if (c === ',' && depth === 1) { args.push(source.slice(start, i)); start = i + 1; }
    }
    return (args[n] || '').trim();
}

/**
 * What the local helper `function name(...) { return <expr>; }` returns, or null.
 * Its parameter list is read by a balanced scan: `\([^)]*\)` ended the list at
 * the first `)`, so a helper with a callback-typed parameter could not be found.
 */
function helperReturn(source, name) {
    const masked = maskCommentsAndStrings(source);
    for (const m of masked.matchAll(new RegExp(`(?<![\\w$.])function\\s+${name}\\s*(?=[<(])`, 'g'))) {
        let open = m.index + m[0].length;
        if (masked[open] === '<') {
            open = closingAngle(masked, open) + 1;
            while (/\s/.test(masked[open])) open++;
        }
        if (masked[open] !== '(') continue;
        const body = bodyAfter(masked, source, matchParen(masked, open) + 1);
        if (body < 0) continue;
        const returned = /\{\s*return\s+([^;]+);/y;
        returned.lastIndex = body;
        const r = returned.exec(source);
        if (r) return r[1].trim();
    }
    return null;
}

/**
 * Resolves an argument expression to the URL it actually denotes, following ONE
 * level of local `const x = <expr>` and one level of `return` inside a local
 * helper, so `const u = getHashiCorpDownloadUrl(v); downloadTool(u, ...)` is
 * recognized as the constant host it is.
 */
function resolveExpression(expr, fnText, source) {
    if (/^[A-Za-z_]\w*$/.test(expr)) {
        const local = fnText.match(new RegExp(`\\b(?:const|let)\\s+${expr}\\s*(?::[^=]+)?=\\s*([^;]+);`));
        if (local) return resolveExpression(local[1].trim(), fnText, source);
        const helper = helperReturn(source, expr);
        if (helper !== null) return helper;
    }
    // A template whose leading interpolation is a local URL variable:
    // `${downloadUrl}.sha256` denotes whatever downloadUrl denotes.
    const leading = expr.match(/^`\$\{(\w+)\}/);
    if (leading) {
        const base = resolveExpression(leading[1], fnText, source);
        if (base !== leading[1]) {
            return base.replace(/`$/, '') + expr.slice(leading[0].length).replace(/`$/, '') + '`';
        }
    }
    const call = expr.match(/^(\w+)\s*\(/);
    if (call) {
        const helper = helperReturn(source, call[1]);
        if (helper !== null) return helper;
    }
    return expr;
}

/** A destination whose HOST cannot be influenced at run time. */
function isConstantHost(expr) {
    const literal = expr.match(/^['"](https?:\/\/[^'"/]+)/);
    if (literal) return true;
    const template = expr.match(/^`https?:\/\/([^`]*?)(?:\/|`)/);
    return !!(template && !template[1].includes('${'));
}

const files = walk(ROOT);
if (files.length === 0) {
    console.error(`FAIL: no **/src/**/*.ts files found under ${ROOT} — the signature would pass vacuously.`);
    process.exit(1);
}

// egressReviewedHelperReason needs to see a marked helper's definition even
// when it lives in a DIFFERENT file than the call site that imports it (e.g.
// a shared `baseUrl()` used by several src modules) -- so it searches the
// whole repo's src/ text, not just the current file's.
const ALL_SOURCE = files.map(f => fs.readFileSync(f, 'utf8')).join('\n');

const findings = [];
const suspects = [];

for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    // Site identities must be byte-stable across platforms: path.relative yields
    // backslashes on Windows, which would make every site id differ from the POSIX
    // form the class test and the ledger record.
    const rel = path.relative(ROOT, file).split(path.sep).join('/');
    const fns = topLevelFunctions(source);
    const masked = maskCommentsAndStrings(source);
    const lineOf = (i) => source.slice(0, i).split('\n').length;

    // --- 3. textual address classification outside the sanctioned module ---
    if (path.basename(file) !== CLASSIFIER_MODULE) {
        const textual = [
            /\/\^?\(?\\d\{1,3\}\\?\.\\d\{1,3\}/,          // dotted-quad regex
            /['"]169\.254\.169\.254['"]/,                  // metadata literal
            /===\s*['"]127\.0\.0\.1['"]/,                  // loopback comparison
            /===\s*['"]localhost['"]/,
            /startsWith\(\s*['"](?:10\.|192\.168\.|172\.1)/,
        ];
        source.split('\n').forEach((line, i) => {
            if (line.trim().startsWith('//') || line.trim().startsWith('*')) return;
            if (textual.some(re => re.test(line))) {
                suspects.push(`${rel}:${i + 1}: textual address classification outside ${CLASSIFIER_MODULE}: ${line.trim().slice(0, 100)}`);
            }
        });
    }

    // --- 1./2. sinks ---
    // Pass 0 DISCOVERS wrappers only (a function whose sink URL is one of its own
    // parameters delegates the authorization decision to its callers); pass 1 does
    // all the reporting, with those wrappers treated as sinks too.
    // name -> index of the argument that carries the URL (0 for the primitives).
    const wrappers = new Map();
    for (const pass of [0, 1]) {
        const sinkNames = pass === 0
            ? SINK_ENTRIES.map(e => [e.name, { index: e.urlArgIndex, authorized: false }])
            // Wrapper entries first: when a repo-local wrapper shares a name with a
            // base sink, its discovered URL-argument index and internal authorization
            // are the accurate reading, and the dedup below keeps the first verdict.
            : [...wrappers, ...SINK_ENTRIES.map(e => [e.name, { index: e.urlArgIndex, authorized: false }])];
        for (const [name, { index: urlArgIndex, authorized: viaWrapper }] of sinkNames) {
            const re = new RegExp(`(?<![.\\w])(?:\\w+\\.)?${name}\\s*(?:<[^>(]*>)?\\s*\\(`, 'g');
            let m;
            while ((m = re.exec(masked)) !== null) {
                const fn = fns.find(f => m.index > f.start && m.index < f.end);
                if (!fn || fn.name === name) continue;
                const raw = argumentAt(source, m.index + m[0].length - 1, urlArgIndex);
                const { params } = fn;
                // The URL is one of this function's own parameters: the
                // authorization decision belongs to its CALLERS, so record the
                // parameter position and re-scan treating calls to it as sinks.
                if (params.includes(raw)) {
                    if (pass === 0) wrappers.set(fn.name, { index: params.indexOf(raw), authorized: fn.text.includes(`${AUTHORIZER}(`) });
                    continue;
                }
                const expr = resolveExpression(raw, fn.text, source);
                if (pass === 0) continue;
                // A sink that takes a per-hop authorization CALLBACK must have the
                // authorizer INSIDE that callback, not merely somewhere in the
                // enclosing function. That distinction is the #191 defect exactly:
                // the initial-host check resolved DNS while the redirect-hop
                // callback re-checked only the textual blocklist, and a
                // function-level test could not tell the two apart.
                const callbackArgs = allArguments(source, m.index + m[0].length - 1)
                    .filter(a => a.includes('=>') || /^(async\s+)?function\b/.test(a));
                // The constant-host exemption only applies to sinks with NO per-hop
                // callback: a one-shot fetch to a hardcoded host has nowhere else to
                // go. A sink that ALSO accepts an authorization callback (#334) can
                // still follow redirects to an attacker-controlled host even though
                // its INITIAL url is a compile-time constant, so it must be judged
                // on whether that callback actually authorizes, not exempted.
                if (isConstantHost(expr) && callbackArgs.length === 0) {
                    findings.push({ verdict: 'EXEMPT-CONSTANT-HOST', rel, line: lineOf(m.index), fn: fn.name, sink: name, expr: expr.slice(0, 70) });
                    continue;
                }
                const callbackUnauthorized = callbackArgs.length > 0
                    && !callbackArgs.every(a => a.includes(`${AUTHORIZER}(`));
                // A call to a wrapper that authorizes internally is authorized:
                // the decision belongs wherever the destination host is known.
                const authorized = !callbackUnauthorized
                    && (viaWrapper || fn.text.includes(`${AUTHORIZER}(`) || invokesInjectedAuthorizer(fn));
                const rawOnly = !authorized
                    && (callbackUnauthorized || RAW_PRIMITIVES.some(p => fn.text.includes(`${p}(`)));
                const reviewedReason = !authorized && !rawOnly ? egressReviewedHelperReason(expr, ALL_SOURCE) : null;
                let verdict;
                if (authorized) verdict = 'AUTHORIZED';
                else if (rawOnly) verdict = 'TEXTUAL-ONLY';
                else if (reviewedReason) verdict = 'EXEMPT-REVIEWED';
                else verdict = 'UNAUTHORIZED';
                findings.push({
                    verdict, rel, line: lineOf(m.index), fn: fn.name, sink: name,
                    expr: expr.slice(0, 70) + (reviewedReason ? ` — ${reviewedReason}` : ''),
                });
            }
        }
    }

    // --- default-injected transport aliases ---
    // `request: RequestFn = adoRequest` is this codebase's standard test-
    // injection seam (also `transport: Transport = httpsRequest` elsewhere):
    // the PRODUCTION call always resolves to the default, so a call through the
    // LOCAL PARAMETER NAME, inside the one function that declares the default,
    // is the same sink under a different spelling -- otherwise a sink reached
    // only this way (as adoRequest is, here) never matches its own name.
    for (const fn of fns) {
        const aliasRe = /(\w+)\s*:\s*\w+\s*=\s*(\w+)\s*[,)]/g;
        let am;
        while ((am = aliasRe.exec(fn.header)) !== null) {
            const entry = SINK_ENTRIES.find(e => e.name === am[2]);
            if (!entry) continue;
            const localName = am[1];
            const callRe = new RegExp(`(?<![.\\w])${localName}\\s*\\(`, 'g');
            const fnMasked = masked.slice(fn.start, fn.end);
            let cm;
            while ((cm = callRe.exec(fnMasked)) !== null) {
                const absIndex = fn.start + cm.index;
                const raw = argumentAt(source, absIndex + cm[0].length - 1, entry.urlArgIndex);
                const expr = resolveExpression(raw, fn.text, source);
                if (isConstantHost(expr)) {
                    findings.push({ verdict: 'EXEMPT-CONSTANT-HOST', rel, line: lineOf(absIndex), fn: fn.name, sink: entry.name, expr: expr.slice(0, 70) });
                    continue;
                }
                const authorized = fn.text.includes(`${AUTHORIZER}(`) || invokesInjectedAuthorizer(fn);
                const rawOnly = !authorized && RAW_PRIMITIVES.some(p => fn.text.includes(`${p}(`));
                const reviewedReason = !authorized && !rawOnly ? egressReviewedHelperReason(expr, ALL_SOURCE) : null;
                let verdict;
                if (authorized) verdict = 'AUTHORIZED';
                else if (rawOnly) verdict = 'TEXTUAL-ONLY';
                else if (reviewedReason) verdict = 'EXEMPT-REVIEWED';
                else verdict = 'UNAUTHORIZED';
                findings.push({
                    verdict, rel, line: lineOf(absIndex), fn: fn.name, sink: entry.name,
                    expr: expr.slice(0, 70) + (reviewedReason ? ` — ${reviewedReason}` : ''),
                });
            }
        }
    }
}

const order = ['UNAUTHORIZED', 'TEXTUAL-ONLY', 'AUTHORIZED', 'EXEMPT-REVIEWED', 'EXEMPT-CONSTANT-HOST'];
const seen = new Set();
const unique = findings.filter(f => {
    const key = `${f.rel}:${f.line}:${f.sink}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
});

// A function that authorizes through an injected authorizer only actually
// authorizes if its CALLERS hand it the real one. Without this, satisfying the
// gate would be as easy as declaring the parameter and passing () => {}.
const injectedCallSiteFailures = [];
const injectedSeen = new Set();
const declaresIn = new Map();
for (const file of files) {
    const source = fs.readFileSync(file, 'utf8');
    const rel = path.relative(ROOT, file).split(path.sep).join('/');
    for (const fn of topLevelFunctions(source)) {
        const params = authorizerParams(fn.header);
        if (params.length === 0) continue;
        // The unit's own name and parameter list. The name used to be read off
        // `function x(` alone, so a `const` arrow or a class method could declare
        // the parameter, be handed a no-op by every caller, and still read as
        // authorized; and the position came from splitting the header at every
        // comma, which a `Map<K, V>` parameter ahead of it would have shifted.
        const { name } = fn;
        const argIndex = fn.params.indexOf(params[0]);
        if (argIndex < 0) continue;
        // A member is called through an object: `this.name(`, `client.name(`.
        const literal = name.replace(/[$[\]().*+?^{}|\\]/g, '\\$&');
        const callee = fn.member ? `(?:[\\w$]+\\s*\\.\\s*)?${literal}` : literal;
        for (const callFile of files) {
            const callSource = fs.readFileSync(callFile, 'utf8');
            const callRel = path.relative(ROOT, callFile).split(path.sep).join('/');
            if (!declaresIn.has(callFile)) declaresIn.set(callFile, declarationHeads(callSource));
            const declares = declaresIn.get(callFile);
            const callRe = new RegExp(`(?<![.\\w])${callee}\\s*\\(`, 'g');
            let cm;
            while ((cm = callRe.exec(maskCommentsAndStrings(callSource))) !== null) {
                if (/(?:function|import)\s+$/.test(callSource.slice(Math.max(0, cm.index - 30), cm.index))) continue;
                if (declares(cm.index)) continue;
                const arg = argumentAt(callSource, cm.index + cm[0].length - 1, argIndex);
                if (arg === null || arg === undefined) continue;
                if (!String(arg).includes(`${AUTHORIZER}(`)) {
                    const key = `${callRel}:${callSource.slice(0, cm.index).split('\n').length}`;
                    if (!injectedSeen.has(key)) {
                        injectedSeen.add(key);
                        injectedCallSiteFailures.push(
                            `${key}: ${name}() requires an egress authorizer but this call passes ${JSON.stringify(String(arg).slice(0, 60))}`);
                    }
                }
            }
        }
    }
}

// A sink NAME must actually be found for the gate to mean anything: this repo
// really does make outbound requests (#124 -- this signature's own SINKS list
// once matched none of them, printing an unconditional OK having examined zero
// real call sites). Zero sinks despite files existing under src/ is treated the
// same as zero files: a silent pass no one can trust.
const vacuous = files.length > 0 && unique.length === 0;

const failures = unique.filter(f => f.verdict === 'UNAUTHORIZED' || f.verdict === 'TEXTUAL-ONLY').length
    + suspects.length + injectedCallSiteFailures.length + (vacuous ? 1 : 0);

if (JSON_OUTPUT) {
    console.log(JSON.stringify({ root: ROOT, sites: unique, suspects: [...suspects, ...injectedCallSiteFailures], failures }, null, 2));
    process.exit(failures > 0 ? 1 : 0);
}

console.log(`egress-authorization signature — ${path.basename(ROOT)} (${files.length} src file(s), ${unique.length} sink(s))\n`);
for (const verdict of order) {
    const rows = unique.filter(f => f.verdict === verdict).sort((a, b) => a.rel.localeCompare(b.rel) || a.line - b.line);
    if (rows.length === 0) continue;
    console.log(`${verdict} (${rows.length}):`);
    for (const r of rows) console.log(`  ${r.rel}:${r.line}  ${r.fn}() -> ${r.sink}(${r.expr})`);
    console.log('');
}
if (suspects.length) {
    console.log(`SUSPECT-TEXTUAL-BLOCKLIST (${suspects.length}):`);
    for (const s of suspects) console.log(`  ${s}`);
    console.log('');
}
if (injectedCallSiteFailures.length) {
    console.log(`INJECTED-AUTHORIZER-NOT-SUPPLIED (${injectedCallSiteFailures.length}):`);
    for (const s of injectedCallSiteFailures) console.log(`  ${s}`);
    console.log('');
}

if (vacuous) {
    console.error(`FAIL: 0 sink(s) matched across ${files.length} src file(s) — this signature would pass vacuously.`);
    console.error('      Either this repo genuinely makes no outbound network calls (extend SINKS to cover its real transport');
    console.error('      function names if it does), or the SINKS list no longer names any function this repo actually calls.');
}

if (failures > 0) {
    console.error(`FAIL: ${failures} residual instance(s) of the egress-authorization class.`);
    console.error(`      Route the destination host through ${AUTHORIZER}() — the same call for the initial URL and for every redirect hop.`);
    process.exit(1);
}
console.log('OK: every dynamic-destination egress site is authorized through assertEgressHostAllowed.');
