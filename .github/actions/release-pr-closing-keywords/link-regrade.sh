#!/usr/bin/env bash
# The scheduled re-grade: walks EVERY open pull request against `main`,
# re-grades the release ones against the live link graph, and republishes the
# verdict as the commit status branch protection actually reads.
#
# WHY THIS IS A FILE AND NOT A run: BLOCK. The first version lived inline in the
# workflow, in the repository this was ported from, and its 74-case suite could
# only PARSE it. Four
# mutations of the inline step -- per_page=100 -> per_page=1, deleting the
# count floor, base=main -> base=develop, and skipping release pull requests
# outright -- all ran inert against that suite, because no test ever EXECUTED
# the step. Extracted here, the suite runs this exact file against a stub `gh`
# it controls and asserts outcomes; all four mutations now fail tests. See
# link-regrade.test.mjs.
#
# THE PAGINATION HOLE THIS VERSION CLOSES. The inline step read
#   gh api "repos/$REPO/pulls?state=open&base=main&per_page=100"
# with NO --paginate, twice, and called the two reads "independent
# derivations". They were two jq filters over the SAME single page: with more
# than 100 open pull requests the release pull request fell off the one page
# BOTH filters saw, the considered-vs-open_count floor could never fire, and
# the tick reported clean. Proven with a stub serving 150 pulls:
# "enumerated: 100 open pull request(s), 0 release, 0 failing", exit 0.
#
# Now the two derivations genuinely differ:
#   * `rows` walks the REST listing WITH --paginate, so every page arrives and
#     the walk's reach is the whole universe, not a prefix of it;
#   * `open_count` is the GraphQL totalCount for the same universe -- a
#     different API answering with a server-side count instead of a page walk.
# A dropped page, a truncated walk or a broken projection now DISAGREES with
# the server's count, and the floor at the bottom fails the job instead of
# passing over a prefix.
#
# Environment contract (the composite action supplies all six). NOTHING here is
# defaulted to a repository-specific value: this script is shared, and a default
# that happened to be right in one repository is a silent no-op in the next.
#   GH_TOKEN                token for gh
#   REPO                    owner/name
#   CONTEXT                 the commit-status context to publish under
#   RUN_URL                 target_url for the posted statuses
#   BASE_BRANCH             the branch releases target
#   RELEASE_BRANCH_PREFIX   the head-branch prefix release-please creates
set -euo pipefail

: "${REPO:?REPO (owner/name) must be set}"
: "${CONTEXT:?CONTEXT (commit-status context) must be set}"
: "${RUN_URL:?RUN_URL (target url for posted statuses) must be set}"
: "${BASE_BRANCH:?BASE_BRANCH (the branch releases target) must be set}"
: "${RELEASE_BRANCH_PREFIX:?RELEASE_BRANCH_PREFIX must be set}"

# verify.mjs lives beside this script; resolve it from here, not from the
# caller's working directory, so the harness can run this file from anywhere.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

# Derivation ONE: the server-side count. `baseRefName` was a LITERAL "main" here
# and in the REST filter below, deliberately duplicated so that a drift between
# the two would make them disagree and fire the floor. Sharing this script across
# repositories replaces that with something better: both now read ONE
# `$BASE_BRANCH`, so they cannot drift apart at all, and the floor keeps the job
# it is actually load-bearing for -- catching a dropped page or a broken
# projection. Detecting a mismatch is worth less than making it impossible.
open_count="$(gh api graphql \
  -f query='query($owner:String!,$repo:String!,$base:String!){repository(owner:$owner,name:$repo){pullRequests(states:OPEN,baseRefName:$base){totalCount}}}' \
  -f owner="${REPO%%/*}" -f repo="${REPO#*/}" -f base="$BASE_BRANCH" \
  --jq '.data.repository.pullRequests.totalCount')"
case "$open_count" in
  '' | *[!0-9]*)
    echo "GraphQL returned no usable open-pull-request count: '$open_count'." >&2
    echo "Without the independent count the floor below cannot fire, and a blind floor" >&2
    echo "reports exactly like a clean one. Refusing to run." >&2
    exit 1
    ;;
esac

# Derivation TWO: the paginated walk. --paginate follows every page; the jq
# projection runs per page and the rows concatenate.
rows="$(gh api --paginate "repos/$REPO/pulls?state=open&base=$BASE_BRANCH&per_page=100" \
          --jq '.[] | [.number, .head.sha, .head.ref] | @tsv')"

# Re-posting an unchanged verdict every tick would burn GitHub's limit of 1000
# statuses per SHA per context: at a 5-minute tick that is reached in about
# three and a half days, and a pull request open longer than that would stop
# being gradeable at all. So the verdict is only POSTED when it differs from
# the one already on the SHA.
#
# The combined-status read is paginated too -- the endpoint pages its
# `statuses` array, and a context past the page boundary would read as absent
# and be re-posted every tick. jq -s gathers ALL pages before `first(...)`
# looks, and jq reads its whole input, so a closed pipe cannot truncate the
# answer the way a pipe into `head` can.
post_if_changed() {
  _sha="$1"; _state="$2"; _desc="$3"
  _now="$(gh api --paginate "repos/$REPO/commits/$_sha/status?per_page=100" \
            | jq -r -s --arg c "$CONTEXT" '[.[].statuses[]] | first(.[] | select(.context==$c) | .state) // ""')"
  if [ "$_now" = "$_state" ]; then
    echo "    unchanged ($_state), not re-posted"
    return 0
  fi
  gh api -X POST "repos/$REPO/statuses/$_sha" \
    -f state="$_state" -f context="$CONTEXT" -f description="$_desc" \
    -f target_url="$RUN_URL" > /dev/null
  echo "    posted $CONTEXT=$_state"
}

considered=0
release=0
failing=0
while IFS="$(printf '\t')" read -r num sha ref; do
  [ -n "$num" ] || continue
  considered=$((considered + 1))
  case "$ref" in
    "$RELEASE_BRANCH_PREFIX"*) ;;
    *)
      # Posted for NON-release pull requests too. A required context that only
      # some pull requests ever receive blocks the rest forever.
      echo "  #$num ($ref) -> not a release PR"
      post_if_changed "$sha" success "Not a release pull request."
      continue
      ;;
  esac
  release=$((release + 1))

  # Into a scratch directory, never the caller's checkout. This script now runs
  # inside consumer repositories through a composite action, and a guard that
  # litters `release-pr-body-*.md` into someone else's working tree is a guard
  # that shows up in their `git status` and their next commit.
  body_file="$scratch/release-pr-body-$num.md"
  gh api "repos/$REPO/pulls/$num" --jq '.body' > "$body_file"
  if node "$here/verify.mjs" "$body_file" "$num"; then
    state=success
    desc="Re-graded against the live link graph."
  else
    state=failure
    desc="Closes an issue this release does not complete."
    failing=$((failing + 1))
  fi
  echo "  #$num ($ref) -> $state"
  post_if_changed "$sha" "$state" "$desc"
done <<< "$rows"

echo "enumerated: $considered open pull request(s), $release release, $failing failing."
if [ "$considered" -ne "$open_count" ]; then
  echo "Walked $considered pull request(s) but the API reports $open_count open." >&2
  echo "The walk and the server-side count disagree, so a re-grade was silently skipped" >&2
  echo "or the projection dropped rows. Refusing to pass." >&2
  exit 1
fi

# A DISCOVERED VIOLATION FAILS THE JOB, not only the commit status (#38).
#
# This mode exists for the one thing the pull_request job can never see: a link
# added through the Development panel fires no webhook, so only a re-grade
# against the live graph finds it. Counting that discovery and exiting 0 put the
# entire signal in the `release-guard/link-regrade` status -- which is a required
# context in none of the twelve adopters, so the finding was made and then
# surfaced nowhere that blocks anything.
#
# THE NOISE IS THE POINT, and it was the argument for exiting 0. A scheduled run
# stays red every tick until the release pull request is fixed. That is not a
# flake: it is a live violation persisting, and a guard whose discovery expires
# quietly is the failure this whole action exists to prevent. The status is
# still posted per pull request, so which one is failing stays legible; this
# exit only makes the discovery visible without every consumer having to wire a
# required context first.
if [ "$failing" -gt 0 ]; then
  echo "$failing release pull request(s) close an issue the release does not complete." >&2
  echo "The per-PR $CONTEXT status says which. Re-run after fixing the pull request body" >&2
  echo "or the issue links; this job stays red until the violation is gone." >&2
  exit 1
fi
