#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

readonly RULESET_NAME="MergeGrounds: default branch"
readonly API_VERSION="2026-03-10"
readonly GITHUB_HOST="github.com"

apply=false
requested_repo=""
requested_branch=""
verifier_app_id=""
verifier_app_slug=""
verifier_app_owner=""

usage() {
  cat <<'USAGE'
Usage: scripts/apply-github-ruleset.sh --repo OWNER/REPOSITORY \
  --verifier-app-id ID --verifier-app-slug SLUG --verifier-app-owner OWNER \
  [--branch DEFAULT_BRANCH] [--apply]

Validates the repository, default branch, CODEOWNERS, and successful required
checks, then renders an idempotent repository ruleset. The default is dry-run:
the JSON is printed and GitHub is not changed. --apply is the only mutation path.

Authoritative checks: MergeGrounds / Admission, MergeGrounds / Independent Challenge
The two authoritative contexts must be emitted by the independently administered
GitHub App whose immutable numeric integration ID, slug, and owner are supplied
explicitly and match GitHub-owned check-run metadata. GitHub Actions is rejected.
Language-specific checks such as CodeQL are inputs to the external admission
decision, not universal ruleset contexts; the verifier must require the
project's applicable SAST evidence.
Required tools: gh, git, python3
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --repo)
      (($# >= 2)) || die "--repo requires OWNER/REPOSITORY"
      requested_repo=$2
      shift 2
      ;;
    --branch)
      (($# >= 2)) || die "--branch requires the repository default branch"
      requested_branch=$2
      shift 2
      ;;
    --verifier-app-id)
      (($# >= 2)) || die "--verifier-app-id requires a positive numeric GitHub App integration id"
      verifier_app_id=$2
      shift 2
      ;;
    --verifier-app-slug)
      (($# >= 2)) || die "--verifier-app-slug requires the external GitHub App slug"
      verifier_app_slug=$2
      shift 2
      ;;
    --verifier-app-owner)
      (($# >= 2)) || die "--verifier-app-owner requires the App owner login"
      verifier_app_owner=$2
      shift 2
      ;;
    --apply)
      apply=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "$requested_repo" ]] || die "--repo OWNER/REPOSITORY is required"
[[ "$verifier_app_id" =~ ^[1-9][0-9]{0,18}$ ]] || \
  die "--verifier-app-id is required and must be a positive numeric GitHub App integration id"
[[ "$verifier_app_slug" =~ ^[a-z0-9][a-z0-9-]{0,99}$ ]] || \
  die "--verifier-app-slug is required and must be the exact lowercase external App slug"
[[ "$verifier_app_owner" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}$ ]] || \
  die "--verifier-app-owner is required and must be the exact App owner login"
case "$verifier_app_owner" in
  [Gg][Ii][Tt][Hh][Uu][Bb])
    die "the authoritative verifier App owner must be independently administered, not GitHub"
    ;;
esac
case "$verifier_app_slug" in
  github-actions|github-code-scanning|codeql)
    die "the authoritative verifier must be an independently administered App, not $verifier_app_slug"
    ;;
esac
[[ "$requested_repo" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,38}/[A-Za-z0-9._-]{1,100}$ ]] || \
  die "invalid repository name: $requested_repo"
[[ "$requested_repo" != *".."* ]] || die "repository name must not contain '..'"

for tool in gh git python3; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done

gh auth status --hostname "$GITHUB_HOST" >/dev/null 2>&1 || \
  die "GitHub CLI is not authenticated to $GITHUB_HOST; run 'gh auth login --hostname $GITHUB_HOST' first"

ruleset_tmp_parent=${TMPDIR:-/tmp}
ruleset_tmp_dir=$(mktemp -d "${ruleset_tmp_parent%/}/mergegrounds-ruleset.XXXXXX")
trap 'rm -rf -- "$ruleset_tmp_dir"' EXIT

api() {
  gh api \
    --hostname "$GITHUB_HOST" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: ${API_VERSION}" \
    "$@"
}

repo_file="$ruleset_tmp_dir/repository.json"
api "repos/$requested_repo" >"$repo_file"

repo_fields=$(python3 -I - "$repo_file" "$requested_repo" "$requested_branch" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    repository = json.load(handle)

requested = sys.argv[2]
expected_branch = sys.argv[3]
canonical = repository.get("full_name")
default_branch = repository.get("default_branch")

if not isinstance(canonical, str) or canonical.casefold() != requested.casefold():
    raise SystemExit("GitHub returned a different repository identity")
if repository.get("archived") or repository.get("disabled"):
    raise SystemExit("archived or disabled repositories cannot be hardened")
if not isinstance(default_branch, str) or not default_branch:
    raise SystemExit("repository has no default branch; create an initial commit first")
if "\t" in canonical or "\t" in default_branch or "\n" in default_branch:
    raise SystemExit("repository metadata contains an invalid delimiter")
if expected_branch and expected_branch != default_branch:
    raise SystemExit(
        f"--branch {expected_branch!r} does not match GitHub default branch {default_branch!r}"
    )
if not repository.get("allow_squash_merge"):
    raise SystemExit("enable squash merging before applying the linear-history ruleset")

print(f"{canonical}\t{default_branch}")
PY
) || die "repository metadata validation failed"

IFS=$'\t' read -r canonical_repo default_branch <<<"$repo_fields"
[[ -n "$canonical_repo" && -n "$default_branch" ]] || die "failed to read validated repository metadata"
git check-ref-format --branch "$default_branch" >/dev/null 2>&1 || die "GitHub default branch is not a valid Git ref"

commit_file="$ruleset_tmp_dir/default-commit.json"
api "repos/$canonical_repo/commits/$default_branch" >"$commit_file"
default_sha=$(python3 -I - "$commit_file" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle).get("sha", "")
if not re.fullmatch(r"[0-9a-f]{40,64}", value):
    raise SystemExit("default branch did not resolve to a commit SHA")
print(value)
PY
) || die "default branch validation failed"

codeowners_file="$ruleset_tmp_dir/codeowners.json"
api --method GET "repos/$canonical_repo/contents/.github/CODEOWNERS" -f "ref=$default_sha" >"$codeowners_file" || \
  die ".github/CODEOWNERS must exist on the default branch"

codeowners_metadata=$(python3 -I - "$codeowners_file" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    response = json.load(handle)

if response.get("type") != "file" or "target" in response or "submodule_git_url" in response:
    raise SystemExit(".github/CODEOWNERS must be a regular Git blob")

maximum_bytes = 3 * 1024 * 1024
declared_size = response.get("size")
if type(declared_size) is not int or declared_size < 0:
    raise SystemExit("CODEOWNERS API response has an invalid size")
if declared_size >= maximum_bytes:
    raise SystemExit("CODEOWNERS must be smaller than GitHub's 3 MiB limit")

blob_sha = response.get("sha")
if not isinstance(blob_sha, str) or not re.fullmatch(r"[0-9a-f]{40,64}", blob_sha):
    raise SystemExit("CODEOWNERS API response has an invalid blob SHA")

print(f"{blob_sha}\t{declared_size}")
PY
) || die "CODEOWNERS metadata validation failed"

IFS=$'\t' read -r codeowners_blob_sha codeowners_size <<<"$codeowners_metadata"
[[ -n "$codeowners_blob_sha" && "$codeowners_size" =~ ^[0-9]+$ ]] || \
  die "failed to read validated CODEOWNERS metadata"

codeowners_blob_file="$ruleset_tmp_dir/codeowners-blob.json"
api --method GET "repos/$canonical_repo/git/blobs/$codeowners_blob_sha" >"$codeowners_blob_file" || \
  die "could not read the validated CODEOWNERS Git blob"

trusted_owners_file="$ruleset_tmp_dir/trusted-codeowners.txt"
python3 -I - "$codeowners_blob_file" "$codeowners_blob_sha" "$codeowners_size" >"$trusted_owners_file" <<'PY' || \
  die "CODEOWNERS content validation failed"
import base64
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    response = json.load(handle)
expected_sha = sys.argv[2]
expected_size = int(sys.argv[3])
if (
    response.get("sha") != expected_sha
    or response.get("encoding") != "base64"
    or response.get("size") != expected_size
):
    raise SystemExit("unexpected CODEOWNERS Git blob response")

maximum_bytes = 3 * 1024 * 1024
try:
    encoded = response["content"]
    if not isinstance(encoded, str):
        raise ValueError("content is not a string")
    decoded = base64.b64decode("".join(encoded.split()), validate=True)
    if len(decoded) != expected_size:
        raise ValueError("decoded content size does not match GitHub metadata")
    if len(decoded) >= maximum_bytes:
        raise ValueError("decoded content reaches GitHub's 3 MiB limit")
    content = decoded.decode("utf-8")
except (KeyError, ValueError, UnicodeDecodeError) as error:
    raise SystemExit(f"cannot decode CODEOWNERS: {error}") from error

if "@org/security-team" in content:
    raise SystemExit("replace every @org/security-team example with a real owner before applying")

entries = []
for raw_line in content.splitlines():
    line = raw_line.split("#", 1)[0].strip()
    if not line:
        continue
    fields = line.split()
    if len(fields) < 2:
        raise SystemExit(f"CODEOWNERS pattern {fields[0]!r} has no owner")
    entries.append((fields[0], fields[1:]))

if not entries or entries[0][0] != "*":
    raise SystemExit("the first active CODEOWNERS rule must be the repository-wide '*' owner")

protected_patterns = (
    "/.codex-plugin/",
    "/.agents/",
    "/.github/",
    "/.mergegrounds/",
    "/.gitattributes",
    "/mergegrounds-custom",
    "/scripts/",
    "/skills/mergegrounds/",
    "/SECURITY.md",
)

# GitHub applies the last matching CODEOWNERS rule. Requiring this exact suffix
# prevents an innocent-looking later glob from silently replacing security
# ownership of a workflow, policy, MergeGrounds implementation, or security policy.
suffix = entries[-len(protected_patterns):]
if tuple(pattern for pattern, _ in suffix) != protected_patterns:
    raise SystemExit(
        "the final active CODEOWNERS rules must be the protected patterns, in canonical order: "
        + ", ".join(protected_patterns)
    )

trusted_owners = entries[0][1]
if len(set(trusted_owners)) != len(trusted_owners):
    raise SystemExit("the repository-wide CODEOWNERS rule contains a duplicate owner")

owner_pattern = re.compile(
    r"^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9_-]{0,99}))?$"
)
invalid_owners = [owner for owner in trusted_owners if not owner_pattern.fullmatch(owner)]
if invalid_owners:
    raise SystemExit(
        "trusted CODEOWNERS must be verifiable GitHub users or organization teams: "
        + ", ".join(invalid_owners)
    )

for pattern, owners in suffix:
    if owners != trusted_owners:
        raise SystemExit(
            f"protected CODEOWNERS rule {pattern!r} must use the repository-wide trusted owners"
        )

sys.stdout.write("\n".join(trusted_owners) + "\n")
PY

repo_owner=${canonical_repo%%/*}
owner_index=0
while IFS= read -r trusted_owner; do
  [[ -n "$trusted_owner" ]] || continue
  owner_index=$((owner_index + 1))
  owner_permission_file="$ruleset_tmp_dir/codeowner-permission-$owner_index.json"
  owner_identity=${trusted_owner#@}

  if [[ "$owner_identity" == */* ]]; then
    owner_org=${owner_identity%%/*}
    team_slug=${owner_identity#*/}
    shopt -s nocasematch
    [[ "$owner_org" == "$repo_owner" ]] || \
      die "trusted CODEOWNERS team $trusted_owner must belong to repository owner $repo_owner"
    shopt -u nocasematch
    api --method GET "orgs/$repo_owner/teams/$team_slug/repos/$canonical_repo" >"$owner_permission_file" || \
      die "cannot verify repository access for CODEOWNERS team $trusted_owner"
  else
    api --method GET "repos/$canonical_repo/collaborators/$owner_identity/permission" >"$owner_permission_file" || \
      die "cannot verify repository access for CODEOWNERS user $trusted_owner"
  fi

  python3 -I - "$owner_permission_file" "$trusted_owner" <<'PY' || \
    die "trusted CODEOWNER does not have write access: $trusted_owner"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    response = json.load(handle)

permissions = response.get("permissions")
if not isinstance(permissions, dict):
    user = response.get("user")
    permissions = user.get("permissions") if isinstance(user, dict) else None

if not isinstance(permissions, dict) or not any(
    permissions.get(level) is True for level in ("push", "maintain", "admin")
):
    raise SystemExit(f"{sys.argv[2]} lacks push, maintain, or admin permission")
PY
done <"$trusted_owners_file"

((owner_index > 0)) || die "CODEOWNERS has no trusted owner"

codeowners_errors_file="$ruleset_tmp_dir/codeowners-errors.json"
api --method GET "repos/$canonical_repo/codeowners/errors" -f "ref=$default_sha" >"$codeowners_errors_file"
python3 -I - "$codeowners_errors_file" <<'PY' || die "GitHub rejected one or more CODEOWNERS entries"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    errors = json.load(handle).get("errors", [])
if errors:
    for error in errors:
        line = error.get("line", "?")
        message = str(error.get("message", "invalid CODEOWNERS entry")).splitlines()[0]
        print(f"CODEOWNERS line {line}: {message}", file=sys.stderr)
    raise SystemExit(1)
PY

checks_file="$ruleset_tmp_dir/check-runs.json"
api --paginate --slurp --method GET "repos/$canonical_repo/commits/$default_sha/check-runs" \
  -f "filter=latest" -f "per_page=100" >"$checks_file"

required_checks_file="$ruleset_tmp_dir/required-checks.json"
python3 -I - "$checks_file" "$verifier_app_id" "$verifier_app_slug" "$verifier_app_owner" >"$required_checks_file" <<'PY' || \
  die "run all required workflows successfully on the default branch before applying the ruleset"
import json
import sys

verifier_app_id = int(sys.argv[2])
verifier_app_slug = sys.argv[3]
verifier_app_owner = sys.argv[4]
authoritative = (
    "MergeGrounds / Admission",
    "MergeGrounds / Independent Challenge",
)
with open(sys.argv[1], encoding="utf-8") as handle:
    response = json.load(handle)
pages = response if isinstance(response, list) else [response]
if not pages or len(pages) > 1000:
    raise SystemExit("GitHub returned an invalid number of check-run pages")
runs = []
for page in pages:
    if not isinstance(page, dict) or not isinstance(page.get("check_runs"), list):
        raise SystemExit("GitHub returned an invalid check-runs page")
    if len(page["check_runs"]) > 100:
        raise SystemExit("GitHub returned an oversized check-runs page")
    runs.extend(page["check_runs"])

reserved_slugs = {"github-actions", "github-code-scanning", "codeql"}
reserved_owners = {"github"}


def app_owner(app):
    owner = app.get("owner")
    return owner.get("login") if isinstance(owner, dict) else None


def is_expected_verifier(run):
    app = run.get("app")
    return (
        isinstance(app, dict)
        and app.get("id") == verifier_app_id
        and app.get("slug") == verifier_app_slug
        and app.get("slug") not in reserved_slugs
        and isinstance(app_owner(app), str)
        and app_owner(app).casefold() == verifier_app_owner.casefold()
        and app_owner(app).casefold() not in reserved_owners
    )


reserved_ids = {
    app.get("id")
    for run in runs
    for app in (run.get("app"),)
    if isinstance(app, dict)
    and app.get("slug") in reserved_slugs
    and isinstance(app.get("id"), int)
}
if verifier_app_id in reserved_ids:
    raise SystemExit(
        "authoritative verifier integration id belongs to GitHub Actions/code scanning"
    )

resolved = []
problems = []
for context in authoritative:
    candidates = [run for run in runs if run.get("name") == context]
    trusted = [run for run in candidates if is_expected_verifier(run)]
    successful = [
        run for run in trusted
        if run.get("status") == "completed" and run.get("conclusion") == "success"
    ]
    if not successful:
        observed = ", ".join(
            sorted({f"{run.get('status')}/{run.get('conclusion')}" for run in trusted})
        ) or (
            "not observed from verifier app "
            f"{verifier_app_owner}/{verifier_app_slug} id {verifier_app_id}"
        )
        problems.append(f"{context}: {observed}")
        continue
    successful.sort(key=lambda run: run.get("completed_at") or "", reverse=True)
    resolved.append({"context": context, "integration_id": verifier_app_id})

if problems:
    print("required checks are not ready:\n  " + "\n  ".join(problems), file=sys.stderr)
    raise SystemExit(1)
json.dump(resolved, sys.stdout, separators=(",", ":"))
PY

payload_file="$ruleset_tmp_dir/ruleset.json"
python3 -I - "$required_checks_file" "$RULESET_NAME" >"$payload_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    required_checks = json.load(handle)

payload = {
    "name": sys.argv[2],
    "target": "branch",
    "enforcement": "active",
    "bypass_actors": [],
    "conditions": {
        "ref_name": {
            "include": ["~DEFAULT_BRANCH"],
            "exclude": [],
        }
    },
    "rules": [
        {"type": "deletion"},
        {"type": "non_fast_forward"},
        {"type": "required_linear_history"},
        {"type": "required_signatures"},
        {
            "type": "pull_request",
            "parameters": {
                "allowed_merge_methods": ["squash"],
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": True,
                "require_last_push_approval": True,
                "required_approving_review_count": 2,
                "required_review_thread_resolution": True,
            },
        },
        {
            "type": "required_status_checks",
            "parameters": {
                "do_not_enforce_on_create": False,
                "required_status_checks": required_checks,
                "strict_required_status_checks_policy": True,
            },
        },
    ],
}
json.dump(payload, sys.stdout, indent=2, sort_keys=True)
sys.stdout.write("\n")
PY

rulesets_file="$ruleset_tmp_dir/existing-rulesets.json"
api --paginate --slurp --method GET "repos/$canonical_repo/rulesets" \
  -f "includes_parents=false" -f "per_page=100" >"$rulesets_file"
existing_id=$(python3 -I - "$rulesets_file" "$RULESET_NAME" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    response = json.load(handle)
if not isinstance(response, list) or len(response) > 1000:
    raise SystemExit("GitHub returned an invalid ruleset page collection")
if not response:
    pages = []
elif all(isinstance(item, dict) for item in response):
    # Backward-compatible input shape for fixtures and older gh clients.
    pages = [response]
elif all(isinstance(page, list) for page in response):
    pages = response
else:
    raise SystemExit("GitHub returned mixed or invalid ruleset pages")
rulesets = []
for page in pages:
    if len(page) > 100 or not all(isinstance(item, dict) for item in page):
        raise SystemExit("GitHub returned an invalid or oversized ruleset page")
    rulesets.extend(page)
matches = [
    ruleset for ruleset in rulesets
    if ruleset.get("name") == sys.argv[2] and ruleset.get("source_type") == "Repository"
]
if len(matches) > 1:
    raise SystemExit("multiple repository rulesets have the managed name")
print(matches[0]["id"] if matches else "")
PY
) || die "could not determine existing managed ruleset"

if [[ -n "$existing_id" && ! "$existing_id" =~ ^[0-9]+$ ]]; then
  die "GitHub returned an invalid ruleset id"
fi

operation="create"
[[ -z "$existing_id" ]] || operation="update ruleset $existing_id"

if [[ "$apply" != true ]]; then
  printf 'Dry run: validated %s at %s (%s). Would %s.\n' \
    "$canonical_repo" "$default_branch" "$default_sha" "$operation" >&2
  printf 'No GitHub settings were changed. Re-run with --apply after reviewing this payload.\n' >&2
  cat "$payload_file"
  exit 0
fi

response_file="$ruleset_tmp_dir/applied-ruleset.json"

# Narrow the bootstrap race: all content and check validation above is bound to
# default_sha. Refuse to mutate if the default branch moved while the preview was
# being assembled. A temporary independently administered protection rule is
# still required during first-time bootstrap because GitHub offers no atomic
# "validate this SHA and create a ruleset" endpoint.
current_commit_file="$ruleset_tmp_dir/current-default-commit.json"
api "repos/$canonical_repo/commits/$default_branch" >"$current_commit_file"
python3 -I - "$current_commit_file" "$default_sha" <<'PY' || \
  die "default branch moved during validation; rerun the helper against the new head"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    current = json.load(handle).get("sha")
if current != sys.argv[2]:
    raise SystemExit(f"expected {sys.argv[2]}, found {current!r}")
PY

if [[ -n "$existing_id" ]]; then
  api --method PUT "repos/$canonical_repo/rulesets/$existing_id" --input "$payload_file" >"$response_file"
else
  api --method POST "repos/$canonical_repo/rulesets" --input "$payload_file" >"$response_file"
fi

python3 -I - "$response_file" "$payload_file" <<'PY' || die "post-apply ruleset verification failed"
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    ruleset = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    expected = json.load(handle)

for field in ("name", "target", "enforcement", "bypass_actors", "conditions"):
    if ruleset.get(field) != expected[field]:
        raise SystemExit(f"GitHub returned an unexpected {field!r} value")

actual_rules = ruleset.get("rules")
expected_rules = expected["rules"]
if not isinstance(actual_rules, list):
    raise SystemExit("GitHub returned an invalid rules list")
if len(actual_rules) != len(expected_rules):
    raise SystemExit("GitHub returned an unexpected number of rules")

def index_rules(values):
    indexed = {}
    for rule in values:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            raise SystemExit("GitHub returned an invalid rule")
        rule_type = rule["type"]
        if rule_type in indexed:
            raise SystemExit(f"GitHub returned duplicate rule type {rule_type!r}")
        indexed[rule_type] = rule
    return indexed

actual_by_type = index_rules(actual_rules)
expected_by_type = index_rules(expected_rules)
if actual_by_type.keys() != expected_by_type.keys():
    raise SystemExit("GitHub returned a different rule type set")
for rule_type, expected_rule in expected_by_type.items():
    actual_rule = actual_by_type[rule_type]
    if actual_rule.get("parameters") != expected_rule.get("parameters"):
        raise SystemExit(f"GitHub returned unexpected parameters for {rule_type!r}")
print(ruleset.get("_links", {}).get("html", {}).get("href", "ruleset applied"))
PY
