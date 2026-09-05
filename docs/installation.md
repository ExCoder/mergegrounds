# Install, update, inspect, and uninstall

The complete repository is the plugin unit. Do not copy only the skill
directory: the skill depends on sibling policy runners, schemas, workflows, and
reference material. These commands require a Codex CLI version that provides
the `codex plugin` command group.

## Install the published release directly

Fresh installation must not depend on a helper that exists only inside the
repository being installed. From any directory, register the reviewed public
release ref and then install the plugin:

```bash
codex plugin marketplace add ExCoder/mergegrounds --ref v1.0.0 --json
codex plugin add mergegrounds@mergegrounds --json
```

Start a new Codex task after installation so plugin discovery uses the installed
copy. The GitHub source and `v1.0.0` ref become available only after the public
repository and release are activated. Before trusting the install, follow the
[release verification runbook](releasing.md); a version-looking ref by itself is
not proof of provenance.

## Install from a reviewed local checkout

Inspect the complete checkout first, then register its path directly:

```bash
codex plugin marketplace add . --json
codex plugin add mergegrounds@mergegrounds --json
```

After the checkout exists, the bundled helper can preview and perform the same
lifecycle:

```bash
python3 -I scripts/manage_plugin.py --dry-run install --source .
python3 -I scripts/manage_plugin.py install --source .
```

The helper also defaults fresh Git installation to the public `v1.0.0` ref:

```bash
python3 -I scripts/manage_plugin.py --dry-run install
python3 -I scripts/manage_plugin.py install
```

Use `--source` and `--ref` together to install a different reviewed Git source.
The helper accepts only a semantic release tag such as `v1.1.0` or a full
40/64-character commit ID for a Git source, and rejects `--ref` for a local
source.

## Inspect status

Inspect both installed/available plugins and configured marketplace roots:

```bash
codex plugin list --available --json
codex plugin marketplace list --json
```

From a checkout, the helper prints both machine-readable results:

```bash
python3 -I scripts/manage_plugin.py status
```

## Update a Git installation

An update is an explicit rebind, not “follow the latest branch.” Review the new
release notes, candidate checksums, and provenance first, then name the exact new
ref:

```bash
python3 -I scripts/manage_plugin.py --dry-run update --ref v1.1.0
python3 -I scripts/manage_plugin.py update --ref v1.1.0
```

Equivalently, run the four direct CLI operations:

```bash
codex plugin remove mergegrounds@mergegrounds --json
codex plugin marketplace remove mergegrounds --json
codex plugin marketplace add ExCoder/mergegrounds --ref v1.1.0 --json
codex plugin add mergegrounds@mergegrounds --json
```

The helper deliberately has no implicit Git update ref and never uses
`marketplace upgrade`: upgrading a marketplace pinned at `v1.0.0` would merely
refresh that same snapshot and could be mistaken for a version change.

## Refresh a local installation

The helper never fetches or changes a local checkout. Update the checkout using
your separately verified Git process, inspect the exact detached tag or commit,
then reinstall its current bytes:

```bash
python3 -I scripts/manage_plugin.py --dry-run update --source .
python3 -I scripts/manage_plugin.py update --source .
```

Git and local update both remove and recreate the registration before
reinstalling the plugin; the Codex CLI does not provide an atomic rebind. If the
process is interrupted, inspect status, remove whichever old plugin or
marketplace registration still exists, and repeat the applicable install
sequence at the intended source/ref. Do not silently fall back to a moving
branch.

## Uninstall

Remove both the installed plugin and marketplace registration directly:

```bash
codex plugin remove mergegrounds@mergegrounds --json
codex plugin marketplace remove mergegrounds --json
```

Or use the helper from an existing checkout:

```bash
python3 -I scripts/manage_plugin.py --dry-run uninstall
python3 -I scripts/manage_plugin.py uninstall
```

Keep the marketplace registration only when another plugin from that catalog
still needs it:

```bash
python3 -I scripts/manage_plugin.py uninstall --keep-marketplace
```

Uninstalling the Codex plugin does not remove MergeGrounds controls previously
copied into application repositories. Remove or migrate those controls only
through that repository's trusted R4 governance process.
