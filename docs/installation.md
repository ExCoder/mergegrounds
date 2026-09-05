# Install, update, and uninstall

The complete repository is the plugin unit. Do not copy only the skill directory:
the skill depends on the sibling policy runner, schemas, workflows, and reference
material.

## Install from a reviewed local checkout

Inspect the checkout and preview the exact lifecycle commands:

```bash
python3 -I scripts/manage_plugin.py --dry-run install --source .
python3 -I scripts/manage_plugin.py install --source .
```

Start a new Codex task after installation so plugin discovery uses the installed
copy.

## Install from a public Git tag

Use the immutable reviewed `v1.0.0` release tag rather than a moving branch.
The canonical repository and tag are the lifecycle helper defaults:

```bash
python3 -I scripts/manage_plugin.py --dry-run install
python3 -I scripts/manage_plugin.py install
```

These commands register `https://github.com/ExCoder/mergegrounds` at
`v1.0.0`, then install `mergegrounds@mergegrounds`. To review a different
immutable release, pass both `--source` and `--ref` explicitly.

Before installing, compare the release archive against `SHA256SUMS`, inspect
`release-manifest.json`, and verify the Git tag/release signature through the
project's published verification policy. A checksum downloaded from the same
untrusted channel detects corruption but is not an independent signature.

## Update

For a registered Git marketplace, refresh its snapshot and reinstall the plugin:

```bash
python3 -I scripts/manage_plugin.py --dry-run update
python3 -I scripts/manage_plugin.py update
```

Review release notes and digest/signature evidence before updating. Local
marketplaces read the checkout directly; update that checkout through your normal
verified Git workflow, then reinstall.

## Uninstall

Remove both the installed plugin and its marketplace registration:

```bash
python3 -I scripts/manage_plugin.py --dry-run uninstall
python3 -I scripts/manage_plugin.py uninstall
```

Keep the marketplace registration when other plugins from the same catalog still
need it:

```bash
python3 -I scripts/manage_plugin.py uninstall --keep-marketplace
```

Uninstalling the Codex plugin does not remove MergeGrounds controls previously copied
into application repositories. Remove or migrate those controls only through that
repository's trusted R4 governance process.
