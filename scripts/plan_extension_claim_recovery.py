"""Plan missed claim invitations without depending on artifact compilation."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys
from pathlib import Path

from extension_claim_github_history import SnapshotClaimHistory
from extension_claim_provenance import ClaimProvenanceError, resolve_initial_contribution
from notify_merged_extension_claimants import GitHubApi, accepted_github_ids, contribution_paths
from reconcile_extension_claim_notices import pending_entries


def external_sources(root: Path) -> dict[str, list[str]]:
    result = {}
    for directory in ("command-sources", "extensions", "mcp-servers"):
        for path in sorted((root / "contributions" / directory).glob("*.json")):
            identity = path.stem
            runtime_id = f"command.mcp-{identity[4:]}" if identity.startswith("mcp.") else identity
            binding = root / "contracts/extensions/trust" / f"{runtime_id}.v1.json"
            if not binding.exists() or json.loads(binding.read_text()) != {
                "schemaVersion": "guard.extension-trust-binding.v1",
                "extension": runtime_id,
                "trustClass": "external",
            }:
                continue
            result[identity] = [name for name in contribution_paths(identity) if (root / name).is_file()]
    return result


def invitation_entries(history, root: Path, sources: dict[str, list[str]], sha: str) -> list[dict]:
    rows = []
    for identity, paths in sorted(sources.items()):
        listing_path = root / "contributions/extension-listings" / f"{identity}.json"
        listing = json.loads(listing_path.read_text()) if listing_path.exists() else None
        ids = accepted_github_ids(listing, identity) if listing is not None else ()
        if listing is not None and listing.get("maintainerGithubIds") == []:
            continue
        try:
            owner = resolve_initial_contribution(history, paths, sha)
        except ClaimProvenanceError as error:
            print(f"{identity}: recovery needs provenance review: {error}", file=sys.stderr)
            continue
        if listing is not None and "maintainerGithubIds" in listing and owner.github_id not in ids:
            continue
        rows.append({"extensionId": identity, "githubId": owner.github_id, "pullRequest": owner.pull_request})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    shallow = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--is-shallow-repository"],
        text=True,
    ).strip()
    if shallow != "false":
        raise ClaimProvenanceError("Claim recovery requires complete source history")
    sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    client = GitHubApi(os.environ.get("GH_TOKEN", ""), "hashgraph-online/hol-guard", source_root=root)
    # Keep stdout a single matrix JSON value; provenance diagnostics go to stderr.
    with contextlib.redirect_stdout(sys.stderr):
        sources = external_sources(root)
        history = SnapshotClaimHistory(client, [path for paths in sources.values() for path in paths], sha)
        rows = invitation_entries(history, root, sources, sha)
        pending = pending_entries(client, rows, sorted({row["pullRequest"] for row in rows}))
    print(json.dumps(pending))


if __name__ == "__main__":
    main()
