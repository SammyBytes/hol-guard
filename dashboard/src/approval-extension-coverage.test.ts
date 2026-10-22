import { readFileSync } from "node:fs";
import {
  coverageScopeLine,
  coverageStepLabel,
  normalizeApprovalExtensionCoverage,
} from "./approval-extension-coverage";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

const DIGEST = "c".repeat(64);

function rawSegment(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    index: 0,
    executable: "docker",
    extensions: [
      {
        extension_id: "command.container-runtime",
        name: "Container runtime protection",
        focus_rule_id: "command.container-runtime.system-prune",
      },
    ],
    rules: [
      { rule_id: "command.container-runtime.system-prune", title: "Docker system prune", severity: "high" },
    ],
    permissions: [
      {
        permission_id: "command.container-runtime.permission.system-prune",
        label: "Container system prune",
        configurable: true,
      },
    ],
    ...overrides,
  };
}

function rawCoverage(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "guard.approval-extension-coverage.v1",
    catalog_digest: DIGEST,
    segments: [rawSegment()],
    compound: false,
    ...overrides,
  };
}

async function run(): Promise<void> {
  const coverage = normalizeApprovalExtensionCoverage(rawCoverage());
  assert(coverage !== null, "a well-formed payload normalizes");
  assert(coverage!.segments.length === 1, "the single step survives");
  assert(coverage!.segments[0].extensions[0].extension_id === "command.container-runtime", "the extension is kept");

  // A compound command's steps arrive apart and stay apart, in order.
  const compound = normalizeApprovalExtensionCoverage(
    rawCoverage({
      compound: true,
      segments: [
        rawSegment({ index: 2, executable: "docker" }),
        rawSegment({
          index: 0,
          executable: "git",
          extensions: [{ extension_id: "command.git", name: "Git protection", focus_rule_id: null }],
          rules: [{ rule_id: "command.git.unverified-fetch", title: "Unverified fetch", severity: "medium" }],
          permissions: [],
        }),
      ],
    }),
  );
  assert(compound !== null, "a compound payload normalizes");
  assert(
    compound!.segments.map((segment) => segment.index).join(",") === "0,2",
    "steps are ordered by their position in the command",
  );
  assert(
    compound!.segments[0].extensions[0].extension_id === "command.git" &&
      compound!.segments[1].extensions[0].extension_id === "command.container-runtime",
    "each step keeps only the extension that matched it",
  );
  assert(compound!.segments[0].extensions[0].focus_rule_id === null, "a step with no focus rule is allowed");

  assert(
    coverageScopeLine(compound!) !== null && coverageScopeLine(compound!)!.includes("comes back for review"),
    "a compound command says the other steps still need review",
  );
  assert(coverageScopeLine(coverage!) === null, "a single-step command needs no scope line");
  assert(coverageStepLabel(compound!.segments[0]) === "Step 1 · git", "a step is labelled by position and executable");
  assert(
    coverageStepLabel({ ...compound!.segments[0], executable: null }) === "Step 1",
    "a step with no executable claims none",
  );

  // Anything that is not the payload the daemon builds drops the whole card.
  assert(normalizeApprovalExtensionCoverage(null) === null, "a missing payload is not a card");
  assert(
    normalizeApprovalExtensionCoverage(rawCoverage({ schema: "guard.approval-extension-coverage.v2" })) === null,
    "another schema is refused",
  );
  assert(normalizeApprovalExtensionCoverage(rawCoverage({ catalog_digest: "nope" })) === null, "a bad digest is refused");
  assert(normalizeApprovalExtensionCoverage(rawCoverage({ segments: [] })) === null, "an empty card is refused");
  assert(
    normalizeApprovalExtensionCoverage(rawCoverage({ segments: [rawSegment({ index: -1 })] })) === null,
    "a negative step index is refused",
  );
  assert(
    normalizeApprovalExtensionCoverage(rawCoverage({ segments: [rawSegment({ extensions: [] })] })) === null,
    "a step naming no extension is refused",
  );
  assert(
    normalizeApprovalExtensionCoverage(
      rawCoverage({ segments: [rawSegment({ extensions: [{ extension_id: "../etc/passwd", name: "x" }] })] }),
    ) === null,
    "an identifier that is not a catalog id is refused",
  );
  assert(
    normalizeApprovalExtensionCoverage(rawCoverage({ segments: [rawSegment({ executable: "docker; rm -rf /" })] })) ===
      null,
    "an executable that is not a bare basename is refused",
  );
  assert(
    normalizeApprovalExtensionCoverage(
      rawCoverage({ segments: [rawSegment({ rules: [{ rule_id: "command.x", title: "t" }] })] }),
    ) === null,
    "a rule missing its severity is refused",
  );

  const cardSource = readFileSync(new URL("./approval-extension-coverage-card.tsx", import.meta.url), "utf8");
  assert(
    !cardSource.includes("onResolve") && !cardSource.includes("buildDecisionPayload"),
    "the coverage card resolves nothing: it is advisory only",
  );
  assert(
    !cardSource.includes("extension-controls-api") && !cardSource.includes("approveWithExtensionAllow"),
    "the coverage card changes no protection setting",
  );
  assert(
    cardSource.includes("extensionPatternHref") && cardSource.includes("segment.extensions.map"),
    "every extension on every step gets its own link",
  );
  assert(cardSource.includes("coverageScopeLine"), "the card shows the compound scope line");

  const recommendationCardSource = readFileSync(
    new URL("./approval-extension-recommendation-card.tsx", import.meta.url),
    "utf8",
  );
  assert(
    recommendationCardSource.includes("configurable.map("),
    "the recommendation card links every extension it would configure, not just the first",
  );

  const decisionCardSource = readFileSync(new URL("./review-decision-card.tsx", import.meta.url), "utf8");
  assert(
    decisionCardSource.includes("ApprovalExtensionCoverageCard"),
    "the review screen renders the coverage card",
  );

  console.log("approval-extension-coverage tests passed");
}

void run().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
