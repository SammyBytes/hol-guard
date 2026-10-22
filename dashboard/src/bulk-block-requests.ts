import { buildDecisionPayload } from "./approval-scopes";
import type { GuardApprovalRequest, GuardApprovalResolutionInput, GuardQueueResolutionResult } from "./guard-types";
import type { QueueGroup } from "./queue-state";

/** Requests, counting each group's duplicates, so totals match what was confirmed. */
export type BulkBlockOutcome = { blocked: number; failed: number; reasons: string[] };

const MAX_REASONS = 3;

/**
 * Refuse each selected request just this once, the same way "Keep blocked"
 * does, one at a time. Guard keeps a one-time block for 15 minutes so the
 * agent's identical retry is refused too, and saves no lasting rule.
 *
 * The server settles the duplicates it can match with the request it
 * resolves and reports them; any other request in the group is blocked on
 * its own. A request that cannot be blocked just this once is reported, never
 * blocked under a wider remembered scope.
 */
export async function blockRequestsOnce(
  groups: readonly QueueGroup[],
  lookup: (requestId: string) => GuardApprovalRequest | undefined,
  resolve: (input: GuardApprovalResolutionInput) => Promise<GuardQueueResolutionResult>,
): Promise<BulkBlockOutcome> {
  const outcome: BulkBlockOutcome = { blocked: 0, failed: 0, reasons: [] };
  const fail = (count: number, error: unknown) => {
    outcome.failed += count;
    const reason = error instanceof Error ? error.message : String(error);
    if (outcome.reasons.length < MAX_REASONS && !outcome.reasons.includes(reason)) {
      outcome.reasons.push(reason);
    }
  };
  const blockOnce = async (item: GuardApprovalRequest) => {
    const payload = buildDecisionPayload({ item, action: "block", scope: "artifact", reason: "blocked in bulk review" });
    if (payload.scope !== "artifact") {
      throw new Error("A request could not be blocked just this once. Open it to choose how to block it.");
    }
    return resolve(payload);
  };
  for (const group of groups) {
    let settled: ReadonlySet<string>;
    try {
      const result = await blockOnce(group.primary);
      settled = new Set(result.resolved_duplicate_ids);
      outcome.blocked += 1;
    } catch (error) {
      fail(1 + group.duplicateCount, error);
      continue;
    }
    for (const duplicateId of group.duplicateIds) {
      if (settled.has(duplicateId)) {
        outcome.blocked += 1;
        continue;
      }
      const duplicate = lookup(duplicateId);
      try {
        if (duplicate === undefined) throw new Error("A selected request is no longer in the queue.");
        await blockOnce(duplicate);
        outcome.blocked += 1;
      } catch (error) {
        fail(1, error);
      }
    }
  }
  return outcome;
}

export function bulkBlockSummary(outcome: BulkBlockOutcome): string {
  const unit = outcome.blocked === 1 ? "request" : "requests";
  return `${outcome.blocked} ${unit} blocked.`;
}

export function bulkBlockFailureMessage(outcome: BulkBlockOutcome): string {
  const reason = outcome.reasons.length > 0 ? ` ${outcome.reasons.join(" ")}` : "";
  if (outcome.blocked === 0) {
    return `Guard could not block the selected requests. Open them to block them one at a time.${reason}`;
  }
  return `${outcome.blocked} blocked, ${outcome.failed} failed. Open the failed requests to block them one at a time.${reason}`;
}
