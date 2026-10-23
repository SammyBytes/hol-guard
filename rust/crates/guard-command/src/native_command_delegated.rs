//! Tightening-only native control gates for delegated package and MCP surfaces.
//! These gates do not replace advisory scans or approve an unknown invocation.

use super::*;
use guard_contracts::{NativeCommandPermissionObservationV1, NativeMatcherEvidenceV1};

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

fn inspection_only(arguments: &[String]) -> bool {
    matches!(arguments, [only] if matches!(only.as_str(), "--version" | "--help" | "-h"))
}

/// The goals and options a build tool reads the same way whichever spelling of
/// its launcher starts it.
struct BuildGoals {
    /// Goals that build or test the checkout the command already runs in.
    local: &'static [&'static str],
    /// Options that take their value as the next word, so that value is not
    /// mistaken for a goal.
    value_options: &'static [&'static str],
    /// Whether a goal may carry a `:`-separated project path, as Gradle's
    /// `:app:test` does. Maven spells a plugin goal that way instead, and a
    /// plugin goal is exactly the dependency work this gate keeps.
    qualified_goals: bool,
}

/// Maven lifecycle phases that compile or test what the checkout holds. The
/// phases that publish an artifact (`install`, `deploy`) are left out, as is
/// every plugin goal, so `mvn dependency:copy-dependencies` keeps its review.
static MAVEN_GOALS: BuildGoals = BuildGoals {
    local: &[
        "clean",
        "compile",
        "package",
        "test",
        "test-compile",
        "validate",
        "verify",
    ],
    value_options: &[
        "--activate-profiles",
        "--file",
        "--projects",
        "--settings",
        "--threads",
        "-f",
        "-p",
        "-pl",
        "-s",
        "-t",
    ],
    qualified_goals: false,
};

/// The Gradle tasks with that property. Gradle task names are project-defined,
/// so a task this does not name keeps the review rather than being guessed at.
static GRADLE_GOALS: BuildGoals = BuildGoals {
    local: &[
        "assemble",
        "build",
        "check",
        "classes",
        "clean",
        "compilejava",
        "compilekotlin",
        "compiletestjava",
        "compiletestkotlin",
        "jar",
        "javadoc",
        "test",
        "testclasses",
    ],
    value_options: &[
        "--build-file",
        "--console",
        "--gradle-user-home",
        "--max-workers",
        "--project-dir",
        "--settings-file",
        "-b",
        "-c",
        "-g",
    ],
    qualified_goals: true,
};

/// Options that name dependency work whatever goal carries them.
const DEPENDENCY_OPTIONS: &[&str] = &[
    "--dependency",
    "--refresh-dependencies",
    "--update-locks",
    "--write-locks",
    "-dartifact",
    "-ddepversion",
    "-dincludes",
];

fn build_goals(executable: &str) -> Option<&'static BuildGoals> {
    let executable = executable.to_ascii_lowercase();
    let executable = executable
        .strip_suffix(".cmd")
        .or_else(|| executable.strip_suffix(".bat"))
        .unwrap_or(&executable);
    match executable {
        "mvn" | "mvnw" => Some(&MAVEN_GOALS),
        "gradle" | "gradlew" => Some(&GRADLE_GOALS),
        _ => None,
    }
}

/// Whether a Maven or Gradle line only builds or tests the checkout it runs in.
/// Those goals read the dependency cache the project already holds, so the
/// workspace sandbox — which has no network at all — bounds them more tightly
/// than a review prompt does. The package firewall owns the operations that
/// fetch or publish artifacts, and every line this does not recognise, so an
/// unknown goal or option keeps the review floor.
fn local_build_work(executable: &str, arguments: &[String]) -> bool {
    let Some(goals) = build_goals(executable) else {
        return false;
    };
    let mut named_a_goal = false;
    let mut skip_value = false;
    for argument in arguments {
        if skip_value {
            skip_value = false;
            continue;
        }
        let lowered = argument.to_ascii_lowercase();
        if lowered.starts_with('-') {
            let name = lowered.split('=').next().unwrap_or(lowered.as_str());
            if DEPENDENCY_OPTIONS.contains(&name) {
                return false;
            }
            skip_value = goals.value_options.contains(&name) && !lowered.contains('=');
            continue;
        }
        let goal = if goals.qualified_goals {
            lowered.rsplit(':').next().unwrap_or(lowered.as_str())
        } else {
            lowered.as_str()
        };
        if !goals.local.contains(&goal) {
            return false;
        }
        named_a_goal = true;
    }
    // A bare launcher prints usage or runs the project's default task; neither
    // is a goal this gate has read, so it keeps the review.
    named_a_goal && !skip_value
}

pub(crate) fn normalized_tool(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', "-")
}

impl CompiledNativeCommandControls {
    pub(super) fn delegated_observations(
        &self,
        command: Option<&CanonicalCommandV1>,
        tool: Option<&str>,
        packages: &[String],
        batch: &mut NativeCommandObservationBatchV1,
        deadline: Option<Instant>,
    ) -> Result<&'static str, &'static str> {
        let mut floor = "allow";
        for &index in self.candidate_index.extension_indices() {
            let extension = &self.program.extensions[index];
            if deadline.is_some_and(|limit| Instant::now() >= limit) {
                return Err("native_command_deadline_exceeded");
            }
            if !self.active_extensions.contains(&extension.extension_id) {
                continue;
            }
            if extension.delegated_protection.as_deref() == Some("package-firewall") {
                let Some(command) = command else { continue };
                let evidence: Vec<_> = command
                    .segments
                    .iter()
                    .enumerate()
                    .filter_map(|(index, segment)| {
                        let executable = basename(segment.executable.as_deref()?);
                        if !extension
                            .executables
                            .iter()
                            .any(|value| value.eq_ignore_ascii_case(executable))
                            || inspection_only(&segment.arguments)
                            || local_build_work(executable, &segment.arguments)
                        {
                            return None;
                        }
                        Some(NativeMatcherEvidenceV1 {
                            segment_index: index,
                            // Use the catalog basename, never an input path.
                            executable: extension
                                .executables
                                .iter()
                                .find(|value| value.eq_ignore_ascii_case(executable))
                                .cloned(),
                            detail: "Matched bounded structured command constraints.".into(),
                        })
                    })
                    .collect();
                if evidence.is_empty() {
                    continue;
                }
                for permission in &extension.permissions {
                    if batch.observations.len() + batch.permission_observations.len()
                        >= guard_contracts::MAX_NATIVE_COMMAND_OBSERVATIONS
                    {
                        return Err("native_command_evidence_limit_exceeded");
                    }
                    batch
                        .permission_observations
                        .push(NativeCommandPermissionObservationV1 {
                            mcp_tool: None,
                            extension_id: extension.extension_id.clone(),
                            permission_id: permission.permission_id.clone(),
                            matcher_evidence: evidence.clone(),
                            uncertainty_reasons: Vec::new(),
                        });
                }
            }
            if let (Some(mcp), Some(tool)) = (&extension.mcp, tool) {
                // A package identity or exact conventional server namespace can
                // select a stronger floor, but never supplies allow authority.
                let alias = extension
                    .extension_id
                    .strip_prefix("command.mcp-")
                    .unwrap_or("");
                let prefix = format!("mcp__{alias}__");
                let lower = tool.to_ascii_lowercase();
                let named = lower.strip_prefix(&prefix);
                let package_match = mcp.mcp_launch.package.as_deref().is_some_and(|expected| {
                    packages
                        .iter()
                        .any(|package| package.eq_ignore_ascii_case(expected))
                });
                let remote_named = mcp.mcp_launch.kind == "remote-http"
                    && mcp.mcp_launch.server_names.iter().any(|server| {
                        let prefix = format!("mcp__{}__", server.to_ascii_lowercase());
                        lower.starts_with(&prefix)
                    });
                if named.is_none() && !package_match && !remote_named {
                    continue;
                }
                let name = named.unwrap_or_else(|| lower.rsplit("__").next().unwrap_or(&lower));
                let wanted = normalized_tool(name);
                let selected = mcp
                    .mcp_tools
                    .iter()
                    .find(|entry| normalized_tool(&entry.name) == wanted)
                    .or_else(|| mcp.mcp_tools.iter().find(|entry| entry.name == "other"));
                let Some(selected) = selected else {
                    continue;
                };
                floor = match selected.state.as_str() {
                    "block" => "block",
                    "review" if floor != "block" => "review",
                    _ => floor,
                };
                for permission in &extension.permissions {
                    if batch.observations.len() + batch.permission_observations.len()
                        >= guard_contracts::MAX_NATIVE_COMMAND_OBSERVATIONS
                    {
                        return Err("native_command_evidence_limit_exceeded");
                    }
                    batch
                        .permission_observations
                        .push(NativeCommandPermissionObservationV1 {
                            // No synthetic shell segment is invented for a tool call.
                            mcp_tool: Some(selected.name.clone()),
                            extension_id: extension.extension_id.clone(),
                            permission_id: permission.permission_id.clone(),
                            matcher_evidence: Vec::new(),
                            uncertainty_reasons: Vec::new(),
                        });
                }
            }
        }
        let count = batch.observations.len() + batch.permission_observations.len();
        let evidence = batch
            .permission_observations
            .iter()
            .map(|item| item.matcher_evidence.len())
            .sum::<usize>()
            + batch
                .observations
                .iter()
                .map(|item| {
                    item.matcher_evidence.len()
                        + item
                            .safe_variants
                            .iter()
                            .map(|safe| safe.matcher_evidence.len())
                            .sum::<usize>()
                })
                .sum::<usize>();
        if count > guard_contracts::MAX_NATIVE_COMMAND_OBSERVATIONS
            || evidence > guard_contracts::MAX_NATIVE_COMMAND_EVIDENCE_ITEMS
        {
            return Err("native_command_evidence_limit_exceeded");
        }
        Ok(floor)
    }
}
