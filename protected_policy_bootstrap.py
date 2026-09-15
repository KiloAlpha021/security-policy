"""Pre-environment identity and baseline-transition decisions.

Until this file is merged and proved from protected main, it is candidate proposal
evidence only.  It cannot authorize its own landing.  Owner authorization and a
post-merge protected proof are required for the first landing.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


REPOSITORY = "KiloAlpha021/security-policy"
DOWNSTREAM_REPOSITORY = "KiloAlpha021/security-workflows"
CURRENT_BASELINE = "SECURITY-POLICY-BASELINE-1"
IMMEDIATE_SUCCESSOR = "SECURITY-POLICY-BASELINE-2"
TRANSITION_PROTECTED_BASE = "76a811e76edbefc76ab1baf20795e2755f5bb794"
OWNER_AUTHORIZATION = "REQUIRED"
POST_MERGE_PROOF = "REQUIRED"

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_BASELINE = re.compile(r"SECURITY-POLICY-BASELINE-([1-9][0-9]*)\Z")


class BootstrapError(ValueError):
    """An invalid or ambiguous bootstrap state."""


class EvaluationContext(str, Enum):
    SELF_PR_BOOTSTRAP = "SELF_PR_BOOTSTRAP"
    STAGE_A_PROTECTED_PROOF = "STAGE_A_PROTECTED_PROOF"
    DOWNSTREAM_SECURITY_WORKFLOWS = "DOWNSTREAM_SECURITY_WORKFLOWS"


class PolicySource(str, Enum):
    CANDIDATE = "candidate"
    POLICY = "policy"


class VersionDisposition(str, Enum):
    SAME_VERSION = "SAME_VERSION"
    IMMEDIATE_SUCCESSOR = "IMMEDIATE_SUCCESSOR"


@dataclass(frozen=True)
class BootstrapInputs:
    event_name: str
    repository: str
    base_repository: str
    base_branch: str
    candidate_sha: str
    protected_sha: str
    candidate_root: Path
    protected_root: Path
    candidate_baseline: str
    event_ref: str = ""
    default_branch: str = "main"
    workflow_ref: str = ""


@dataclass(frozen=True)
class BootstrapResult:
    evaluation_context: EvaluationContext
    policy_source: PolicySource
    version_disposition: VersionDisposition
    owner_authorization: str
    post_merge_proof: str

    def as_outputs(self) -> tuple[tuple[str, str], ...]:
        values = (
            ("evaluation-context", self.evaluation_context.value),
            ("policy-source", self.policy_source.value),
            ("version-disposition", self.version_disposition.value),
            ("owner-authorization", self.owner_authorization),
            ("post-merge-proof", self.post_merge_proof),
        )
        for key, value in values:
            _clean(key, "output key")
            _clean(value, "output value")
        return values


def _clean(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(char in value for char in "\r\n\0"):
        raise BootstrapError(f"Invalid {label}")
    return value


def _repository(value: object, label: str) -> str:
    text = _clean(value, label)
    if _REPOSITORY.fullmatch(text) is None:
        raise BootstrapError(f"Invalid {label}")
    return text


def _sha(value: object, label: str) -> str:
    text = _clean(value, label)
    if _SHA.fullmatch(text) is None:
        raise BootstrapError(f"Invalid {label}")
    return text


def _root(value: object, label: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise BootstrapError(f"Invalid {label}")
    try:
        resolved = value.resolve(strict=True)
    except OSError as error:
        raise BootstrapError(f"Invalid {label}") from error
    if not resolved.is_dir() or resolved != value:
        raise BootstrapError(f"Invalid {label}")
    return resolved


def _git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments], check=True,
            capture_output=True, text=True, encoding="utf-8", errors="strict",
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise BootstrapError("Git identity verification failed") from error
    value = completed.stdout.strip()
    if not value or any(char in value for char in "\r\n\0"):
        raise BootstrapError("Malformed Git identity output")
    return value


def _canonical_remote(value: str) -> str:
    clean = _clean(value, "Git remote").rstrip("/")
    prefix = "https://github.com/"
    if not clean.startswith(prefix):
        raise BootstrapError("Unsupported Git remote")
    repository = clean[len(prefix):]
    if repository.endswith(".git"):
        repository = repository[:-4]
    return _repository(repository, "Git remote repository")


def _context(inputs: BootstrapInputs) -> EvaluationContext:
    event = _clean(inputs.event_name, "event name")
    repository = _repository(inputs.repository, "repository")
    base_repository = _repository(inputs.base_repository, "base repository")
    branch = _clean(inputs.base_branch, "base branch")
    default_branch = _clean(inputs.default_branch, "default branch")

    if event == "workflow_dispatch":
        expected_workflow = f"{REPOSITORY}/.github/workflows/security-workflows-policy.yml@refs/heads/main"
        if (repository, base_repository, branch, default_branch, inputs.event_ref,
                inputs.workflow_ref) != (REPOSITORY, REPOSITORY, "main", "main",
                                         "refs/heads/main", expected_workflow):
            raise BootstrapError("Unsupported protected-proof context")
        return EvaluationContext.STAGE_A_PROTECTED_PROOF
    if event == "pull_request" and repository == REPOSITORY:
        if base_repository != REPOSITORY or branch != "main":
            raise BootstrapError("Unsupported self-PR context")
        return EvaluationContext.SELF_PR_BOOTSTRAP
    if event in {"pull_request", "merge_group"} and repository == DOWNSTREAM_REPOSITORY:
        if base_repository != DOWNSTREAM_REPOSITORY or branch != "main":
            raise BootstrapError("Unsupported downstream context")
        return EvaluationContext.DOWNSTREAM_SECURITY_WORKFLOWS
    raise BootstrapError("Unsupported or ambiguous evaluation context")


def evaluate(inputs: BootstrapInputs) -> BootstrapResult:
    """Validate bootstrap identity and return closed deterministic decisions."""
    if not isinstance(inputs, BootstrapInputs):
        raise BootstrapError("Invalid bootstrap input object")
    candidate_sha = _sha(inputs.candidate_sha, "candidate SHA")
    protected_sha = _sha(inputs.protected_sha, "protected SHA")
    candidate = _root(inputs.candidate_root, "candidate root")
    protected = _root(inputs.protected_root, "protected root")
    if candidate == protected or candidate.is_relative_to(protected) or protected.is_relative_to(candidate):
        raise BootstrapError("Candidate and protected roots must be separate")

    context = _context(inputs)
    if _git(candidate, "rev-parse", "HEAD") != candidate_sha:
        raise BootstrapError("Candidate checkout does not match authorized SHA")
    if _git(protected, "rev-parse", "HEAD") != protected_sha:
        raise BootstrapError("Protected checkout does not match protected SHA")
    if _git(protected, "rev-parse", "refs/remotes/origin/main") != protected_sha:
        raise BootstrapError("Protected checkout is not protected main")
    if _canonical_remote(_git(candidate, "remote", "get-url", "origin")) != inputs.repository:
        raise BootstrapError("Candidate checkout repository mismatch")
    if _canonical_remote(_git(protected, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("Protected checkout repository mismatch")
    if context is EvaluationContext.STAGE_A_PROTECTED_PROOF and candidate_sha != protected_sha:
        raise BootstrapError("Protected proof roots must use the same protected SHA")

    protected_baseline = CURRENT_BASELINE
    candidate_baseline = _clean(inputs.candidate_baseline, "candidate baseline")
    match = _BASELINE.fullmatch(candidate_baseline)
    if match is None:
        raise BootstrapError("Malformed candidate baseline")
    if candidate_baseline == protected_baseline:
        disposition = VersionDisposition.SAME_VERSION
    elif candidate_baseline == IMMEDIATE_SUCCESSOR:
        if context is not EvaluationContext.SELF_PR_BOOTSTRAP:
            raise BootstrapError("Successor proposal requires self-PR context")
        if protected_sha != TRANSITION_PROTECTED_BASE:
            raise BootstrapError("Successor transition is expired or bound to another base")
        disposition = VersionDisposition.IMMEDIATE_SUCCESSOR
    else:
        raise BootstrapError("Unsupported baseline transition")

    if context is EvaluationContext.SELF_PR_BOOTSTRAP and disposition is VersionDisposition.SAME_VERSION:
        source = PolicySource.CANDIDATE
    else:
        source = PolicySource.POLICY
    return BootstrapResult(context, source, disposition, OWNER_AUTHORIZATION, POST_MERGE_PROOF)
