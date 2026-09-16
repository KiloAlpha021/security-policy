"""Pre-environment identity and baseline-transition decisions.

Until this file is merged and proved from protected main, it is candidate proposal
evidence only.  It cannot authorize its own landing.  Owner authorization and a
post-merge protected proof are required for the first landing.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import subprocess
import sys
import tempfile
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
MODEL_D_MAINTENANCE_OPERATION = "MODEL_D_ORCHESTRATION_V1"
MODEL_D_TRANSITION_BASE = "97774bf4f5885a5900a1ccea98c98af12482f9e0"
MODEL_D_MAINTENANCE_PATHS = (
    ".github/workflows/security-workflows-policy.yml",
    "protected_policy_bootstrap.py",
    "test_verify_security_workflows.py",
)
PROTECTED_UNIVERSE = (
    ".github/workflows/security-workflows-policy.yml",
    "requirements-audit.lock",
    "requirements-policy.lock",
    "test_verify_security_workflows.py",
    "verify_security_workflows.py",
    "protected_policy_bootstrap.py",
)
CANDIDATE_BASELINE_PATH = ".github/workflows/security-workflows-policy.yml"

_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_BASELINE = re.compile(r"SECURITY-POLICY-BASELINE-([1-9][0-9]*)\Z")
_BASELINE_DECLARATION = re.compile(
    r"(?m)^  POLICY_BASELINE_VERSION: (SECURITY-POLICY-BASELINE-[1-9][0-9]*)$"
)
_ANY_BASELINE_DECLARATION = re.compile(r"(?m)^[ \t]*POLICY_BASELINE_VERSION[ \t]*:")
_OUTPUT_KEYS = (
    "evaluation-context",
    "policy-source",
    "version-disposition",
    "owner-authorization",
    "post-merge-proof",
)


class _Once(argparse.Action):
    """Reject repeated options instead of silently accepting the last value."""

    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"argument {option_string}: may be specified only once")
        setattr(namespace, self.dest, values)


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


def extract_candidate_baseline(candidate_root: Path) -> str:
    """Read one exact baseline declaration from the candidate workflow."""
    root = _root(candidate_root, "candidate root")
    path = root / CANDIDATE_BASELINE_PATH
    try:
        metadata = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise BootstrapError("Candidate baseline declaration is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise BootstrapError("Candidate baseline source must be a regular file")
    if b"\x00" in data or b"\r" in data:
        raise BootstrapError("Invalid candidate baseline source bytes")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise BootstrapError("Invalid candidate baseline source encoding") from error
    declarations = _ANY_BASELINE_DECLARATION.findall(text)
    exact = _BASELINE_DECLARATION.findall(text)
    if len(declarations) != 1 or len(exact) != 1:
        raise BootstrapError("Candidate baseline must have one exact declaration")
    baseline = exact[0]
    if baseline not in {CURRENT_BASELINE, IMMEDIATE_SUCCESSOR}:
        raise BootstrapError("Unsupported candidate baseline declaration")
    return baseline


def validate_universe_members(members: tuple[str, ...]) -> None:
    """Validate an observed protected-universe identity against protected v2."""
    if not isinstance(members, tuple) or len(set(members)) != len(members):
        raise BootstrapError("Invalid protected universe identity")
    for member in members:
        clean = _clean(member, "protected universe member")
        path = Path(clean)
        if (path.is_absolute() or "\\" in clean or clean.startswith("/")
                or any(part in {"", ".", ".."} for part in path.parts)
                or path.as_posix() != clean):
            raise BootstrapError("Noncanonical protected universe member")
    if members != PROTECTED_UNIVERSE:
        raise BootstrapError("Protected universe does not match canonical v2")


def validate_protected_universe(protected_root: Path, protected_sha: str) -> None:
    """Require every canonical member to be a tracked regular 100644 blob."""
    root = _root(protected_root, "protected root")
    revision = _sha(protected_sha, "protected SHA")
    validate_universe_members(PROTECTED_UNIVERSE)
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-z", revision, "--", *PROTECTED_UNIVERSE],
            check=True, capture_output=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BootstrapError("Protected universe Git validation failed") from error
    entries: dict[str, tuple[str, str]] = {}
    try:
        records = completed.stdout.split(b"\0")
        for record in records:
            if not record:
                continue
            identity, raw_path = record.split(b"\t", 1)
            mode, kind, _object_id = identity.decode("ascii", errors="strict").split(" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
            if path in entries:
                raise BootstrapError("Duplicate protected universe member")
            entries[path] = (mode, kind)
    except (ValueError, UnicodeError) as error:
        raise BootstrapError("Malformed protected universe Git output") from error
    if set(entries) != set(PROTECTED_UNIVERSE):
        raise BootstrapError("Protected universe member is missing or renamed")
    if any(identity != ("100644", "blob") for identity in entries.values()):
        raise BootstrapError("Protected universe member must be a regular 100644 blob")


def _git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments], check=True,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BootstrapError("Git maintenance admission failed") from error
    return completed.stdout


def _tree_entries(root: Path, revision: str,
                  paths: tuple[str, ...]) -> dict[str, tuple[str, str]]:
    output = _git_bytes(root, "ls-tree", "-z", revision, "--", *paths)
    entries: dict[str, tuple[str, str]] = {}
    try:
        for record in output.split(b"\0"):
            if not record:
                continue
            identity, raw_path = record.split(b"\t", 1)
            mode, kind, _object_id = identity.decode(
                "ascii", errors="strict").split(" ", 2)
            path = raw_path.decode("utf-8", errors="strict")
            if path in entries:
                raise BootstrapError("Duplicate maintenance path identity")
            entries[path] = (mode, kind)
    except (ValueError, UnicodeError) as error:
        raise BootstrapError("Malformed maintenance tree identity") from error
    return entries


def _model_d_records(output: bytes) -> tuple[tuple[str, str], ...]:
    if not isinstance(output, bytes):
        raise BootstrapError("Malformed Model D maintenance diff")
    if not output.endswith(b"\0"):
        raise BootstrapError("Malformed Model D maintenance diff")
    fields = output.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if len(fields) != len(MODEL_D_MAINTENANCE_PATHS) * 2:
        raise BootstrapError("Model D maintenance requires exactly three records")
    records: list[tuple[str, str]] = []
    try:
        for index in range(0, len(fields), 2):
            status_value = fields[index].decode("ascii", errors="strict")
            path_value = fields[index + 1].decode("utf-8", errors="strict")
            path = Path(path_value)
            if (any(char in path_value for char in "\r\n\0")
                    or path.is_absolute() or "\\" in path_value
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or path.as_posix() != path_value):
                raise BootstrapError("Invalid Model D maintenance path")
            records.append((status_value, path_value))
    except (IndexError, UnicodeError) as error:
        raise BootstrapError("Malformed Model D maintenance diff") from error
    if len({path_value for _status, path_value in records}) != len(records):
        raise BootstrapError("Duplicate Model D maintenance path")
    if tuple(path_value for _status, path_value in records) != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError("Model D maintenance paths do not match protected scope")
    if any(status_value != "M" for status_value, _path in records):
        raise BootstrapError("Model D maintenance requires exact modified statuses")
    return tuple(records)


def validate_model_d_maintenance(
        operation: str, candidate_root: Path, protected_root: Path,
        candidate_sha: str, protected_sha: str) -> None:
    """Admit one exact Model D operation during its protected lifecycle.

    The protected authority commit must be the normal two-parent first landing
    whose first parent is MODEL_D_TRANSITION_BASE.  After the comprehensive
    Model D merge, protected main has a different first parent and this bridge
    expires automatically.
    """
    if _clean(operation, "maintenance operation") != MODEL_D_MAINTENANCE_OPERATION:
        raise BootstrapError("Unsupported maintenance operation")
    candidate_revision = _sha(candidate_sha, "candidate SHA")
    protected_revision = _sha(protected_sha, "protected SHA")
    candidate = _root(candidate_root, "candidate root")
    protected = _root(protected_root, "protected root")
    if (candidate == protected or candidate.is_relative_to(protected)
            or protected.is_relative_to(candidate)):
        raise BootstrapError("Candidate and protected roots must be separate")
    if _git(candidate, "rev-parse", "HEAD") != candidate_revision:
        raise BootstrapError("Candidate checkout does not match authorized SHA")
    if _git(protected, "rev-parse", "HEAD") != protected_revision:
        raise BootstrapError("Protected checkout does not match protected SHA")
    if _git(protected, "rev-parse", "refs/remotes/origin/main") != protected_revision:
        raise BootstrapError("Protected checkout is not protected main")
    if _canonical_remote(_git(candidate, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("Candidate checkout repository mismatch")
    if _canonical_remote(_git(protected, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("Protected checkout repository mismatch")

    parents = _git(protected, "rev-list", "--parents", "-n", "1",
                   protected_revision).split(" ")
    if (len(parents) != 3 or parents[0] != protected_revision
            or parents[1] != MODEL_D_TRANSITION_BASE):
        raise BootstrapError("Model D maintenance operation is expired or bound to another base")
    _model_d_records(_git_bytes(
        protected, "diff", "--name-status", "-z", "--no-renames",
        MODEL_D_TRANSITION_BASE, protected_revision,
    ))

    validate_protected_universe(protected, protected_revision)
    validate_protected_universe(candidate, candidate_revision)
    if extract_candidate_baseline(candidate) != CURRENT_BASELINE:
        raise BootstrapError("Model D maintenance requires the current protected baseline")

    output = _git_bytes(
        candidate, "diff", "--name-status", "-z", "--no-renames",
        protected_revision, candidate_revision,
    )
    _model_d_records(output)

    for root, revision in ((protected, protected_revision),
                           (candidate, candidate_revision)):
        entries = _tree_entries(root, revision, MODEL_D_MAINTENANCE_PATHS)
        if tuple(entries) != MODEL_D_MAINTENANCE_PATHS:
            raise BootstrapError("Model D maintenance tree paths do not match protected scope")
        if any(identity != ("100644", "blob") for identity in entries.values()):
            raise BootstrapError("Model D maintenance paths must be regular 100644 blobs")


def _validated_outputs(result: BootstrapResult) -> tuple[tuple[str, str], ...]:
    if not isinstance(result, BootstrapResult):
        raise BootstrapError("Invalid bootstrap result")
    if (not isinstance(result.evaluation_context, EvaluationContext)
            or not isinstance(result.policy_source, PolicySource)
            or not isinstance(result.version_disposition, VersionDisposition)
            or result.owner_authorization != OWNER_AUTHORIZATION
            or result.post_merge_proof != POST_MERGE_PROOF):
        raise BootstrapError("Invalid bootstrap result authority")
    expected = (
        ("evaluation-context", result.evaluation_context.value),
        ("policy-source", result.policy_source.value),
        ("version-disposition", result.version_disposition.value),
        ("owner-authorization", OWNER_AUTHORIZATION),
        ("post-merge-proof", POST_MERGE_PROOF),
    )
    values = result.as_outputs()
    if values != expected:
        raise BootstrapError("Bootstrap outputs do not match protected result")
    if tuple(key for key, _value in values) != _OUTPUT_KEYS:
        raise BootstrapError("Invalid bootstrap output schema")
    if len(set(key for key, _value in values)) != len(_OUTPUT_KEYS):
        raise BootstrapError("Duplicate bootstrap output key")
    allowed = {
        "evaluation-context": {item.value for item in EvaluationContext},
        "policy-source": {item.value for item in PolicySource},
        "version-disposition": {item.value for item in VersionDisposition},
        "owner-authorization": {OWNER_AUTHORIZATION},
        "post-merge-proof": {POST_MERGE_PROOF},
    }
    if any(value not in allowed[key] for key, value in values):
        raise BootstrapError("Invalid bootstrap output value")
    return values


def emit_github_output(
        result: BootstrapResult, destination: Path,
        candidate_root: Path, protected_root: Path) -> None:
    """Atomically replace a trusted empty output file with validated outputs."""
    values = _validated_outputs(result)
    candidate = _root(candidate_root, "candidate root")
    protected = _root(protected_root, "protected root")
    if not isinstance(destination, Path) or not destination.is_absolute():
        raise BootstrapError("Invalid GITHUB_OUTPUT destination")
    try:
        parent = destination.parent.resolve(strict=True)
        resolved = destination.resolve(strict=True)
        metadata = destination.lstat()
    except OSError as error:
        raise BootstrapError("Invalid GITHUB_OUTPUT destination") from error
    if (resolved != destination or parent != destination.parent
            or not stat.S_ISREG(metadata.st_mode) or destination.is_symlink()
            or resolved.is_relative_to(candidate) or resolved.is_relative_to(protected)):
        raise BootstrapError("Unsafe GITHUB_OUTPUT destination")
    try:
        if destination.read_bytes():
            raise BootstrapError("GITHUB_OUTPUT destination must be empty")
    except OSError as error:
        raise BootstrapError("Invalid GITHUB_OUTPUT destination") from error
    payload = "".join(f"{key}={value}\n" for key, value in values).encode("utf-8")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", dir=parent, prefix=".bootstrap-output-",
                delete=False) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, destination)
        temporary_name = None
    except OSError as error:
        raise BootstrapError("Unable to emit bootstrap outputs") from error
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass


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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="protected_policy_bootstrap.py")
    commands = parser.add_subparsers(dest="operation", required=True)
    evaluate_parser = commands.add_parser("evaluate")
    for name in (
            "event-name", "repository", "base-repository", "base-branch",
            "candidate-sha", "protected-sha", "candidate-root", "protected-root",
            "event-ref", "default-branch", "workflow-ref"):
        evaluate_parser.add_argument(f"--{name}", required=True, default=None, action=_Once)
    maintenance_parser = commands.add_parser("admit-maintenance")
    for name in (
            "maintenance-operation", "candidate-sha", "protected-sha",
            "candidate-root", "protected-root"):
        maintenance_parser.add_argument(
            f"--{name}", required=True, default=None, action=_Once)
    return parser


def _cli_inputs(arguments: argparse.Namespace) -> BootstrapInputs:
    candidate_root = Path(arguments.candidate_root)
    protected_root = Path(arguments.protected_root)
    baseline = extract_candidate_baseline(candidate_root)
    return BootstrapInputs(
        event_name=arguments.event_name,
        repository=arguments.repository,
        base_repository=arguments.base_repository,
        base_branch=arguments.base_branch,
        candidate_sha=arguments.candidate_sha,
        protected_sha=arguments.protected_sha,
        candidate_root=candidate_root,
        protected_root=protected_root,
        candidate_baseline=baseline,
        event_ref=arguments.event_ref,
        default_branch=arguments.default_branch,
        workflow_ref=arguments.workflow_ref,
    )


def main(argv: list[str] | None = None) -> int:
    """Run one closed protected bootstrap operation and fail closed."""
    try:
        arguments = _parser().parse_args(argv)
        if arguments.operation == "admit-maintenance":
            validate_model_d_maintenance(
                arguments.maintenance_operation,
                Path(arguments.candidate_root), Path(arguments.protected_root),
                arguments.candidate_sha, arguments.protected_sha,
            )
            return 0
        if arguments.operation != "evaluate":
            raise BootstrapError("Unsupported bootstrap operation")
        inputs = _cli_inputs(arguments)
        result = evaluate(inputs)
        validate_protected_universe(inputs.protected_root, inputs.protected_sha)
        raw_destination = os.environ.get("GITHUB_OUTPUT")
        if raw_destination is None:
            raise BootstrapError("GITHUB_OUTPUT is required")
        emit_github_output(
            result, Path(raw_destination), inputs.candidate_root, inputs.protected_root)
    except BootstrapError as error:
        print(f"bootstrap error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
