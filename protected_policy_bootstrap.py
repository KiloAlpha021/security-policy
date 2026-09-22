"""Pre-environment identity and baseline-transition decisions.

Until this file is merged and proved from protected main, it is candidate proposal
evidence only.  It cannot authorize its own landing.  Owner authorization and a
post-merge protected proof are required for the first landing.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
import unicodedata
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
MODEL_D_PLAN_OPERATION = "MODEL_D_PLAN_V1"
MODEL_D_MAINTENANCE_GENERATION = "MODEL_D_ORCHESTRATION_V1_GENERATION_1"
MODEL_D_MAINTENANCE_HISTORY_ANCHOR = "2784fc943f9eebcab4e468980ad0040499eadc52"
MODEL_D_MAINTENANCE_LIFECYCLE = "MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED"
G2_MAINTENANCE_GENERATION = "MODEL_D_ORCHESTRATION_V1_GENERATION_2"
G2_MAINTENANCE_LIFECYCLE = "MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE_BOUND"
G2_MAINTENANCE_PURPOSE = "PUB-01A/PUB-01B/PUB-01C protected routing correction"
G2_BOUND_ORIGIN = "985bdf2801f07d8f2447d1bcde96c7a7a59669ad"
G2_BOUND_CANDIDATE_TREE = "4272cb4707345a1a3da41382525e9833e0f1a7e1"
G2_BOUND_WORKFLOW_BLOB = "e8a2ff5957c77f03f1c5b8b16ae707820f11159f"
G2_BOUND_BOOTSTRAP_BLOB = "7edbdf8c216aa336bae95af44fef8b9e4a582731"
G2_BOUND_TEST_BLOB = "cd5ce5f194cef50dd016ca529f2857cf8c7a6082"
G2_BOUND_EXPECTED_TERMINAL = "MODEL_D_ORCHESTRATION_V1_GENERATION_2:CONSUMED"
B3_AUTHORITY_ORIGIN = "9393099a9060f90689341611457c9b9032959b88"
B3_ENABLEMENT = "DESIGN_B_FINITE_V1"
B3_CORRECTION = "PPR_FWD_01_V1"
B3_CORRECTION_BASE = "580e923a5adb83bda915af32ffacb9c55512a26f"
B3_CORRECTION_PATHS = (
    ".github/workflows/security-workflows-policy.yml",
    "protected_policy_bootstrap.py",
    "test_verify_security_workflows.py",
)
MODEL_D_MAINTENANCE_PATHS = (
    ".github/workflows/security-workflows-policy.yml",
    "protected_policy_bootstrap.py",
    "test_verify_security_workflows.py",
)
G2_EXPECTED_CANDIDATE_BLOBS = (
    (MODEL_D_MAINTENANCE_PATHS[0], G2_BOUND_WORKFLOW_BLOB),
    (MODEL_D_MAINTENANCE_PATHS[1], G2_BOUND_BOOTSTRAP_BLOB),
    (MODEL_D_MAINTENANCE_PATHS[2], G2_BOUND_TEST_BLOB),
)
G2_BINDING_PATHS = (
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
_MODEL_D_OUTPUT_KEYS = (
    "normalization-roots", "policy-lock-source", "audit-lock-source",
    "candidate-evidence", "protected-evidence", "downstream-validation",
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


class NormalizationRoot(str, Enum):
    CANDIDATE = "candidate"
    POLICY = "policy"


class CandidateEvidenceDisposition(str, Enum):
    RUN_STAGE_A = "RUN_CANDIDATE_STAGE_A_EVIDENCE"
    SKIP = "SKIP"


class ProtectedEvidenceDisposition(str, Enum):
    RUN_LEGACY_HEALTH = "RUN_LEGACY_PROTECTED_HEALTH"
    APPLY_STAGE_A_TO_CANDIDATE = "APPLY_PROTECTED_STAGE_A_TO_CANDIDATE"
    TEST_INDEPENDENT_POLICY = "TEST_INDEPENDENT_ROOT_POLICY"


class DownstreamValidationDisposition(str, Enum):
    RUN = "RUN_DOWNSTREAM_VALIDATION"
    SKIP = "SKIP"


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


@dataclass(frozen=True, slots=True)
class ModelDOrchestrationPlan:
    normalization_roots: tuple[NormalizationRoot, ...]
    policy_lock_source: PolicySource
    audit_lock_source: PolicySource
    candidate_evidence: CandidateEvidenceDisposition
    protected_evidence: ProtectedEvidenceDisposition
    downstream_validation: DownstreamValidationDisposition

    def __post_init__(self) -> None:
        if (type(self.normalization_roots) is not tuple or
                self.normalization_roots != (
                    NormalizationRoot.CANDIDATE, NormalizationRoot.POLICY) or
                any(type(root) is not NormalizationRoot
                    for root in self.normalization_roots) or
                type(self.policy_lock_source) is not PolicySource or
                type(self.audit_lock_source) is not PolicySource or
                type(self.candidate_evidence) is not CandidateEvidenceDisposition or
                type(self.protected_evidence) is not ProtectedEvidenceDisposition or
                type(self.downstream_validation) is not DownstreamValidationDisposition):
            raise BootstrapError("Invalid MODEL_D_PLAN_V1 value")


def derive_model_d_plan(result: BootstrapResult) -> ModelDOrchestrationPlan:
    """Map a result value to a plan value; neither object proves provenance."""
    if type(result) is not BootstrapResult:
        raise BootstrapError("Invalid MODEL_D_PLAN_V1 input")
    if set(vars(result)) != {
            "evaluation_context", "policy_source", "version_disposition",
            "owner_authorization", "post_merge_proof"}:
        raise BootstrapError("Invalid MODEL_D_PLAN_V1 input schema")
    _validated_outputs(result)

    authority = (
        result.evaluation_context,
        result.policy_source,
        result.version_disposition,
    )
    supported = {
        (EvaluationContext.SELF_PR_BOOTSTRAP,
         PolicySource.CANDIDATE,
         VersionDisposition.SAME_VERSION): (
            CandidateEvidenceDisposition.RUN_STAGE_A,
            ProtectedEvidenceDisposition.RUN_LEGACY_HEALTH,
            DownstreamValidationDisposition.SKIP,
        ),
        (EvaluationContext.SELF_PR_BOOTSTRAP,
         PolicySource.POLICY,
         VersionDisposition.IMMEDIATE_SUCCESSOR): (
            CandidateEvidenceDisposition.RUN_STAGE_A,
            ProtectedEvidenceDisposition.RUN_LEGACY_HEALTH,
            DownstreamValidationDisposition.SKIP,
        ),
        (EvaluationContext.STAGE_A_PROTECTED_PROOF,
         PolicySource.POLICY,
         VersionDisposition.SAME_VERSION): (
            CandidateEvidenceDisposition.RUN_STAGE_A,
            ProtectedEvidenceDisposition.APPLY_STAGE_A_TO_CANDIDATE,
            DownstreamValidationDisposition.SKIP,
        ),
        (EvaluationContext.DOWNSTREAM_SECURITY_WORKFLOWS,
         PolicySource.POLICY,
         VersionDisposition.SAME_VERSION): (
            CandidateEvidenceDisposition.SKIP,
            ProtectedEvidenceDisposition.TEST_INDEPENDENT_POLICY,
            DownstreamValidationDisposition.RUN,
        ),
    }
    try:
        candidate_evidence, protected_evidence, downstream_validation = supported[authority]
    except KeyError as error:
        raise BootstrapError("Unsupported MODEL_D_PLAN_V1 authority combination") from error
    return ModelDOrchestrationPlan(
        normalization_roots=(NormalizationRoot.CANDIDATE, NormalizationRoot.POLICY),
        policy_lock_source=result.policy_source,
        audit_lock_source=result.policy_source,
        candidate_evidence=candidate_evidence,
        protected_evidence=protected_evidence,
        downstream_validation=downstream_validation,
    )


def evaluate_model_d_plan(
        inputs: BootstrapInputs) -> tuple[BootstrapResult, ModelDOrchestrationPlan]:
    """Authoritative D1 entry point: evaluate once, then apply the sole plan map."""
    result = evaluate(inputs)
    return result, derive_model_d_plan(result)


def validate_model_d_plan_correspondence(
        inputs: BootstrapInputs, result: BootstrapResult,
        plan: ModelDOrchestrationPlan,
) -> tuple[BootstrapResult, ModelDOrchestrationPlan]:
    """Recompute before accepting supplied values; equality, not identity, binds them."""
    canonical_result, canonical_plan = evaluate_model_d_plan(inputs)
    if (type(result) is not BootstrapResult or
            type(plan) is not ModelDOrchestrationPlan or
            result != canonical_result or plan != canonical_plan):
        raise BootstrapError("MODEL_D_PLAN_V1 correspondence mismatch")
    return canonical_result, canonical_plan


_LOCK_ENTRY = re.compile(
    r"([A-Za-z0-9_.-]+)==([^\s]+) --hash=sha256:([0-9a-f]{64})\Z")
_PROTECTED_LOCK_BLOBS = {
    "requirements-policy.lock": "b11e8ca274a5426789be10d24919679c8da0aa4f",
    "requirements-audit.lock": "dbfa6a4d8ef8c344009ad3a15007b2b1c98511fe",
}


def _validate_model_d_lock(root: Path, revision: str, name: str,
                           source: PolicySource) -> None:
    """Verify exact committed and worktree bytes of one plan-selected lock."""
    record = _git_bytes(root, "ls-tree", "-z", revision, "--", name)
    try:
        identity, raw_path = record.removesuffix(b"\0").split(b"\t", 1)
        mode, kind, object_id = identity.decode("ascii").split(" ")
        if (raw_path != name.encode("ascii") or mode != "100644" or
                kind != "blob" or _SHA.fullmatch(object_id) is None):
            raise ValueError("Invalid lock tree entry")
    except (UnicodeError, ValueError) as error:
        raise BootstrapError("Invalid Model D lock Git identity") from error
    if source is PolicySource.POLICY and object_id != _PROTECTED_LOCK_BLOBS[name]:
        raise BootstrapError("Protected Model D lock identity changed")
    path = root / name
    try:
        metadata = path.lstat()
        data = path.read_bytes()
    except OSError as error:
        raise BootstrapError("Model D lock is unavailable") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise BootstrapError("Model D lock must be a regular file")
    if (hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data)
            .hexdigest() != object_id):
        raise BootstrapError("Model D lock raw bytes differ from committed bytes")
    if (b"\0" in data or b"\r" in data or data.startswith(b"\xef\xbb\xbf") or
            not data.endswith(b"\n")):
        raise BootstrapError("Invalid Model D lock representation")
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as error:
        raise BootstrapError("Invalid Model D lock encoding") from error
    entries = [line for line in lines if line and not line.startswith("#")]
    if (not entries or entries[0] != "--only-binary=:all:" or
            len(entries) < 2 or any(_LOCK_ENTRY.fullmatch(line) is None
                                    for line in entries[1:])):
        raise BootstrapError("Malformed Model D lock")
    names = [_LOCK_ENTRY.fullmatch(line).group(1).lower() for line in entries[1:]]
    if len(names) != len(set(names)):
        raise BootstrapError("Duplicate Model D lock package")
    required = "pyyaml" if name == "requirements-policy.lock" else "pip-audit"
    if required not in names:
        raise BootstrapError("Model D lock has the wrong role")


def normalize_and_validate_model_d_bytes(
        inputs: BootstrapInputs) -> tuple[BootstrapResult, ModelDOrchestrationPlan]:
    """D2 mechanics: use only canonical D1 decisions, return only after validation.

    Workflow invocation and external failure propagation belong to D3.
    """
    result, plan = evaluate_model_d_plan(inputs)
    roots = {
        NormalizationRoot.CANDIDATE: _root(inputs.candidate_root, "candidate root"),
        NormalizationRoot.POLICY: _root(inputs.protected_root, "protected root"),
    }
    revisions = {
        NormalizationRoot.CANDIDATE: _sha(inputs.candidate_sha, "candidate SHA"),
        NormalizationRoot.POLICY: _sha(inputs.protected_sha, "protected SHA"),
    }
    for selected in plan.normalization_roots:
        root = roots[selected]
        revision = revisions[selected]
        _git_bytes(root, "config", "--local", "core.autocrlf", "false")
        if _git(root, "config", "--local", "--get", "core.autocrlf") != "false":
            raise BootstrapError("Model D normalization policy did not take effect")
        _git_bytes(root, "reset", "--hard", revision)
        if _git(root, "rev-parse", "HEAD") != revision:
            raise BootstrapError("Model D normalization changed checkout identity")
    sources = (
        ("requirements-policy.lock", plan.policy_lock_source),
        ("requirements-audit.lock", plan.audit_lock_source),
    )
    for name, source in sources:
        selected = (NormalizationRoot.CANDIDATE if source is PolicySource.CANDIDATE
                    else NormalizationRoot.POLICY)
        _validate_model_d_lock(roots[selected], revisions[selected], name, source)
    return result, plan


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
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
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
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
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


def _model_d_generation_state(root: Path, revision: str) -> str:
    """Read the closed generation state from protected Git objects."""
    bootstrap_source = _git_bytes(
        root, "show", f"{revision}:protected_policy_bootstrap.py")
    workflow_source = _git_bytes(
        root, "show", f"{revision}:.github/workflows/security-workflows-policy.yml")
    try:
        bootstrap_text = bootstrap_source.decode("utf-8", errors="strict")
        workflow_text = workflow_source.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise BootstrapError("Invalid Model D generation source encoding") from error
    if any(value in bootstrap_source + workflow_source for value in (b"\r", b"\0")):
        raise BootstrapError("Invalid Model D generation source bytes")
    generation_line = (
        f'MODEL_D_MAINTENANCE_GENERATION = "{MODEL_D_MAINTENANCE_GENERATION}"')
    lifecycle_name = "MODEL_D_MAINTENANCE_" + "LIFECYCLE"
    lifecycle_lines = re.findall(
        rf"^{re.escape(lifecycle_name)}[^\n]*$", bootstrap_text, re.MULTILINE)
    lifecycle_pattern = re.compile(
        rf'^{re.escape(lifecycle_name)} = "'
        rf'({re.escape(MODEL_D_MAINTENANCE_GENERATION)}):(ACTIVE|CONSUMED)"$')
    workflow_generation = (
        "  MODEL_D_MAINTENANCE_GENERATION: " + MODEL_D_MAINTENANCE_GENERATION)
    invocation = '--maintenance-generation "${{ env.MODEL_D_MAINTENANCE_GENERATION }}"'
    if (bootstrap_text.count(generation_line) != 1
            or workflow_text.count(workflow_generation) != 1
            or workflow_text.count(invocation) != 1):
        raise BootstrapError("Model D maintenance generation identity mismatch")
    if len(lifecycle_lines) != 1:
        raise BootstrapError("Missing or malformed Model D lifecycle record")
    lifecycle = lifecycle_pattern.fullmatch(lifecycle_lines[0])
    if lifecycle is None:
        raise BootstrapError("Missing or malformed Model D lifecycle record")
    return lifecycle.group(2)


def _require_model_d_history(root: Path, revision: str) -> None:
    """Require sufficient protected ancestry for lifecycle consumption checks."""
    shallow = _git_bytes(root, "rev-parse", "--is-shallow-repository")
    if shallow != b"false\n":
        raise BootstrapError("Protected lifecycle history is shallow or malformed")
    _git_bytes(
        root, "cat-file", "-e", MODEL_D_MAINTENANCE_HISTORY_ANCHOR + "^{commit}")
    _git_bytes(
        root, "merge-base", "--is-ancestor",
        MODEL_D_MAINTENANCE_HISTORY_ANCHOR, revision)


def _model_d_generation_was_consumed(
        root: Path, revision: str,
        generation: str = MODEL_D_MAINTENANCE_GENERATION) -> bool:
    """Reject an ACTIVE rollback whose protected history already consumed it."""
    if re.fullmatch(r"MODEL_D_ORCHESTRATION_V1_GENERATION_[1-9][0-9]*", generation) is None:
        raise BootstrapError("Malformed Model D maintenance generation")
    lifecycle_name = "MODEL_D_MAINTENANCE_" + "LIFECYCLE"
    declaration = f'{lifecycle_name} = "{generation}:CON' + 'SUMED"'
    output = _git_bytes(
        root, "log", "--format=%H", "-S" + declaration,
        f"{MODEL_D_MAINTENANCE_HISTORY_ANCHOR}..{revision}",
        "--", "protected_policy_bootstrap.py")
    return bool(output.strip())


def _g2_generation_was_consumed(root: Path, revision: str) -> bool:
    """A protected G2 terminal record cannot be erased by later declarations."""
    declaration = (f'G2_MAINTENANCE_LIFECYCLE = '
                   f'"{G2_MAINTENANCE_GENERATION}:CONSUMED"')
    output = _git_bytes(
        root, "log", "--format=%H", "-S" + declaration,
        f"{MODEL_D_MAINTENANCE_HISTORY_ANCHOR}..{revision}",
        "--", "protected_policy_bootstrap.py")
    return bool(output.strip())


def _g2_lifecycle(source: bytes) -> str:
    """Return one closed G2 lifecycle declaration from protected bytes."""
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise BootstrapError("Invalid G2 source encoding") from error
    if b"\r" in source or b"\0" in source:
        raise BootstrapError("Invalid G2 source bytes")
    name = "G2_MAINTENANCE_LIFECYCLE"
    lines = re.findall(rf"^{name}[^\n]*$", text, re.MULTILINE)
    pattern = re.compile(
        rf'^{name} = "{re.escape(G2_MAINTENANCE_GENERATION)}:'
        r'(ACTIVE_UNBOUND|ACTIVE_BOUND|CONSUMED)"$')
    if len(lines) != 1:
        raise BootstrapError("Missing or malformed G2 lifecycle record")
    match = pattern.fullmatch(lines[0])
    if match is None:
        raise BootstrapError("Missing or malformed G2 lifecycle record")
    return match.group(1)


def _require_g2_bound_declarations(source: bytes) -> None:
    """Require exactly one immutable protected expectation and no alternatives."""
    declarations = (
        f'G2_BOUND_ORIGIN = "{G2_BOUND_ORIGIN}"',
        f'G2_BOUND_CANDIDATE_TREE = "{G2_BOUND_CANDIDATE_TREE}"',
        f'G2_BOUND_WORKFLOW_BLOB = "{G2_BOUND_WORKFLOW_BLOB}"',
        f'G2_BOUND_BOOTSTRAP_BLOB = "{G2_BOUND_BOOTSTRAP_BLOB}"',
        f'G2_BOUND_TEST_BLOB = "{G2_BOUND_TEST_BLOB}"',
        f'G2_BOUND_EXPECTED_TERMINAL = "{G2_BOUND_EXPECTED_TERMINAL}"',
    )
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise BootstrapError("Invalid G2 binding source encoding") from error
    binding_lines = tuple(re.findall(r"^G2_BOUND_[A-Z_]+ = .*?$", text, re.MULTILINE))
    if binding_lines != declarations:
        raise BootstrapError("G2 protected binding is missing, duplicated, or replaced")


def _module_authority_declarations(source: bytes) -> dict[str, str]:
    """Return the closed module-level uppercase declaration schema."""
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"))
    except (UnicodeError, SyntaxError) as error:
        raise BootstrapError("Invalid B3 declaration source") from error
    declarations: dict[str, str] = {}
    for statement in tree.body:
        name: str | None = None
        value: ast.expr | None = None
        if (isinstance(statement, ast.Assign) and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)):
            name, value = statement.targets[0].id, statement.value
        elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            name, value = statement.target.id, statement.value
        if name is None or value is None or not name.isupper():
            continue
        if name in declarations:
            raise BootstrapError("Duplicate B3 authority declaration")
        declarations[name] = ast.dump(value, annotate_fields=True,
                                      include_attributes=False)
    return declarations


def _require_b3_enablement_declaration_schema(
        s1_source: bytes, enablement_source: bytes) -> None:
    """Allow exactly the S1 declarations plus the two frozen B3 declarations."""
    baseline = _module_authority_declarations(s1_source)
    observed = _module_authority_declarations(enablement_source)
    expected = dict(baseline)
    expected.update({
        "B3_AUTHORITY_ORIGIN": ast.dump(
            ast.Constant(B3_AUTHORITY_ORIGIN), annotate_fields=True,
            include_attributes=False),
        "B3_ENABLEMENT": ast.dump(
            ast.Constant(B3_ENABLEMENT), annotate_fields=True,
            include_attributes=False),
    })
    if observed != expected:
        raise BootstrapError(
            "B3 enablement authority declarations differ from the closed S1 schema")


def _exact_modified_paths(root: Path, before: str, after: str) -> tuple[str, ...]:
    output = _git_bytes(root, "diff", "--name-status", "-z", "--no-renames",
                        before, after)
    if not output.endswith(b"\0"):
        raise BootstrapError("Malformed exact-path diff")
    fields = output.removesuffix(b"\0").split(b"\0")
    try:
        records = tuple((fields[index].decode("ascii"), fields[index + 1].decode("utf-8"))
                        for index in range(0, len(fields), 2))
    except (IndexError, UnicodeError) as error:
        raise BootstrapError("Malformed exact-path diff") from error
    if any(status != "M" for status, _path in records):
        raise BootstrapError("Exact binding requires modified regular files")
    return tuple(path for _status, path in records)


def validate_g2_bound_authority(protected_root: Path, protected_sha: str) -> None:
    """Recognize only the immediate protected S0-to-S1 binding merge."""
    protected = _root(protected_root, "protected root")
    revision = _sha(protected_sha, "protected SHA")
    if _git(protected, "rev-parse", "HEAD") != revision:
        raise BootstrapError("G2 bound checkout does not match protected SHA")
    if _git(protected, "rev-parse", "refs/remotes/origin/main") != revision:
        raise BootstrapError("G2 bound checkout is not protected main")
    if _canonical_remote(_git(protected, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("G2 bound protected repository mismatch")
    _require_model_d_history(protected, revision)
    if _g2_generation_was_consumed(protected, revision):
        raise BootstrapError("G2 maintenance generation was permanently consumed")
    validate_protected_universe(protected, revision)
    source = _git_bytes(protected, "show", f"{revision}:protected_policy_bootstrap.py")
    if _g2_lifecycle(source) != "ACTIVE_BOUND":
        raise BootstrapError("G2 protected authority is not ACTIVE_BOUND")
    _require_g2_bound_declarations(source)
    parents = _git(protected, "rev-list", "--parents", "-n", "1", revision).split()
    if len(parents) != 3 or parents[0] != revision or parents[1] != G2_BOUND_ORIGIN:
        raise BootstrapError("G2 S1 is not the exact protected binding merge from S0")
    proposal = parents[2]
    proposal_parents = _git(
        protected, "rev-list", "--parents", "-n", "1", proposal).split()
    if proposal_parents != [proposal, G2_BOUND_ORIGIN]:
        raise BootstrapError("G2 binding proposal is not based directly on S0")
    if (_git(protected, "rev-parse", f"{proposal}^{{tree}}")
            != _git(protected, "rev-parse", f"{revision}^{{tree}}")):
        raise BootstrapError("G2 binding merge tree differs from its proposal")
    before = _git_bytes(protected, "show", f"{G2_BOUND_ORIGIN}:protected_policy_bootstrap.py")
    if _g2_lifecycle(before) != "ACTIVE_UNBOUND" or b"G2_BOUND_ORIGIN = " in before:
        raise BootstrapError("G2 binding was present before S1")
    if _exact_modified_paths(protected, G2_BOUND_ORIGIN, revision) != G2_BINDING_PATHS:
        raise BootstrapError("G2 S1 exceeds the exact binding scope")


def validate_g2_bound_candidate_identity(
        candidate_root: Path, candidate_sha: str,
        protected_root: Path, protected_sha: str) -> None:
    """Validate the frozen B1 identity without granting B3 admission."""
    validate_g2_bound_authority(protected_root, protected_sha)
    candidate = _root(candidate_root, "candidate root")
    revision = _sha(candidate_sha, "candidate SHA")
    if _git(candidate, "rev-parse", "HEAD") != revision:
        raise BootstrapError("Bound candidate checkout does not match candidate SHA")
    if _canonical_remote(_git(candidate, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("Bound candidate repository mismatch")
    parents = _git(candidate, "rev-list", "--parents", "-n", "1", revision).split()
    if len(parents) != 2 or parents != [revision, G2_BOUND_ORIGIN]:
        raise BootstrapError("Bound candidate must have sole parent S0")
    if _git(candidate, "rev-parse", f"{revision}^{{tree}}") != G2_BOUND_CANDIDATE_TREE:
        raise BootstrapError("Bound candidate tree mismatch")
    if _exact_modified_paths(candidate, G2_BOUND_ORIGIN, revision) != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError("Bound candidate paths mismatch")
    entries = _tree_entries(candidate, revision, MODEL_D_MAINTENANCE_PATHS)
    if tuple(entries) != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError("Bound candidate tree paths mismatch")
    for path, expected_blob in G2_EXPECTED_CANDIDATE_BLOBS:
        mode, kind = entries[path]
        if (mode, kind) != ("100644", "blob"):
            raise BootstrapError("Bound candidate paths must be regular blobs")
        if _git(candidate, "rev-parse", f"{revision}:{path}") != expected_blob:
            raise BootstrapError("Bound candidate blob mismatch")
    candidate_source = _git_bytes(
        candidate, "show", f"{revision}:protected_policy_bootstrap.py")
    if _g2_lifecycle(candidate_source) != "CONSUMED":
        raise BootstrapError("Bound candidate must propose terminal CONSUMED")
    if G2_BOUND_EXPECTED_TERMINAL.encode() not in candidate_source:
        raise BootstrapError("Bound candidate terminal disposition mismatch")
    validate_protected_universe(candidate, revision)


def _validate_b1_candidate(candidate: Path, revision: str) -> None:
    """Validate one exact S0-parented B1 object without granting authority."""
    if _git(candidate, "rev-parse", "HEAD") != revision:
        raise BootstrapError("B3 P checkout does not match selected P SHA")
    if _canonical_remote(_git(candidate, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("B3 P repository mismatch")
    if _git(candidate, "cat-file", "-t", revision) != "commit":
        raise BootstrapError("B3 P is not a commit")
    _git_attribution(candidate, revision, "B3 P")
    parents = _git(candidate, "rev-list", "--parents", "-n", "1", revision).split()
    if parents != [revision, G2_BOUND_ORIGIN]:
        raise BootstrapError("B3 P must have sole parent S0")
    if _git(candidate, "rev-parse", f"{revision}^{{tree}}") != G2_BOUND_CANDIDATE_TREE:
        raise BootstrapError("B3 P tree mismatch")
    if _exact_modified_paths(candidate, G2_BOUND_ORIGIN, revision) != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError("B3 P paths mismatch")
    entries = _tree_entries(candidate, revision, MODEL_D_MAINTENANCE_PATHS)
    if tuple(entries) != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError("B3 P tree paths mismatch")
    for path, expected_blob in G2_EXPECTED_CANDIDATE_BLOBS:
        mode, kind = entries[path]
        if (mode, kind) != ("100644", "blob"):
            raise BootstrapError("B3 P paths must be regular 100644 blobs")
        if _git(candidate, "rev-parse", f"{revision}:{path}") != expected_blob:
            raise BootstrapError("B3 P blob mismatch")
    source = _git_bytes(candidate, "show", f"{revision}:protected_policy_bootstrap.py")
    if _g2_lifecycle(source) != "CONSUMED":
        raise BootstrapError("B3 P must propose terminal CONSUMED")
    if G2_BOUND_EXPECTED_TERMINAL.encode() not in source:
        raise BootstrapError("B3 P terminal disposition mismatch")
    validate_protected_universe(candidate, revision)


def validate_b3_enablement_candidate(
        candidate_root: Path, candidate_sha: str,
        protected_root: Path, protected_sha: str) -> None:
    """Validate one proposal that only enables finite DESIGN-B validation."""
    if _sha(protected_sha, "protected SHA") != B3_AUTHORITY_ORIGIN:
        raise BootstrapError("B3 enablement authority must be exact S1")
    validate_g2_bound_authority(protected_root, protected_sha)
    candidate = _root(candidate_root, "B3 enablement candidate root")
    revision = _sha(candidate_sha, "B3 enablement candidate SHA")
    if _git(candidate, "rev-parse", "HEAD") != revision:
        raise BootstrapError("B3 enablement checkout mismatch")
    if _canonical_remote(_git(candidate, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("B3 enablement repository mismatch")
    parents = _git(candidate, "rev-list", "--parents", "-n", "1", revision).split()
    if parents != [revision, B3_AUTHORITY_ORIGIN]:
        raise BootstrapError("B3 enablement must be based directly on exact S1")
    if _exact_modified_paths(candidate, B3_AUTHORITY_ORIGIN, revision) != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError("B3 enablement exceeds the exact three-file scope")
    source = _git_bytes(candidate, "show", f"{revision}:protected_policy_bootstrap.py")
    s1_source = _git_bytes(
        _root(protected_root, "B3 S1 authority root"), "show",
        f"{B3_AUTHORITY_ORIGIN}:protected_policy_bootstrap.py")
    _require_b3_enablement_declaration_schema(s1_source, source)
    if _g2_lifecycle(source) != "ACTIVE_BOUND":
        raise BootstrapError("B3 enablement must remain ACTIVE_BOUND")
    _require_g2_bound_declarations(source)
    marker = f'B3_ENABLEMENT = "{B3_ENABLEMENT}"'.encode()
    if source.split(b"\n").count(marker) != 1:
        raise BootstrapError("B3 enablement marker is missing or duplicated")
    if re.search(rb'^G2_SELECTED_P_SHA\s*=', source, re.MULTILINE):
        raise BootstrapError("B3 enablement must not select P")
    validate_protected_universe(candidate, revision)


def validate_b3_enabled_authority(protected_root: Path, protected_sha: str) -> None:
    """Recognize exactly one protected DESIGN-B enablement merge after S1."""
    protected = _root(protected_root, "B3 protected root")
    revision = _sha(protected_sha, "B3 protected SHA")
    if _git(protected, "rev-parse", "HEAD") != revision:
        raise BootstrapError("B3 protected checkout mismatch")
    if _git(protected, "rev-parse", "refs/remotes/origin/main") != revision:
        raise BootstrapError("B3 validator is not protected main")
    if _canonical_remote(_git(protected, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("B3 protected repository mismatch")
    parents = _git(protected, "rev-list", "--parents", "-n", "1", revision).split()
    if len(parents) != 3 or parents[1] != B3_AUTHORITY_ORIGIN:
        raise BootstrapError("B3 validator is not the finite S1 enablement merge")
    proposal = parents[2]
    if _git(protected, "rev-list", "--parents", "-n", "1", proposal).split() != [proposal, B3_AUTHORITY_ORIGIN]:
        raise BootstrapError("B3 enablement proposal is not based directly on S1")
    if _git(protected, "rev-parse", f"{proposal}^{{tree}}") != _git(protected, "rev-parse", f"{revision}^{{tree}}"):
        raise BootstrapError("B3 enablement merge tree differs from proposal")
    source = _git_bytes(protected, "show", f"{revision}:protected_policy_bootstrap.py")
    s1_source = _git_bytes(
        protected, "show", f"{B3_AUTHORITY_ORIGIN}:protected_policy_bootstrap.py")
    _require_b3_enablement_declaration_schema(s1_source, source)
    if _g2_lifecycle(source) != "ACTIVE_BOUND":
        raise BootstrapError("B3 validator must remain ACTIVE_BOUND")
    _require_g2_bound_declarations(source)
    marker = f'B3_ENABLEMENT = "{B3_ENABLEMENT}"'.encode()
    if source.split(b"\n").count(marker) != 1:
        raise BootstrapError("B3 validator marker is missing or duplicated")
    if _exact_modified_paths(protected, B3_AUTHORITY_ORIGIN, revision) != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError("B3 validator exceeds the finite enablement scope")
    validate_protected_universe(protected, revision)


def _require_b3_corrected_history(root: Path, revision: str) -> None:
    """Recognize only one S2-anchored, purpose-limited correction merge."""
    if _git(root, "cat-file", "-t", revision) != "commit":
        raise BootstrapError("B3 correction checkpoint is not a commit")
    parents = _git(root, "rev-list", "--parents", "-n", "1", revision).split()
    if len(parents) != 3 or parents[1] != B3_CORRECTION_BASE:
        raise BootstrapError("B3 correction must have exact S2 first parent")
    proposal = parents[2]
    if _git(root, "cat-file", "-t", proposal) != "commit":
        raise BootstrapError("B3 correction proposal is not a commit")
    if _git(root, "rev-list", "--parents", "-n", "1", proposal).split() != [
            proposal, B3_CORRECTION_BASE]:
        raise BootstrapError("B3 correction proposal must be a direct S2 child")
    if (_git(root, "rev-parse", f"{proposal}^{{tree}}") !=
            _git(root, "rev-parse", f"{revision}^{{tree}}")):
        raise BootstrapError("B3 correction merge tree differs from proposal")
    if _exact_modified_paths(root, B3_CORRECTION_BASE, revision) != B3_CORRECTION_PATHS:
        raise BootstrapError("B3 correction exceeds its three-file scope")
    before = _git_bytes(root, "show", f"{B3_CORRECTION_BASE}:protected_policy_bootstrap.py")
    source = _git_bytes(root, "show", f"{revision}:protected_policy_bootstrap.py")
    expected = _module_authority_declarations(before)
    for name, value in (
            ("B3_CORRECTION", B3_CORRECTION),
            ("B3_CORRECTION_BASE", B3_CORRECTION_BASE),
            ("B3_CORRECTION_PATHS", B3_CORRECTION_PATHS)):
        expected[name] = ast.dump(ast.parse(repr(value), mode="eval").body,
                                  annotate_fields=True, include_attributes=False)
    if _module_authority_declarations(source) != expected:
        raise BootstrapError("B3 correction authority declarations differ from S2")
    if _g2_lifecycle(source) != "ACTIVE_BOUND":
        raise BootstrapError("B3 correction must remain ACTIVE_BOUND")
    _require_g2_bound_declarations(source)
    for declaration in (
            f'B3_AUTHORITY_ORIGIN = "{B3_AUTHORITY_ORIGIN}"',
            f'B3_ENABLEMENT = "{B3_ENABLEMENT}"',
            f'B3_CORRECTION = "{B3_CORRECTION}"'):
        if source.split(b"\n").count(declaration.encode()) != 1:
            raise BootstrapError("B3 correction marker is missing or duplicated")


def validate_b3_corrected_authority(protected_root: Path, protected_sha: str) -> None:
    """Require the actual protected main to be the unique S2 correction."""
    protected = _root(protected_root, "B3 protected root")
    revision = _sha(protected_sha, "B3 protected SHA")
    if _git(protected, "rev-parse", "HEAD") != revision:
        raise BootstrapError("B3 corrected checkout mismatch")
    if _git(protected, "rev-parse", "refs/remotes/origin/main") != revision:
        raise BootstrapError("B3 corrected validator is not protected main")
    if _canonical_remote(_git(protected, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("B3 corrected repository mismatch")
    _require_b3_corrected_history(protected, revision)
    validate_protected_universe(protected, revision)


def validate_b3_establishment(
        protected_root: Path, protected_sha: str,
        p_root: Path, p_sha: str, e_root: Path, e_sha: str) -> None:
    """Admit one exact P through one deterministic terminal-tree proposal E."""
    validate_b3_corrected_authority(protected_root, protected_sha)
    protected_revision = _sha(protected_sha, "B3 protected SHA")
    selected_p = _sha(p_sha, "selected P SHA")
    proposal = _sha(e_sha, "E SHA")
    p = _root(p_root, "P root")
    e = _root(e_root, "E root")
    protected = _root(protected_root, "B3 protected root")
    roots = (protected, p, e)
    if len(set(roots)) != 3 or any(a.is_relative_to(b) for a in roots for b in roots if a != b):
        raise BootstrapError("B3 protected, P, and E roots must be separate")
    _validate_b1_candidate(p, selected_p)
    if _git(e, "rev-parse", "HEAD") != proposal:
        raise BootstrapError("B3 E checkout does not match E SHA")
    if _canonical_remote(_git(e, "remote", "get-url", "origin")) != REPOSITORY:
        raise BootstrapError("B3 E repository mismatch")
    if _git(e, "cat-file", "-t", proposal) != "commit":
        raise BootstrapError("B3 E is not a commit")
    _git_attribution(e, proposal, "B3 E")
    parents = _git(e, "rev-list", "--parents", "-n", "1", proposal).split()
    if parents != [proposal, protected_revision, selected_p]:
        raise BootstrapError("B3 E ordered parents must be exact S2 and selected P")
    if _git(e, "rev-parse", f"{proposal}^{{tree}}") != G2_BOUND_CANDIDATE_TREE:
        raise BootstrapError("B3 E terminal tree mismatch")
    for path, expected_blob in G2_EXPECTED_CANDIDATE_BLOBS:
        if _git(e, "rev-parse", f"{proposal}:{path}") != expected_blob:
            raise BootstrapError("B3 E terminal blob mismatch")
    source = _git_bytes(e, "show", f"{proposal}:protected_policy_bootstrap.py")
    if _g2_lifecycle(source) != "CONSUMED":
        raise BootstrapError("B3 E must be terminal CONSUMED")
    validate_protected_universe(e, proposal)


def validate_b3_terminal(
        terminal_root: Path, terminal_sha: str, protected_sha: str,
        p_sha: str, e_sha: str) -> None:
    """Prove the actual protected two-parent terminal checkpoint T."""
    terminal = _root(terminal_root, "terminal root")
    revision = _sha(terminal_sha, "terminal SHA")
    enabled = _sha(protected_sha, "B3 protected SHA")
    selected_p = _sha(p_sha, "selected P SHA")
    proposal = _sha(e_sha, "E SHA")
    if (_git(terminal, "rev-parse", "HEAD") != revision
            or _git(terminal, "rev-parse", "refs/remotes/origin/main") != revision):
        raise BootstrapError("B3 terminal checkpoint is not protected main")
    if _git(terminal, "cat-file", "-t", revision) != "commit":
        raise BootstrapError("B3 terminal checkpoint is not a commit")
    if _git(terminal, "rev-list", "--parents", "-n", "1", revision).split() != [revision, enabled, proposal]:
        raise BootstrapError("B3 T ordered parents must be exact S2 and E")
    if _git(terminal, "rev-list", "--parents", "-n", "1", proposal).split() != [proposal, enabled, selected_p]:
        raise BootstrapError("B3 T does not retain exact E and P ancestry")
    _require_b3_corrected_history(terminal, enabled)
    ancestry = subprocess.run(
        ["git", "-C", str(terminal), "merge-base", "--is-ancestor",
         B3_AUTHORITY_ORIGIN, enabled], capture_output=True, check=False)
    if ancestry.returncode != 0:
        raise BootstrapError("B3 S1 ancestry check failed")
    if _git(terminal, "rev-parse", f"{revision}^{{tree}}") != G2_BOUND_CANDIDATE_TREE:
        raise BootstrapError("B3 T terminal tree mismatch")
    source = _git_bytes(terminal, "show", f"{revision}:protected_policy_bootstrap.py")
    if _g2_lifecycle(source) != "CONSUMED":
        raise BootstrapError("B3 T must be terminal CONSUMED")
    validate_protected_universe(terminal, revision)


def validate_model_d_maintenance(
        operation: str, generation: str,
        candidate_root: Path, protected_root: Path,
        candidate_sha: str, protected_sha: str) -> None:
    """Admit one exact Model D operation from one protected generation."""
    if _clean(operation, "maintenance operation") != MODEL_D_MAINTENANCE_OPERATION:
        raise BootstrapError("Unsupported maintenance operation")
    if _clean(generation, "maintenance generation") != MODEL_D_MAINTENANCE_GENERATION:
        raise BootstrapError("Unsupported maintenance generation")
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

    _require_model_d_history(protected, protected_revision)
    if (_model_d_generation_state(protected, protected_revision) != "ACTIVE"
            or _model_d_generation_was_consumed(protected, protected_revision)):
        raise BootstrapError("Model D maintenance generation is not active")

    validate_protected_universe(protected, protected_revision)
    validate_protected_universe(candidate, candidate_revision)
    if extract_candidate_baseline(candidate) != CURRENT_BASELINE:
        raise BootstrapError("Model D maintenance requires the current protected baseline")

    output = _git_bytes(
        candidate, "diff", "--name-status", "-z", "--no-renames",
        protected_revision, candidate_revision,
    )
    _model_d_records(output)
    if _model_d_generation_state(candidate, candidate_revision) != "CONSUMED":
        raise BootstrapError("Model D maintenance candidate must consume the generation")

    for root, revision in ((protected, protected_revision),
                            (candidate, candidate_revision)):
        entries = _tree_entries(root, revision, MODEL_D_MAINTENANCE_PATHS)
        if tuple(entries) != MODEL_D_MAINTENANCE_PATHS:
            raise BootstrapError("Model D maintenance tree paths do not match protected scope")
        if any(identity != ("100644", "blob") for identity in entries.values()):
            raise BootstrapError("Model D maintenance paths must be regular 100644 blobs")


def validate_g2_maintenance(
        generation: str, candidate_root: Path, protected_root: Path,
        candidate_sha: str, protected_sha: str) -> None:
    """Reject substantive use while unbound; allow lifecycle-only revocation.

    The seed PR is established by protected branch governance, never this method.
    The protected checkout must be the merge that first established G2 UNBOUND;
    any subsequent protected-main movement expires this admission surface.
    """
    if generation != G2_MAINTENANCE_GENERATION:
        raise BootstrapError("Unsupported G2 generation")
    candidate_revision = _sha(candidate_sha, "candidate SHA")
    protected_revision = _sha(protected_sha, "protected SHA")
    candidate = _root(candidate_root, "candidate root")
    protected = _root(protected_root, "protected root")
    if (candidate == protected or candidate.is_relative_to(protected)
            or protected.is_relative_to(candidate)):
        raise BootstrapError("Candidate and protected roots must be separate")
    for root, revision, repository in (
            (candidate, candidate_revision, REPOSITORY),
            (protected, protected_revision, REPOSITORY)):
        if _git(root, "rev-parse", "HEAD") != revision:
            raise BootstrapError("G2 checkout does not match authorized SHA")
        if _canonical_remote(_git(root, "remote", "get-url", "origin")) != repository:
            raise BootstrapError("G2 checkout repository mismatch")
    if _git(protected, "rev-parse", "refs/remotes/origin/main") != protected_revision:
        raise BootstrapError("G2 protected checkout is not protected main")
    _require_model_d_history(protected, protected_revision)
    if _g2_generation_was_consumed(protected, protected_revision):
        raise BootstrapError("G2 maintenance generation was permanently consumed")
    validate_protected_universe(protected, protected_revision)
    validate_protected_universe(candidate, candidate_revision)

    active = f'{G2_MAINTENANCE_GENERATION}:ACTIVE_UNBOUND'
    consumed = f'{G2_MAINTENANCE_GENERATION}:CONSUMED'
    protected_source = _git_bytes(
        protected, "show", f"{protected_revision}:protected_policy_bootstrap.py")
    candidate_source = _git_bytes(
        candidate, "show", f"{candidate_revision}:protected_policy_bootstrap.py")
    protected_lifecycle = _g2_lifecycle(protected_source)
    if protected_lifecycle == "ACTIVE_BOUND":
        validate_g2_bound_authority(protected, protected_revision)
        parents = _git(candidate, "rev-list", "--parents", "-n", "1",
                       candidate_revision).split()
        bound = f'{G2_MAINTENANCE_GENERATION}:ACTIVE_BOUND'.encode()
        consumed_value = f'{G2_MAINTENANCE_GENERATION}:CONSUMED'.encode()
        expected_revocation = protected_source.replace(bound, consumed_value)
        paths = _exact_modified_paths(candidate, protected_revision, candidate_revision)
        if (parents == [candidate_revision, protected_revision]
                and paths == ("protected_policy_bootstrap.py",)
                and candidate_source == expected_revocation):
            return
        validate_g2_bound_candidate_identity(
            candidate, candidate_revision, protected, protected_revision)
        raise BootstrapError("B3 admission is not implemented")
    if protected_lifecycle != "ACTIVE_UNBOUND":
        raise BootstrapError("G2 protected authority is not ACTIVE_UNBOUND")
    declaration = f'G2_MAINTENANCE_LIFECYCLE = "{active}"'.encode()
    replacement = f'G2_MAINTENANCE_LIFECYCLE = "{consumed}"'.encode()
    identity = f'G2_MAINTENANCE_GENERATION = "{generation}"'.encode()
    purpose = f'G2_MAINTENANCE_PURPOSE = "{G2_MAINTENANCE_PURPOSE}"'.encode()
    g1_identity = f'MODEL_D_MAINTENANCE_GENERATION = "{MODEL_D_MAINTENANCE_GENERATION}"'.encode()
    g1 = (f'MODEL_D_MAINTENANCE_LIFECYCLE = '
          f'"{MODEL_D_MAINTENANCE_GENERATION}:CONSUMED"').encode()
    for source in (protected_source, candidate_source):
        lines = source.split(b"\n")
        if (lines.count(identity) != 1 or lines.count(purpose) != 1
                or lines.count(g1_identity) != 1 or lines.count(g1) != 1):
            raise BootstrapError("G2 or consumed G1 identity changed")
    g1_workflow = (f"  MODEL_D_MAINTENANCE_GENERATION: "
                   f"{MODEL_D_MAINTENANCE_GENERATION}").encode()
    for root, revision in ((protected, protected_revision),
                           (candidate, candidate_revision)):
        workflow_source = _git_bytes(
            root, "show", f"{revision}:.github/workflows/security-workflows-policy.yml")
        if workflow_source.split(b"\n").count(g1_workflow) != 1:
            raise BootstrapError("Consumed G1 workflow identity changed")
    if protected_source.split(b"\n").count(declaration) != 1:
        raise BootstrapError("G2 is not active in protected source")
    if (candidate_source.split(b"\n").count(replacement) != 1
            or declaration in candidate_source.split(b"\n")):
        raise BootstrapError("G2 candidate must consume the generation")

    parents = _git(protected, "rev-list", "--parents", "-n", "1", protected_revision).split()
    if len(parents) != 3 or parents[0] != protected_revision:
        raise BootstrapError("G2 protected seed must be a merge commit")
    before_seed = _git_bytes(
        protected, "show", f"{parents[1]}:protected_policy_bootstrap.py")
    if (declaration in before_seed or identity in before_seed
            or purpose in before_seed):
        raise BootstrapError("G2 protected seed state has drifted")
    if _git(candidate, "merge-base", protected_revision, candidate_revision) != protected_revision:
        raise BootstrapError("G2 candidate is not based on exact seed state")
    if _git(candidate, "rev-list", "--count", f"{protected_revision}..{candidate_revision}") != "1":
        raise BootstrapError("G2 candidate must contain one commit")

    output = _git_bytes(candidate, "diff", "--name-status", "-z", "--no-renames",
                        protected_revision, candidate_revision)
    try:
        fields = output.removesuffix(b"\0").split(b"\0")
        records = tuple((fields[index].decode("ascii"), fields[index + 1].decode("utf-8"))
                        for index in range(0, len(fields), 2))
    except (IndexError, UnicodeError) as error:
        raise BootstrapError("Malformed G2 maintenance diff") from error
    if not output.endswith(b"\0") or any(status != "M" for status, _ in records):
        raise BootstrapError("G2 maintenance requires modified regular files")
    paths = tuple(path for _, path in records)
    revocation = paths == ("protected_policy_bootstrap.py",)
    if not revocation and paths != MODEL_D_MAINTENANCE_PATHS:
        raise BootstrapError(f"G2 maintenance exceeds exact PUB-01 scope: {paths!r}")
    if revocation and candidate_source != protected_source.replace(declaration, replacement):
        raise BootstrapError("G2 revocation may change only lifecycle state")
    entries = _tree_entries(candidate, candidate_revision, paths)
    if tuple(entries) != paths or any(value != ("100644", "blob") for value in entries.values()):
        raise BootstrapError("G2 maintenance paths must be regular files")
    if not revocation:
        raise BootstrapError("G2 has no independently bound candidate identity")


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
    _emit_fixed_outputs(values, destination, candidate_root, protected_root)


def _validated_model_d_outputs(
        plan: ModelDOrchestrationPlan) -> tuple[tuple[str, str], ...]:
    if type(plan) is not ModelDOrchestrationPlan:
        raise BootstrapError("Invalid Model D output plan")
    plan.__post_init__()
    values = (
        ("normalization-roots", ",".join(root.value for root in plan.normalization_roots)),
        ("policy-lock-source", plan.policy_lock_source.value),
        ("audit-lock-source", plan.audit_lock_source.value),
        ("candidate-evidence", plan.candidate_evidence.value),
        ("protected-evidence", plan.protected_evidence.value),
        ("downstream-validation", plan.downstream_validation.value),
    )
    if tuple(key for key, _ in values) != _MODEL_D_OUTPUT_KEYS:
        raise BootstrapError("Invalid Model D output schema")
    for key, value in values:
        _clean(key, "Model D output key")
        _clean(value, "Model D output value")
    return values


def emit_model_d_output(
        inputs: BootstrapInputs, result: BootstrapResult,
        plan: ModelDOrchestrationPlan, destination: Path) -> None:
    """Emit a fixed plan only after canonical correspondence is re-established."""
    canonical_result, canonical_plan = validate_model_d_plan_correspondence(
        inputs, result, plan)
    values = (_validated_outputs(canonical_result) +
              _validated_model_d_outputs(canonical_plan))
    _emit_fixed_outputs(values, destination, inputs.candidate_root,
                        inputs.protected_root)


def _emit_fixed_outputs(
        values: tuple[tuple[str, str], ...], destination: Path,
        candidate_root: Path, protected_root: Path) -> None:
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


def _git_attribution(root: Path, revision: str, label: str) -> tuple[str, str, str, str]:
    """Read the one intentional NUL-delimited Git identity record."""
    output = _git_bytes(
        root, "show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce", revision)
    if (not output.endswith(b"\n") or output.count(b"\n") != 1 or
            b"\r" in output or output[:-1].count(b"\0") != 3):
        raise BootstrapError(f"{label} attribution is malformed")
    try:
        fields = tuple(field.decode("utf-8", errors="strict")
                       for field in output[:-1].split(b"\0"))
    except UnicodeError as error:
        raise BootstrapError(f"{label} attribution is malformed") from error
    if (len(fields) != 4 or any(not field.strip() for field in fields) or
            any(unicodedata.category(char).startswith("C")
                for field in fields for char in field)):
        raise BootstrapError(f"{label} attribution is malformed")
    return fields  # type: ignore[return-value]


def _git(root: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments], check=True,
            capture_output=True, text=True, encoding="utf-8", errors="strict",
            env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
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
    for operation in ("evaluate", "run-model-d"):
        operation_parser = commands.add_parser(operation)
        for name in (
                "event-name", "repository", "base-repository", "base-branch",
                "candidate-sha", "protected-sha", "candidate-root", "protected-root",
                "event-ref", "default-branch", "workflow-ref"):
            operation_parser.add_argument(
                f"--{name}", required=True, default=None, action=_Once)
    maintenance_parser = commands.add_parser("admit-maintenance")
    for name in (
            "maintenance-operation", "maintenance-generation",
            "candidate-sha", "protected-sha",
            "candidate-root", "protected-root"):
        maintenance_parser.add_argument(
            f"--{name}", required=True, default=None, action=_Once)
    b3_parser = commands.add_parser("admit-b3")
    for name in ("protected-sha", "protected-root", "p-sha", "p-root", "e-sha", "e-root"):
        b3_parser.add_argument(f"--{name}", required=True, default=None, action=_Once)
    terminal_parser = commands.add_parser("prove-b3-terminal")
    for name in ("terminal-sha", "terminal-root", "protected-sha", "p-sha", "e-sha"):
        terminal_parser.add_argument(f"--{name}", required=True, default=None, action=_Once)
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
        if arguments.operation == "admit-b3":
            validate_b3_establishment(
                Path(arguments.protected_root), arguments.protected_sha,
                Path(arguments.p_root), arguments.p_sha,
                Path(arguments.e_root), arguments.e_sha)
            return 0
        if arguments.operation == "prove-b3-terminal":
            validate_b3_terminal(
                Path(arguments.terminal_root), arguments.terminal_sha,
                arguments.protected_sha, arguments.p_sha, arguments.e_sha)
            return 0
        if arguments.operation == "admit-maintenance":
            if arguments.maintenance_generation == G2_MAINTENANCE_GENERATION:
                if arguments.maintenance_operation != MODEL_D_MAINTENANCE_OPERATION:
                    raise BootstrapError("Unsupported G2 maintenance operation")
                validate_g2_maintenance(
                    arguments.maintenance_generation,
                    Path(arguments.candidate_root), Path(arguments.protected_root),
                    arguments.candidate_sha, arguments.protected_sha,
                )
            else:
                validate_model_d_maintenance(
                    arguments.maintenance_operation,
                    arguments.maintenance_generation,
                    Path(arguments.candidate_root), Path(arguments.protected_root),
                    arguments.candidate_sha, arguments.protected_sha,
                )
            return 0
        if arguments.operation not in {"evaluate", "run-model-d"}:
            raise BootstrapError("Unsupported bootstrap operation")
        inputs = _cli_inputs(arguments)
        if arguments.operation == "run-model-d":
            result, plan = normalize_and_validate_model_d_bytes(inputs)
        else:
            result = evaluate(inputs)
        validate_protected_universe(inputs.protected_root, inputs.protected_sha)
        raw_destination = os.environ.get("GITHUB_OUTPUT")
        if raw_destination is None:
            raise BootstrapError("GITHUB_OUTPUT is required")
        if arguments.operation == "run-model-d":
            emit_model_d_output(inputs, result, plan, Path(raw_destination))
        else:
            emit_github_output(
                result, Path(raw_destination), inputs.candidate_root, inputs.protected_root)
    except BootstrapError as error:
        print(f"bootstrap error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
