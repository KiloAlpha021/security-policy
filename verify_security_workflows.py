"""Independent policy for proposed KiloAlpha021/security-workflows revisions."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

TARGET = "KiloAlpha021/security-workflows"
POLICY = "KiloAlpha021/security-policy"
BASE_BRANCH = "main"
SHA = re.compile(r"[0-9a-f]{40}\Z")
ACTION = re.compile(r"(?m)^\s*-\s*uses:\s*([^\s#]+)")
IDENTITY = re.compile(r"([0-9a-f]{40})  (.+)\Z")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise ValueError(f"Git identity check failed: {args[0]}")
    return result.stdout.strip()


def repository(root: Path) -> str:
    url = urlparse(git(root, "remote", "get-url", "origin"))
    if url.scheme != "https" or url.hostname != "github.com" or url.username:
        raise ValueError("Unexpected repository remote")
    return url.path.removeprefix("/").removesuffix(".git")


def require(text: str, fragment: str, message: str) -> None:
    if fragment not in text:
        raise ValueError(message)


def verify(
    candidate: Path,
    policy: Path,
    event_repository: str,
    candidate_sha: str,
    base_repository: str,
    base_branch: str,
    event_name: str,
) -> None:
    candidate = candidate.resolve(strict=True)
    policy = policy.resolve(strict=True)
    if candidate == policy or candidate in policy.parents or policy in candidate.parents:
        raise ValueError("Candidate and policy roots must be separate")
    if event_repository != TARGET or base_repository != TARGET:
        raise ValueError("Unsupported candidate repository")
    if base_branch != BASE_BRANCH:
        raise ValueError("Unsupported protected base branch")
    if event_name not in {"pull_request", "merge_group"}:
        raise ValueError("Unsupported policy event")
    if not SHA.fullmatch(candidate_sha):
        raise ValueError("Invalid candidate SHA")
    if repository(candidate) != TARGET or repository(policy) != POLICY:
        raise ValueError("Repository checkout identity mismatch")
    if git(candidate, "rev-parse", "HEAD") != candidate_sha:
        raise ValueError("Candidate checkout does not match event SHA")
    if git(policy, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("Independent policy history is unavailable")

    workflow = (candidate / ".github/workflows/m1-trusted.yml").read_text(encoding="utf-8")
    verifier = (candidate / "verify_candidate.py").read_text(encoding="utf-8")
    identities = (candidate / "trusted-git-blobs.txt").read_text(encoding="utf-8")
    tests = (candidate / "test_verify_candidate.py").read_text(encoding="utf-8")
    validate_workflow(workflow)
    validate_verifier(verifier)
    validate_identities(identities)
    validate_tests(tests)


def validate_workflow(text: str) -> None:
    if "pull_request_target" in text:
        raise ValueError("Unsafe pull_request_target trigger")
    if re.search(r"(?m)^name:\s*trusted-m1-evaluator\s*$", text) is None:
        raise ValueError("Trusted workflow identity changed")
    require(text, "pull_request:", "Pull-request trigger removed")
    require(text, "merge_group:", "Merge-group trigger removed")
    require(text, "permissions:\n  contents: read", "Workflow permissions are not least privilege")
    if re.search(r"(?mi)^\s*[a-z_-]+:\s*write\s*$", text):
        raise ValueError("Write-capable workflow permission")
    actions = ACTION.findall(text)
    if not actions or any(re.search(r"@[0-9a-f]{40}\Z", item) is None for item in actions):
        raise ValueError("Action reference is not a full commit SHA")
    for fragment, message in (
        ("repository: ${{ github.repository }}", "Event repository candidate checkout removed"),
        ("ref: ${{ github.sha }}", "Exact candidate checkout removed"),
        ("path: candidate", "Candidate root removed"),
        ("repository: KiloAlpha021/security-workflows", "Independent trusted checkout removed"),
        ("ref: main", "Protected trusted ref removed"),
        ("path: trusted", "Trusted root removed"),
        ("EVENT_REPOSITORY: ${{ github.repository }}", "Repository dispatch input removed"),
        ("CANDIDATE_SHA: ${{ github.sha }}", "Candidate SHA input removed"),
        ("python trusted/verify_candidate.py", "Independent validator execution removed"),
        ("working-directory: candidate", "Candidate-scoped validation removed"),
        ("python -m pip check", "Dependency identity check removed"),
        ("python -m ruff check", "Ruff check removed"),
        ("python -m mypy", "Strict mypy check removed"),
        ("python -m coverage run", "Coverage test execution removed"),
        ("tests/test_closure_security.py", "Security/provenance controls removed"),
        ("python -m pip_audit --local", "Dependency audit removed"),
    ):
        require(text, fragment, message)
    if re.search(r"(?m)^\s*if:\s*.*", text):
        raise ValueError("Critical workflow steps may not be conditional")


def validate_verifier(text: str) -> None:
    for fragment, message in (
        ('CANDIDATE_REPOSITORY = "KiloAlpha021/automated-trading-bot"', "Trading target removed"),
        ('TRUSTED_REPOSITORY = "KiloAlpha021/security-workflows"', "Trusted target removed"),
        ("SUPPORTED_REPOSITORIES", "Explicit repository dispatch removed"),
        ("if event_repository not in SUPPORTED_REPOSITORIES", "Unknown repository is not fail closed"),
        ("repository(candidate) != event_repository", "Candidate repository binding removed"),
        ("Candidate checkout does not match event SHA", "Candidate SHA verification removed"),
        ("Candidate and trusted roots must be separate", "Root separation removed"),
        ("Trusted M1 control mismatch", "Trusted blob mismatch rejection removed"),
        ("Malformed trusted identity", "Malformed identity rejection removed"),
        ("Unsafe or duplicate trusted identity", "Duplicate identity rejection removed"),
    ):
        require(text, fragment, message)


def validate_identities(text: str) -> None:
    seen: set[str] = set()
    for line in text.splitlines():
        match = IDENTITY.fullmatch(line)
        if match is None:
            raise ValueError("Malformed trusted identity")
        _, name = match.groups()
        path = PurePosixPath(name)
        if name in seen or path.is_absolute() or ".." in path.parts or "\\" in name:
            raise ValueError("Unsafe or duplicate trusted identity")
        seen.add(name)
    required = {"pyproject.toml", "tests/test_architecture.py", "tests/test_m1_completion.py"}
    if not required <= seen:
        raise ValueError("Critical trading identity removed")


def validate_tests(text: str) -> None:
    for fragment in (
        "test_valid_candidate_and_protected_controls",
        "test_reversed_roots_fail",
        "test_wrong_candidate_sha_fails",
        "test_unknown_repository_fails",
        "test_malformed_identity_fails",
    ):
        require(text, fragment, "Critical adversarial verifier test removed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--event-repository", required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--base-repository", required=True)
    parser.add_argument("--base-branch", required=True)
    parser.add_argument("--event-name", required=True)
    args = parser.parse_args()
    verify(args.candidate, args.policy, args.event_repository, args.candidate_sha,
           args.base_repository, args.base_branch, args.event_name)
    print("Exact security-workflows candidate passed independent root policy")


if __name__ == "__main__":
    main()
