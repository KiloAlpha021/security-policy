from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from verify_security_workflows import validate_workflow, verify


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


class RootPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.candidate = base / "candidate"
        self.policy = base / "policy"
        for root, branch, remote in (
            (self.candidate, "main", "security-workflows"),
            (self.policy, "main", "security-policy"),
        ):
            root.mkdir()
            git(root, "init", "-b", branch)
            git(root, "config", "user.name", "Policy Test")
            git(root, "config", "user.email", "policy@example.invalid")
            git(root, "remote", "add", "origin", f"https://github.com/KiloAlpha021/{remote}.git")
        self._write_good_candidate()
        (self.policy / "policy.txt").write_text("independent\n", encoding="utf-8")
        git(self.policy, "add", ".")
        git(self.policy, "commit", "-m", "policy")
        self._commit_candidate("candidate")

    def _write_good_candidate(self) -> None:
        workflow = '''name: trusted-m1-evaluator
on:
  pull_request:
  merge_group:
permissions:
  contents: read
jobs:
  trusted-m1-evaluator:
    name: trusted-m1-evaluator
    steps:
      - name: Check out candidate
        uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          repository: ${{ github.repository }}
          ref: ${{ github.sha }}
          path: candidate
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          repository: KiloAlpha021/security-workflows
          ref: main
          path: trusted
      - name: verify
        env:
          EVENT_REPOSITORY: ${{ github.repository }}
          CANDIDATE_SHA: ${{ github.sha }}
        run: python trusted/verify_candidate.py
      - name: checks
        working-directory: candidate
        run: |
          python -m pip check
          python -m ruff check src tests scripts
          python -m mypy src/automated_trading_bot
          python -m coverage run --source=automated_trading_bot -m pytest -q
          python -m pytest -q tests/test_closure_security.py
          python -m pip_audit --local
'''
        verifier = '''CANDIDATE_REPOSITORY = "KiloAlpha021/automated-trading-bot"
TRUSTED_REPOSITORY = "KiloAlpha021/security-workflows"
SUPPORTED_REPOSITORIES = {CANDIDATE_REPOSITORY, TRUSTED_REPOSITORY}
def verify(candidate, trusted, event_repository, candidate_sha):
    if event_repository not in SUPPORTED_REPOSITORIES: raise ValueError()
    if repository(candidate) != event_repository: raise ValueError()
    if head(candidate) != candidate_sha: raise ValueError("Candidate checkout does not match event SHA")
    if candidate == trusted: raise ValueError("Candidate and trusted roots must be separate")
    raise ValueError("Trusted M1 control mismatch")
def identities(line):
    raise ValueError("Malformed trusted identity")
def duplicate():
    raise ValueError("Unsafe or duplicate trusted identity")
'''
        tests = "\n".join(f"def {name}(): pass" for name in (
            "test_valid_candidate_and_protected_controls", "test_reversed_roots_fail",
            "test_wrong_candidate_sha_fails", "test_unknown_repository_fails",
            "test_malformed_identity_fails"))
        identities = "\n".join((
            "1" * 40 + "  pyproject.toml",
            "2" * 40 + "  tests/test_architecture.py",
            "3" * 40 + "  tests/test_m1_completion.py",
        )) + "\n"
        files = {
            ".github/workflows/m1-trusted.yml": workflow,
            "verify_candidate.py": verifier,
            "test_verify_candidate.py": tests,
            "trusted-git-blobs.txt": identities,
        }
        for name, content in files.items():
            path = self.candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    def _commit_candidate(self, message: str) -> None:
        git(self.candidate, "add", ".")
        git(self.candidate, "commit", "-m", message)
        self.sha = git(self.candidate, "rev-parse", "HEAD")

    def check(self, **overrides: object) -> None:
        values = dict(candidate=self.candidate, policy=self.policy,
                      event_repository="KiloAlpha021/security-workflows",
                      candidate_sha=self.sha,
                      base_repository="KiloAlpha021/security-workflows",
                      base_branch="main", event_name="pull_request")
        values.update(overrides)
        verify(**values)  # type: ignore[arg-type]

    def mutate(self, path: str, old: str, new: str = "") -> None:
        target = self.candidate / path
        text = target.read_text(encoding="utf-8")
        self.assertIn(old, text)
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
        self._commit_candidate("mutation")

    def test_good_candidate(self) -> None:
        self.check()

    def test_named_step_full_sha_is_accepted(self) -> None:
        workflow = (self.candidate / ".github/workflows/m1-trusted.yml").read_text()
        workflow = workflow.replace("actions/checkout@" + "1" * 40,
                                    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2", 1)
        validate_workflow(workflow)

    def test_named_step_invalid_action_refs_are_rejected(self) -> None:
        workflow = (self.candidate / ".github/workflows/m1-trusted.yml").read_text()
        full_ref = "actions/checkout@" + "1" * 40
        for invalid in ("actions/checkout@main", "actions/checkout@v4",
                        "actions/checkout@" + "1" * 39,
                        full_ref + " extra", "actions/checkout@",
                        "actions/checkout"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError, "Action reference is not a full commit SHA"
            ):
                validate_workflow(workflow.replace(full_ref, invalid, 1))

    def test_exact_candidate_identity(self) -> None:
        for kwargs in ({"candidate_sha": "0" * 40}, {"event_repository": "KiloAlpha021/other"},
                       {"base_repository": "KiloAlpha021/other"}, {"base_branch": "dev"},
                       {"event_name": "push"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): self.check(**kwargs)

    def test_roots_reversed(self) -> None:
        with self.assertRaises(ValueError): self.check(candidate=self.policy, policy=self.candidate)

    def test_mutations_fail_closed(self) -> None:
        cases = json.loads((Path(__file__).parent / "fixtures/mutations/cases.json").read_text())
        mutations = {
            "removed_trusted_blob_validation": ("verify_candidate.py", "Trusted M1 control mismatch", "ignored"),
            "unknown_repository_accepted": ("verify_candidate.py", "if event_repository not in SUPPORTED_REPOSITORIES", "if False"),
            "floating_action_ref": (".github/workflows/m1-trusted.yml", "@1111111111111111111111111111111111111111", "@v4"),
            "write_capable_permissions": (".github/workflows/m1-trusted.yml", "contents: read", "contents: write"),
            "candidate_sha_verification_removed": ("verify_candidate.py", "Candidate checkout does not match event SHA", "ignored"),
            "candidate_trusted_roots_reversed": (".github/workflows/m1-trusted.yml", "path: candidate", "path: wrong"),
            "ruff_removed": (".github/workflows/m1-trusted.yml", "python -m ruff check", "echo ruff"),
            "mypy_removed": (".github/workflows/m1-trusted.yml", "python -m mypy", "echo mypy"),
            "pytest_coverage_removed": (".github/workflows/m1-trusted.yml", "python -m coverage run", "echo coverage"),
            "pip_audit_removed": (".github/workflows/m1-trusted.yml", "python -m pip_audit --local", "echo audit"),
            "security_provenance_removed": (".github/workflows/m1-trusted.yml", "tests/test_closure_security.py", "tests/test_smoke.py"),
            "critical_step_conditional": (".github/workflows/m1-trusted.yml", "      - name: checks", "      - name: checks\n        if: false"),
            "workflow_identity_replaced": (".github/workflows/m1-trusted.yml", "name: trusted-m1-evaluator", "name: trivial-success"),
            "repository_dispatch_weakened": ("verify_candidate.py", "if event_repository not in SUPPORTED_REPOSITORIES", "if False"),
            "malformed_trusted_identity_accepted": ("trusted-git-blobs.txt", "1" * 40 + "  pyproject.toml", "invalid"),
        }
        self.assertEqual(set(cases), set(mutations))
        for name in cases:
            with self.subTest(name=name):
                self.tearDown(); self.setUp()
                self.mutate(*mutations[name])
                with self.assertRaises(ValueError): self.check()


if __name__ == "__main__":
    unittest.main()
