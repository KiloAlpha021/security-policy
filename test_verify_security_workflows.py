from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import ast
import base64
from dataclasses import replace
from pathlib import Path
from unittest import mock

import yaml

from verify_security_workflows import action_references, validate_verifier, verify
import protected_policy_bootstrap as bootstrap


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


class RootPolicyTests(unittest.TestCase):
    BASELINE_VERSION = "SECURITY-POLICY-BASELINE-1"
    POLICY_REPOSITORY = "KiloAlpha021/security-policy"

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
      - uses: actions/checkout@1111111111111111111111111111111111111111
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

    def test_structural_action_references(self) -> None:
        workflow = (self.candidate / ".github/workflows/m1-trusted.yml").read_text()
        sha = "1" * 40
        refs = action_references(workflow)
        self.assertEqual([ref for _, ref in refs], [f"actions/checkout@{sha}"] * 2)
        named = workflow.replace("- uses: actions/checkout@", "- name: checkout\n        uses: actions/checkout@")
        self.assertEqual([ref for _, ref in action_references(named)], [f"actions/checkout@{sha}"] * 2)
        quoted = workflow.replace("- uses: actions/checkout@", "- uses: \"actions/checkout@")
        quoted = quoted.replace(sha + "\n", sha + "\"\n")
        self.assertEqual([ref for _, ref in action_references(quoted)], [f"actions/checkout@{sha}"] * 2)
        escaped_key = workflow.replace("- uses:", '- "\\u0075ses":', 1)
        self.assertEqual([ref for _, ref in action_references(escaped_key)], [f"actions/checkout@{sha}"] * 2)
        reusable = workflow.replace("    steps:\n", f"    uses: KiloAlpha021/security-policy/.github/workflows/evaluator.yml@{sha}\n    steps:\n", 1)
        self.assertEqual(len(action_references(reusable)), 3)
        block = f"jobs:\n  audit:\n    steps:\n      - uses: >-\n          actions/checkout@{sha}\n"
        self.assertEqual(action_references(block)[0][1], f"actions/checkout@{sha}")
        flow = f"jobs: {{audit: {{steps: [{{uses: actions/checkout@{sha}}}]}}}}"
        self.assertEqual(action_references(flow)[0][1], f"actions/checkout@{sha}")
        escaped_value = f'jobs:\n  audit:\n    steps:\n      - uses: "actions/checkout@\\u0031{sha[1:]}"\n'
        self.assertEqual(action_references(escaped_value)[0][1], f"actions/checkout@{sha}")

    def test_independent_whole_tree_uses_oracle(self) -> None:
        workflow = (self.candidate / ".github/workflows/m1-trusted.yml").read_text()
        sha = "1" * 40
        workflow = workflow.replace("- uses: actions/checkout@", '- "\\u0075ses": actions/checkout@', 1)
        workflow = workflow.replace("    steps:\n", f"    uses: KiloAlpha021/security-policy/.github/workflows/evaluator.yaml@{sha}\n    steps:\n", 1)
        root = yaml.compose(workflow, Loader=yaml.BaseLoader)
        observed: list[tuple[tuple[object, ...], str]] = []

        def walk(node: yaml.Node, path: tuple[object, ...]) -> None:
            if isinstance(node, yaml.MappingNode):
                for key, value in node.value:
                    assert isinstance(key, yaml.ScalarNode)
                    child_path = (*path, key.value)
                    if key.value == "uses":
                        assert isinstance(value, yaml.ScalarNode)
                        observed.append((child_path, value.value))
                    walk(value, child_path)
            elif isinstance(node, yaml.SequenceNode):
                for index, value in enumerate(node.value):
                    walk(value, (*path, index))

        assert root is not None
        walk(root, ())
        self.assertEqual(len(observed), 3)
        self.assertCountEqual(action_references(workflow), observed)

    def _stage_a_contract(self, root: Path) -> None:
        workflow_path = root / ".github/workflows/security-workflows-policy.yml"
        text = workflow_path.read_text(encoding="utf-8")
        syntax = yaml.compose(text, Loader=yaml.BaseLoader)
        self.assertIsInstance(syntax, yaml.MappingNode)
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow["on"]), {"pull_request", "merge_group", "workflow_dispatch"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(workflow["env"], {
            "POLICY_BASELINE_VERSION": self.BASELINE_VERSION,
            "MODEL_D_MAINTENANCE_GENERATION":
                bootstrap.MODEL_D_MAINTENANCE_GENERATION,
        })
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("GITHUB_ENV", text)

        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        names = [step["name"] for step in steps]
        expected = [
            "Check out exact candidate", "Check out independent root policy", "Set up CPython",
            "Assert exact CPython runtime", "Acquire protected Git identity",
            "Resolve protected bootstrap authority", "Assert protected bootstrap outputs",
            "Enforce exact Model D maintenance admission",
            "Resolve protected Model D orchestration", "Assert protected Model D outputs",
            "Install isolated hash-locked policy environment", "Run candidate Stage A evidence",
            "Run legacy protected health", "Apply protected Stage A baseline to candidate target",
            "Test independent root policy", "Install isolated hash-locked audit environment",
            "Audit locked policy dependencies", "Validate downstream security workflows",
        ]
        self.assertEqual(names, expected)
        by_name = {step["name"]: step for step in steps}

        candidate = by_name["Check out exact candidate"]
        protected = by_name["Check out independent root policy"]
        self.assertEqual(candidate["with"], {
            "repository": "${{ github.repository }}", "ref": "${{ github.sha }}",
            "fetch-depth": "0", "path": "candidate",
        })
        self.assertEqual(protected["with"], {
            "repository": self.POLICY_REPOSITORY, "ref": "main",
            "fetch-depth": "0", "path": "policy",
        })
        self.assertEqual(by_name["Set up CPython"]["with"]["python-version"], "3.12.10")
        self.assertEqual(by_name["Acquire protected Git identity"]["id"], "protected-git")

        bootstrap_step = by_name["Resolve protected bootstrap authority"]
        self.assertEqual(bootstrap_step["id"], "protected-bootstrap")
        bootstrap_run = bootstrap_step["run"]
        bootstrap_command = 'python -I -S "${{ github.workspace }}/policy/protected_policy_bootstrap.py"'
        self.assertEqual(bootstrap_run.count(bootstrap_command), 1)
        preparation_run, invocation = bootstrap_run.split(bootstrap_command, 1)
        self.assertEqual(preparation_run, """$ErrorActionPreference = 'Stop'
$candidateRoot = "${{ github.workspace }}/candidate"
$candidateSha = "${{ github.sha }}"
git -C $candidateRoot config core.autocrlf false
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git -C $candidateRoot reset --hard $candidateSha
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$observedHead = (git -C $candidateRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($observedHead -ne $candidateSha) { throw 'Candidate HEAD differs from authorized candidate SHA' }
$workflowPath = '.github/workflows/security-workflows-policy.yml'
$expectedBlob = (git -C $candidateRoot rev-parse "${candidateSha}:$workflowPath").Trim()
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($expectedBlob -notmatch '^[0-9a-f]{40}$') { throw 'Malformed committed candidate workflow blob' }
$actualBlob = (git -C $candidateRoot hash-object --no-filters $workflowPath).Trim()
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($actualBlob -ne $expectedBlob) { throw 'Candidate workflow bytes differ from exact committed Git blob' }
""")
        self.assertNotIn('${{ github.workspace }}/policy', preparation_run)
        self.assertTrue(invocation.startswith(" evaluate "))
        self.assertEqual(names.index("Resolve protected bootstrap authority"),
                         names.index("Acquire protected Git identity") + 1)
        self.assertIn('python -I -S "${{ github.workspace }}/policy/protected_policy_bootstrap.py" evaluate', bootstrap_run)
        self.assertNotIn("candidate/protected_policy_bootstrap.py", bootstrap_run)
        for argument in (
            "--event-name", "--repository", "--base-repository", "--base-branch",
            "--candidate-sha", "--protected-sha", "--candidate-root", "--protected-root",
            "--event-ref", "--default-branch", "--workflow-ref",
        ):
            self.assertEqual(bootstrap_run.count(argument), 1)
        self.assertIn('--protected-sha "${{ steps.protected-git.outputs.protected-sha }}"', bootstrap_run)
        self.assertIn('--candidate-root "${{ github.workspace }}/candidate"', bootstrap_run)
        self.assertIn('--protected-root "${{ github.workspace }}/policy"', bootstrap_run)

        output_step = by_name["Assert protected bootstrap outputs"]
        self.assertEqual(output_step["env"], {
            "EVALUATION_CONTEXT": "${{ steps.protected-bootstrap.outputs.evaluation-context }}",
            "POLICY_SOURCE": "${{ steps.protected-bootstrap.outputs.policy-source }}",
            "VERSION_DISPOSITION": "${{ steps.protected-bootstrap.outputs.version-disposition }}",
            "OWNER_AUTHORIZATION": "${{ steps.protected-bootstrap.outputs.owner-authorization }}",
            "POST_MERGE_PROOF": "${{ steps.protected-bootstrap.outputs.post-merge-proof }}",
        })
        for fragment in (
            "SELF_PR_BOOTSTRAP", "STAGE_A_PROTECTED_PROOF", "DOWNSTREAM_SECURITY_WORKFLOWS",
            "SAME_VERSION", "IMMEDIATE_SUCCESSOR", "OWNER_AUTHORIZATION -ne 'REQUIRED'",
            "POST_MERGE_PROOF -ne 'REQUIRED'",
        ):
            self.assertIn(fragment, output_step["run"])

        admission = by_name["Enforce exact Model D maintenance admission"]
        self.assertEqual(admission["if"], "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP'")
        for fragment in (
            'python -I -S "${{ github.workspace }}/policy/protected_policy_bootstrap.py"',
            "admit-maintenance", "--maintenance-operation MODEL_D_ORCHESTRATION_V1",
            '--candidate-sha "${{ github.sha }}"',
            '--protected-sha "${{ steps.protected-git.outputs.protected-sha }}"',
            '--candidate-root "${{ github.workspace }}/candidate"',
            '--protected-root "${{ github.workspace }}/policy"',
            "$LASTEXITCODE -ne 0",
        ):
            self.assertIn(fragment, admission["run"])
        self.assertNotIn("candidate/protected_policy_bootstrap.py", admission["run"])
        self.assertNotIn("1211595f9b0b5d1e76dd892bb210fece54f24b53", admission["run"])

        model_d = by_name["Resolve protected Model D orchestration"]
        self.assertEqual(model_d["id"], "protected-model-d")
        self.assertIn('policy/protected_policy_bootstrap.py" run-model-d', model_d["run"])
        self.assertNotIn('candidate/protected_policy_bootstrap.py', model_d["run"])
        self.assertLess(names.index("Enforce exact Model D maintenance admission"),
                        names.index("Resolve protected Model D orchestration"))
        asserted_plan = by_name["Assert protected Model D outputs"]
        self.assertEqual(asserted_plan["env"]["NORMALIZATION_ROOTS"],
                         "${{ steps.protected-model-d.outputs.normalization-roots }}")
        self.assertIn("Protected Model D outputs differ from D0 authority", asserted_plan["run"])

        context_ref = "steps.protected-bootstrap.outputs.evaluation-context"
        candidate_ref = "steps.protected-model-d.outputs.candidate-evidence"
        protected_ref = "steps.protected-model-d.outputs.protected-evidence"
        downstream_ref = "steps.protected-model-d.outputs.downstream-validation"
        self.assertEqual(by_name["Run candidate Stage A evidence"]["if"],
                         f"{candidate_ref} == 'RUN_CANDIDATE_STAGE_A_EVIDENCE'")
        self.assertEqual(by_name["Run legacy protected health"]["if"],
                         f"{protected_ref} == 'RUN_LEGACY_PROTECTED_HEALTH'")
        self.assertEqual(by_name["Apply protected Stage A baseline to candidate target"]["if"],
                         f"{protected_ref} == 'APPLY_PROTECTED_STAGE_A_TO_CANDIDATE'")
        self.assertEqual(
            by_name["Apply protected Stage A baseline to candidate target"]["env"]["POLICY_EXPECTED_PROTECTED_SHA"],
            "${{ steps.protected-git.outputs.protected-sha }}",
        )
        self.assertEqual(by_name["Test independent root policy"]["if"],
                         f"{protected_ref} == 'TEST_INDEPENDENT_ROOT_POLICY'")
        self.assertEqual(by_name["Validate downstream security workflows"]["if"],
                         f"{downstream_ref} == 'RUN_DOWNSTREAM_VALIDATION'")

        for name, output, lock in (
                ("Install isolated hash-locked policy environment", "policy-lock-source", "requirements-policy.lock"),
                ("Install isolated hash-locked audit environment", "audit-lock-source", "requirements-audit.lock"),
                ("Audit locked policy dependencies", "policy-lock-source", "requirements-policy.lock")):
            self.assertNotIn("env", by_name[name])
            self.assertIn(f"${{{{ steps.protected-model-d.outputs.{output} }}}}/{lock}",
                          by_name[name]["run"])
        self.assertNotIn("env.EVALUATION_CONTEXT", text)
        self.assertNotIn("env.POLICY_SOURCE", text)

        self.assertNotIn("Normalize and verify committed policy bytes", by_name)
        self.assertNotIn("foreach ($root in @('candidate', 'policy'))", text)
        policy_install = by_name["Install isolated hash-locked policy environment"]["run"]
        audit_install = by_name["Install isolated hash-locked audit environment"]["run"]
        for run, expected in ((policy_install, "6.0.3"), (audit_install, "'pip-audit') == '2.10.1'")):
            self.assertIn("--require-hashes", run)
            self.assertIn("--only-binary=:all:", run)
            self.assertIn("-m pip check", run)
            self.assertIn(expected, run)
        self.assertIn("policy/test_verify_security_workflows.py", by_name["Apply protected Stage A baseline to candidate target"]["run"])
        self.assertNotIn("candidate/test_verify_security_workflows.py", text)
        self.assertIn("policy/verify_security_workflows.py --candidate candidate",
                      by_name["Validate downstream security workflows"]["run"])
        for step in steps:
            if "run" in step:
                self.assertIn("$ErrorActionPreference = 'Stop'", step["run"])
                if step["name"] not in ("Assert protected bootstrap outputs", "Assert protected Model D outputs"):
                    self.assertIn("$LASTEXITCODE -ne 0", step["run"])

    def test_policy_dependency_workflow_contract(self) -> None:
        root = Path(os.environ.get("POLICY_CONTRACT_TARGET", Path(__file__).parent))
        self._stage_a_contract(root)
        original = (root / ".github/workflows/security-workflows-policy.yml").read_text(encoding="utf-8")
        mutations = (
            ("POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1", "POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-2"),
            ('python -I -S "${{ github.workspace }}/policy/protected_policy_bootstrap.py"',
             'python -I -S "${{ github.workspace }}/candidate/protected_policy_bootstrap.py"'),
            ("id: protected-bootstrap", "id: candidate-bootstrap"),
            ("steps.protected-bootstrap.outputs.evaluation-context", "env.EVALUATION_CONTEXT"),
            ("steps.protected-bootstrap.outputs.policy-source", "env.POLICY_SOURCE"),
            ("OWNER_AUTHORIZATION -ne 'REQUIRED'", "OWNER_AUTHORIZATION -eq 'OPTIONAL'"),
            ("POST_MERGE_PROOF -ne 'REQUIRED'", "POST_MERGE_PROOF -eq 'OPTIONAL'"),
            ("admit-maintenance", "unknown-maintenance"),
            ("--maintenance-operation MODEL_D_ORCHESTRATION_V1",
             "--maintenance-operation CANDIDATE_SELECTED"),
            ('"${{ github.workspace }}/policy/protected_policy_bootstrap.py" admit-maintenance',
             '"${{ github.workspace }}/candidate/protected_policy_bootstrap.py" admit-maintenance'),
            ("config core.autocrlf false", "config core.autocrlf true"),
            ("reset --hard $candidateSha", "reset --hard HEAD"),
            ("hash-object --no-filters $workflowPath", "hash-object $workflowPath"),
            ("if ($actualBlob -ne $expectedBlob)", "if ($actualBlob -eq $expectedBlob)"),
            ('$candidateSha = "${{ github.sha }}"',
             '$candidateSha = "${{ github.event.pull_request.head.sha }}"'),
            (" --require-hashes", ""), (" --only-binary=:all:", ""),
            ("policy/test_verify_security_workflows.py", "candidate/test_verify_security_workflows.py"),
            ("policy/verify_security_workflows.py", "candidate/verify_security_workflows.py"),
            ("$ErrorActionPreference = 'Stop'", "$ErrorActionPreference = 'Continue'"),
        )
        for old, new in mutations:
            with self.subTest(old=old, new=new):
                changed = original.replace(old, new, 1)
                self.assertNotEqual(changed, original)
                with tempfile.TemporaryDirectory() as directory:
                    target = Path(directory)
                    shutil.copytree(root / ".github", target / ".github")
                    (target / ".github/workflows/security-workflows-policy.yml").write_text(changed, encoding="utf-8")
                    with self.assertRaises((AssertionError, KeyError, TypeError)):
                        self._stage_a_contract(target)

    def _bound_roots(self) -> tuple[Path, Path]:
        names = ("POLICY_CANDIDATE_ROOT", "POLICY_PROTECTED_ROOT", "POLICY_EXPECTED_REPOSITORY",
                 "POLICY_EXPECTED_CANDIDATE_SHA", "POLICY_EXPECTED_BASE_REPOSITORY",
                 "POLICY_EXPECTED_BASE_BRANCH", "POLICY_EXPECTED_EVENT",
                 "POLICY_EXPECTED_PROTECTED_SHA")
        values = {name: os.environ.get(name) for name in names}
        if not any(values.values()):
            self.skipTest("protected candidate binding requires explicit inputs")
        self.assertEqual([name for name, value in values.items() if not value], [])
        candidate = Path(values["POLICY_CANDIDATE_ROOT"])
        protected = Path(values["POLICY_PROTECTED_ROOT"])
        self.assertTrue(candidate.is_absolute())
        self.assertTrue(protected.is_absolute())
        self.assertEqual(str(candidate), str(candidate.resolve(strict=True)))
        self.assertEqual(str(protected), str(protected.resolve(strict=True)))
        self.assertNotEqual(candidate, protected)
        self.assertNotIn(candidate, protected.parents)
        self.assertNotIn(protected, candidate.parents)
        return candidate, protected

    def test_protected_source_and_candidate_target_contract(self) -> None:
        candidate, protected = self._bound_roots()
        expected_repository = os.environ["POLICY_EXPECTED_REPOSITORY"]
        self.assertEqual(expected_repository, self.POLICY_REPOSITORY)
        self.assertEqual(os.environ["POLICY_EXPECTED_BASE_REPOSITORY"], self.POLICY_REPOSITORY)
        self.assertEqual(os.environ["POLICY_EXPECTED_BASE_BRANCH"], "main")
        expected_event = os.environ["POLICY_EXPECTED_EVENT"]
        self.assertIn(expected_event, {"pull_request", "workflow_dispatch"})
        expected_remote = f"https://github.com/{self.POLICY_REPOSITORY}"
        for root in (candidate, protected):
            self.assertEqual(git(root, "rev-parse", "--is-inside-work-tree"), "true")
            self.assertIn(git(root, "remote", "get-url", "origin").rstrip("/"),
                          (expected_remote, expected_remote + ".git"))
        self.assertEqual(git(candidate, "rev-parse", "HEAD"),
                         os.environ["POLICY_EXPECTED_CANDIDATE_SHA"])
        if expected_event == "workflow_dispatch":
            self.assertEqual(git(candidate, "rev-parse", "HEAD"),
                             os.environ["POLICY_EXPECTED_PROTECTED_SHA"])
        self.assertEqual(git(protected, "rev-parse", "HEAD"),
                         os.environ["POLICY_EXPECTED_PROTECTED_SHA"])
        self.assertEqual(git(protected, "rev-parse", "refs/remotes/origin/main"),
                         os.environ["POLICY_EXPECTED_PROTECTED_SHA"])
        source = Path(__file__).resolve()
        self.assertTrue(source.is_relative_to(protected))
        self.assertFalse(source.is_relative_to(candidate))

    def _assert_candidate_locks_equal_protected(self, candidate: Path,
                                                  protected: Path) -> None:
        for name in ("requirements-policy.lock", "requirements-audit.lock"):
            candidate_lock = candidate / name
            protected_lock = protected / name
            self.assertTrue(candidate_lock.is_file() and not candidate_lock.is_symlink(), name)
            self.assertTrue(protected_lock.is_file() and not protected_lock.is_symlink(), name)
            candidate_bytes = candidate_lock.read_bytes()
            protected_bytes = protected_lock.read_bytes()
            self.assertEqual(candidate_bytes, protected_bytes, name)
            candidate_blob = git(candidate, "rev-parse", f"HEAD:{name}")
            protected_blob = git(protected, "rev-parse", f"HEAD:{name}")
            self.assertEqual(candidate_blob, protected_blob, name)
            self.assertEqual(git(candidate, "hash-object", "--no-filters", name),
                             candidate_blob, name)
            self.assertEqual(git(protected, "hash-object", "--no-filters", name),
                             protected_blob, name)

    def _assert_candidate_validator_contract(self, candidate: Path) -> None:
        validator_path = candidate / "verify_security_workflows.py"
        self.assertTrue(validator_path.is_file() and not validator_path.is_symlink())
        resolved = validator_path.resolve(strict=True)
        self.assertTrue(resolved.is_relative_to(candidate))
        validator = resolved.read_text(encoding="utf-8")
        self.assertIn('POLICY = "KiloAlpha021/security-policy"', validator)
        self.assertNotIn("candidate/test_verify_security_workflows.py", validator)
        self.assertNotIn("POLICY_PROTECTED_ROOT", validator)
        validate_verifier(validator)

    def test_stage_a_candidate_invariants(self) -> None:
        candidate, protected = self._bound_roots()
        protected_test = protected / "test_verify_security_workflows.py"
        protected_validator = protected / "verify_security_workflows.py"
        protected_test_bytes = protected_test.read_bytes()
        protected_validator_bytes = protected_validator.read_bytes()
        self._stage_a_contract(candidate)
        self._assert_candidate_locks_equal_protected(candidate, protected)
        self._assert_candidate_validator_contract(candidate)
        self.assertEqual(protected_test.read_bytes(), protected_test_bytes)
        self.assertEqual(protected_validator.read_bytes(), protected_validator_bytes)

    def test_stage_a_target_binding_executes_in_isolated_git_roots(self) -> None:
        source_root = Path(__file__).parent
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            candidate = base / "candidate"
            protected = base / "protected"
            ignored = shutil.ignore_patterns(".git", "__pycache__", "*.pyc")
            shutil.copytree(source_root, candidate, ignore=ignored)
            shutil.copytree(source_root, protected, ignore=ignored)
            for root in (candidate, protected):
                git(root, "init", "-b", "main")
                git(root, "config", "core.autocrlf", "false")
                git(root, "config", "user.name", "Stage A Test")
                git(root, "config", "user.email", "stage-a@example.invalid")
                git(root, "remote", "add", "origin",
                    "https://github.com/KiloAlpha021/security-policy.git")
                git(root, "add", ".")
                git(root, "commit", "-m", "fixture")
            git(protected, "update-ref", "refs/remotes/origin/main",
                git(protected, "rev-parse", "HEAD"))

            environment = os.environ.copy()
            environment.update({
                "POLICY_CANDIDATE_ROOT": str(candidate.resolve()),
                "POLICY_PROTECTED_ROOT": str(protected.resolve()),
                "POLICY_EXPECTED_REPOSITORY": self.POLICY_REPOSITORY,
                "POLICY_EXPECTED_CANDIDATE_SHA": git(candidate, "rev-parse", "HEAD"),
                "POLICY_EXPECTED_BASE_REPOSITORY": self.POLICY_REPOSITORY,
                "POLICY_EXPECTED_BASE_BRANCH": "main",
                "POLICY_EXPECTED_EVENT": "pull_request",
                "POLICY_EXPECTED_PROTECTED_SHA": git(protected, "rev-parse", "HEAD"),
                "PYTHONPATH": str(protected.resolve()),
            })

            def execute(method: str, overrides: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
                selected = environment.copy()
                selected.update(overrides or {})
                return subprocess.run(
                    [str(Path(os.sys.executable)), str(protected / "test_verify_security_workflows.py"),
                     f"RootPolicyTests.{method}", "-v"],
                    cwd=protected, env=selected, capture_output=True, text=True,
                )

            for method in ("test_protected_source_and_candidate_target_contract",
                           "test_stage_a_candidate_invariants"):
                result = execute(method)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

            failures = (
                {"POLICY_EXPECTED_REPOSITORY": "KiloAlpha021/other"},
                {"POLICY_EXPECTED_CANDIDATE_SHA": "0" * 40},
                {"POLICY_EXPECTED_BASE_REPOSITORY": "KiloAlpha021/other"},
                {"POLICY_EXPECTED_BASE_BRANCH": "other"},
                {"POLICY_EXPECTED_EVENT": "push"},
                {"POLICY_CANDIDATE_ROOT": str(protected.resolve())},
                {"POLICY_CANDIDATE_ROOT": str((candidate / "missing").resolve())},
            )
            for overrides in failures:
                with self.subTest(overrides=overrides):
                    self.assertNotEqual(
                        execute("test_protected_source_and_candidate_target_contract", overrides).returncode,
                        0,
                    )

            git(candidate, "remote", "set-url", "origin",
                "https://github.com/KiloAlpha021/other.git")
            self.assertNotEqual(
                execute("test_protected_source_and_candidate_target_contract").returncode, 0
            )
            git(candidate, "remote", "set-url", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")

            protected_lock_bytes = {
                name: (protected / name).read_bytes()
                for name in ("requirements-policy.lock", "requirements-audit.lock")
            }
            lock_mutations = (
                ("requirements-policy.lock", lambda value: value + b"# one-byte mutation\n"),
                ("requirements-policy.lock", lambda value: value.replace(b"\n", b"\r\n")),
                ("requirements-policy.lock", lambda value: value.replace(b"pyyaml==6.0.3", b"pyyaml==6.0.2")),
                ("requirements-policy.lock", lambda value: value.replace(b"sha256:", b"sha256:0", 1)),
                ("requirements-audit.lock", lambda value: b"\n".join(reversed(value.splitlines())) + b"\n"),
            )
            for name, mutate in lock_mutations:
                with self.subTest(lock_mutation=name, mutation=mutate):
                    lock = candidate / name
                    original_lock = lock.read_bytes()
                    changed = mutate(original_lock)
                    self.assertNotEqual(changed, original_lock)
                    lock.write_bytes(changed)
                    self.assertNotEqual(execute("test_stage_a_candidate_invariants").returncode, 0)
                    lock.write_bytes(original_lock)
            missing_lock = candidate / "requirements-policy.lock"
            saved_lock = missing_lock.read_bytes()
            missing_lock.unlink()
            self.assertNotEqual(execute("test_stage_a_candidate_invariants").returncode, 0)
            missing_lock.mkdir()
            self.assertNotEqual(execute("test_stage_a_candidate_invariants").returncode, 0)
            missing_lock.rmdir()
            missing_lock.write_bytes(saved_lock)
            for name, expected in protected_lock_bytes.items():
                self.assertEqual((protected / name).read_bytes(), expected)

            validator_path = candidate / "verify_security_workflows.py"
            validator_original = validator_path.read_text(encoding="utf-8")
            validator_mutations = (
                ('POLICY = "KiloAlpha021/security-policy"', 'POLICY = "KiloAlpha021/other"'),
                ('CANDIDATE_REPOSITORY = "KiloAlpha021/automated-trading-bot"',
                 'CANDIDATE_REPOSITORY = "KiloAlpha021/other"'),
                ("if event_repository not in SUPPORTED_REPOSITORIES", "if False"),
                ("repository(candidate) != event_repository", "False"),
                ("Candidate checkout does not match event SHA", "candidate accepted"),
                ("Candidate and trusted roots must be separate", "roots may overlap"),
                ("Trusted M1 control mismatch", "trusted mismatch ignored"),
            )
            protected_validator_bytes = (protected / "verify_security_workflows.py").read_bytes()
            for old_fragment, new_fragment in validator_mutations:
                with self.subTest(validator_mutation=old_fragment):
                    changed = validator_original.replace(old_fragment, new_fragment)
                    self.assertNotEqual(changed, validator_original)
                    validator_path.write_text(changed, encoding="utf-8")
                    self.assertNotEqual(execute("test_stage_a_candidate_invariants").returncode, 0)
                    validator_path.write_text(validator_original, encoding="utf-8")
            validator_path.unlink()
            self.assertNotEqual(execute("test_stage_a_candidate_invariants").returncode, 0)
            validator_path.mkdir()
            self.assertNotEqual(execute("test_stage_a_candidate_invariants").returncode, 0)
            validator_path.rmdir()
            validator_path.write_text(validator_original, encoding="utf-8")
            self.assertEqual((protected / "verify_security_workflows.py").read_bytes(),
                             protected_validator_bytes)

            workflow = candidate / ".github/workflows/security-workflows-policy.yml"
            original = workflow.read_text(encoding="utf-8")
            workflow.write_text(original.replace(self.BASELINE_VERSION,
                                                  "SECURITY-POLICY-BASELINE-2", 1),
                                encoding="utf-8")
            git(candidate, "add", ".")
            git(candidate, "commit", "-m", "candidate mutation")
            result = execute("test_stage_a_candidate_invariants", {
                "POLICY_EXPECTED_CANDIDATE_SHA": git(candidate, "rev-parse", "HEAD")
            })
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((protected / "test_verify_security_workflows.py").read_bytes(),
                             (source_root / "test_verify_security_workflows.py").read_bytes())

    def test_stage_a_admission_and_proof_context_execute(self) -> None:
        workflow_path = Path(__file__).parent / ".github/workflows/security-workflows-policy.yml"
        workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        admission = next(step for step in steps
                         if step["name"] == "Enforce exact Model D maintenance admission")
        run = admission["run"]
        self.assertEqual(admission["if"],
                         "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP'")
        self.assertEqual(run.count("admit-maintenance"), 1)
        self.assertEqual(run.count("--maintenance-operation MODEL_D_ORCHESTRATION_V1"), 1)
        self.assertIn("policy/protected_policy_bootstrap.py", run)
        self.assertIn("$LASTEXITCODE -ne 0", run)
        for forbidden in ("candidate/protected_policy_bootstrap.py",
                          "1211595f9b0b5d1e76dd892bb210fece54f24b53",
                          "diff --name-status", "$changed"):
            self.assertNotIn(forbidden, run)

    def test_exact_model_d_admission_scope_is_protected_python(self) -> None:
        self.assertEqual(bootstrap.MODEL_D_MAINTENANCE_OPERATION,
                         "MODEL_D_ORCHESTRATION_V1")
        self.assertEqual(bootstrap.MODEL_D_MAINTENANCE_GENERATION,
                         "MODEL_D_ORCHESTRATION_V1_GENERATION_1")
        self.assertEqual(
            bootstrap.MODEL_D_MAINTENANCE_LIFECYCLE,
            "MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED")
        self.assertEqual(
            bootstrap.MODEL_D_MAINTENANCE_HISTORY_ANCHOR,
            "2784fc943f9eebcab4e468980ad0040499eadc52")
        self.assertEqual(bootstrap.MODEL_D_MAINTENANCE_PATHS, (
            ".github/workflows/security-workflows-policy.yml",
            "protected_policy_bootstrap.py",
            "test_verify_security_workflows.py",
        ))
        self.assertTrue(callable(bootstrap.validate_model_d_maintenance))

    def test_exact_model_d_admission_rejects_record_mutations(self) -> None:
        valid = b"".join(
            b"M\0" + path.encode("utf-8") + b"\0"
            for path in bootstrap.MODEL_D_MAINTENANCE_PATHS)
        bootstrap._model_d_records(valid)
        for changed in (
            valid.replace(b"M\0", b"A\0", 1),
            valid.replace(b"M\0", b"D\0", 1),
            valid.replace(b"protected_policy_bootstrap.py",
                          b"Protected_policy_bootstrap.py"),
            valid.replace(b"protected_policy_bootstrap.py",
                          b"dir\\protected_policy_bootstrap.py"),
            valid + b"M\0foreign.py\0",
        ):
            with self.subTest(changed=changed), self.assertRaises(
                    bootstrap.BootstrapError):
                bootstrap._model_d_records(changed)

    def test_stage_a_transition_removal_is_required_after_bootstrap(self) -> None:
        text = (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text(encoding="utf-8")
        self.assertNotIn("1211595f9b0b5d1e76dd892bb210fece54f24b53", text)
        self.assertNotIn("P0b-2 transition expired after protected-main movement", text)
        self.assertIn("MODEL_D_ORCHESTRATION_V1", text)
        self.assertNotIn("$stageABase", text)
        self.assertNotIn("Security-policy self-PR exceeds the bounded five-file scope", text)

    def test_prebootstrap_preparation_restores_windows_checkout_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="Model D path with spaces ") as directory:
            workspace = Path(directory).resolve()
            candidate = workspace / "candidate"
            protected = workspace / "policy"
            candidate.mkdir()
            protected.mkdir()
            sentinel = protected / "sentinel"
            sentinel.write_bytes(b"protected\n")
            git(candidate, "init", "-b", "main")
            git(candidate, "config", "user.name", "P0b2 Test")
            git(candidate, "config", "user.email", "p0b2@example.invalid")
            git(candidate, "config", "core.autocrlf", "false")
            workflow_path = candidate / bootstrap.CANDIDATE_BASELINE_PATH
            workflow_path.parent.mkdir(parents=True)
            committed = (
                b"name: policy\nenv:\n"
                b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\n"
            )
            workflow_path.write_bytes(committed)
            git(candidate, "add", bootstrap.CANDIDATE_BASELINE_PATH)
            git(candidate, "commit", "-m", "head")
            head_sha = git(candidate, "rev-parse", "HEAD")
            git(candidate, "commit", "--allow-empty", "-m", "synthetic merge")
            merge_sha = git(candidate, "rev-parse", "HEAD")
            self.assertNotEqual(head_sha, merge_sha)
            committed_blob = git(
                candidate, "rev-parse", f"{merge_sha}:{bootstrap.CANDIDATE_BASELINE_PATH}")

            git(candidate, "config", "core.autocrlf", "true")
            workflow_path.unlink()
            git(candidate, "checkout", "--", bootstrap.CANDIDATE_BASELINE_PATH)
            self.assertIn(b"\r\n", workflow_path.read_bytes())
            self.assertEqual(git(candidate, "hash-object", bootstrap.CANDIDATE_BASELINE_PATH),
                             committed_blob)
            self.assertNotEqual(
                git(candidate, "hash-object", "--no-filters", bootstrap.CANDIDATE_BASELINE_PATH),
                committed_blob,
            )
            with self.assertRaisesRegex(bootstrap.BootstrapError,
                                        "Invalid candidate baseline source bytes"):
                bootstrap.extract_candidate_baseline(candidate)

            workflow = yaml.load(
                (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text(
                    encoding="utf-8"), Loader=yaml.BaseLoader)
            step = next(item for item in workflow["jobs"]["security-workflows-policy"]["steps"]
                        if item["name"] == "Resolve protected bootstrap authority")
            preparation = step["run"].split(
                'python -I -S "${{ github.workspace }}/policy/protected_policy_bootstrap.py"', 1)[0]
            rendered = preparation.replace("${{ github.workspace }}", workspace.as_posix())
            rendered = rendered.replace("${{ github.sha }}", merge_sha)
            completed = subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-Command", rendered],
                cwd=workspace, capture_output=True, text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
            self.assertEqual(git(candidate, "rev-parse", "HEAD"), merge_sha)
            self.assertEqual(workflow_path.read_bytes(), committed)
            self.assertEqual(
                git(candidate, "hash-object", "--no-filters", bootstrap.CANDIDATE_BASELINE_PATH),
                committed_blob,
            )
            self.assertEqual(bootstrap.extract_candidate_baseline(candidate),
                             bootstrap.CURRENT_BASELINE)
            self.assertEqual(sentinel.read_bytes(), b"protected\n")

    def test_all_pwsh_blocks_parse_executably(self) -> None:
        workflow = yaml.load(
            (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text(
                encoding="utf-8"
            ),
            Loader=yaml.BaseLoader,
        )
        blocks = [step["run"] for step in workflow["jobs"]["security-workflows-policy"]["steps"]
                  if step.get("shell") == "pwsh"]
        self.assertGreater(len(blocks), 0)
        for index, block in enumerate(blocks):
            with self.subTest(index=index):
                self.assertIsNone(re.search(r"'[^'\r\n]*`[tnr][^'\r\n]*'", block))
                rendered = re.sub(r"\$\{\{.*?\}\}", "GITHUB_EXPRESSION", block)
                result = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                     "[void][scriptblock]::Create([Console]::In.ReadToEnd())"],
                    input=rendered, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_policy_dependency_lock_identities(self) -> None:
        root = Path(__file__).parent
        policy = root / "requirements-policy.lock"
        audit = root / "requirements-audit.lock"
        self.assertEqual(hashlib.sha256(policy.read_bytes()).hexdigest(),
                         "2c8257dff9274ba95c7a2d21757ac79acc816e295e45062d0ad8c05d7a2d2f6c")
        self.assertEqual(hashlib.sha256(audit.read_bytes()).hexdigest(),
                         "bd75e0d124e602152a78c08f8f2c8e6ed7a8852bfce4a4b189b605a7f064ce34")
        policy_entries = [line for line in policy.read_text().splitlines()
                          if line and not line.startswith(("#", "--"))]
        audit_entries = [line for line in audit.read_text().splitlines()
                         if line and not line.startswith(("#", "--"))]
        locked = re.compile(r"[A-Za-z0-9_.-]+==[^ ]+ --hash=sha256:[0-9a-f]{64}\Z")
        self.assertEqual(policy_entries, [
            "pyyaml==6.0.3 --hash=sha256:5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b"
        ])
        self.assertEqual(len(audit_entries), 29)
        self.assertTrue(all(locked.fullmatch(entry) for entry in audit_entries))
        self.assertEqual(sum(entry.startswith("pip-audit==2.10.1 ") for entry in audit_entries), 1)

    def test_structural_rejections(self) -> None:
        workflow = (self.candidate / ".github/workflows/m1-trusted.yml").read_text()
        sha = "1" * 40
        cases = {
            "branch": workflow.replace("@" + sha, "@main", 1),
            "tag": workflow.replace("@" + sha, "@v4", 1),
            "short": workflow.replace("@" + sha, "@" + sha[:12], 1),
            "empty": workflow.replace("@" + sha, "@", 1),
            "trailing": workflow.replace("@" + sha, "@" + sha + "junk", 1),
            "local": workflow.replace("actions/checkout@" + sha, "./local@" + sha, 1),
            "docker": workflow.replace("actions/checkout@" + sha, "docker://image@" + sha, 1),
            "duplicate": workflow.replace("      - uses: actions/checkout@" + sha,
                                           "      - uses: actions/checkout@" + sha + "\n        uses: actions/checkout@" + sha, 1),
            "alias": workflow.replace("      - uses: actions/checkout@" + sha,
                                       "      - uses: &ref actions/checkout@" + sha, 1),
            "tagged": workflow.replace("      - uses: actions/checkout@" + sha,
                                        "      - uses: !!str actions/checkout@" + sha, 1),
            "unknown_placement": workflow + "extra:\n  uses: actions/checkout@" + sha + "\n",
            "malformed": workflow + "[\n",
            "escaped_duplicate": workflow.replace("      - uses: actions/checkout@" + sha,
                '      - uses: actions/checkout@' + sha + '\n        "\\u0075ses": actions/checkout@' + sha, 1),
            "merge": workflow.replace("      - uses: actions/checkout@" + sha,
                "      - <<: {uses: actions/checkout@" + sha + "}", 1),
            "nested_uses": workflow.replace("          path: candidate", "          path: candidate\n          uses: actions/checkout@" + sha, 1),
            "same_repo_workflow": workflow.replace("    steps:\n",
                "    uses: ./.github/workflows/evaluator.yml@" + sha + "\n    steps:\n", 1),
            "job_action_instead_of_workflow": workflow.replace("    steps:\n",
                "    uses: actions/checkout@" + sha + "\n    steps:\n", 1),
            "missing_owner": workflow.replace("actions/checkout@" + sha, "checkout@" + sha, 1),
            "empty_path_segment": workflow.replace("actions/checkout@" + sha, "actions//checkout@" + sha, 1),
            "dotdot_path": workflow.replace("actions/checkout@" + sha, "actions/checkout/../other@" + sha, 1),
            "invalid_owner": workflow.replace("actions/checkout@" + sha, "--/checkout@" + sha, 1),
            "uppercase_sha": workflow.replace("actions/checkout@" + sha,
                "actions/checkout@" + "A" * 40, 1),
            "expression": workflow.replace("actions/checkout@" + sha,
                "actions/checkout@${{ github.sha }}", 1),
        }
        for label, value in cases.items():
            with self.subTest(label=label), self.assertRaises(ValueError):
                action_references(value)

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


class ProtectedBootstrapComponentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.candidate = base / "candidate"
        self.protected = base / "protected"
        for root in (self.candidate, self.protected):
            root.mkdir()
            git(root, "init", "-b", "main")
            git(root, "config", "user.name", "Bootstrap Test")
            git(root, "config", "user.email", "bootstrap@example.invalid")
            git(root, "remote", "add", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")
            (root / "identity.txt").write_text(root.name + "\n", encoding="utf-8")
            git(root, "add", ".")
            git(root, "commit", "-m", "identity")
        self.candidate_sha = git(self.candidate, "rev-parse", "HEAD")
        self.protected_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", self.protected_sha)

    def inputs(self, **changes: object) -> bootstrap.BootstrapInputs:
        values: dict[str, object] = {
            "event_name": "pull_request",
            "repository": bootstrap.REPOSITORY,
            "base_repository": bootstrap.REPOSITORY,
            "base_branch": "main",
            "candidate_sha": self.candidate_sha,
            "protected_sha": self.protected_sha,
            "candidate_root": self.candidate,
            "protected_root": self.protected,
            "candidate_baseline": bootstrap.CURRENT_BASELINE,
        }
        values.update(changes)
        return bootstrap.BootstrapInputs(**values)  # type: ignore[arg-type]

    def test_atomic_model_d_plan_correspondence_rejects_forged_values(self) -> None:
        inputs = self.inputs()
        result, plan = bootstrap.evaluate_model_d_plan(inputs)
        self.assertEqual((result, plan), bootstrap.evaluate_model_d_plan(inputs))
        self.assertEqual(
            (result, plan),
            bootstrap.validate_model_d_plan_correspondence(inputs, result, plan))
        # Copies and reconstructed values have no provenance; matching values
        # are accepted only after canonical evaluation of the inputs again.
        self.assertEqual(
            (result, plan), bootstrap.validate_model_d_plan_correspondence(
                inputs, replace(result), replace(plan)))
        for forged_result in (
                replace(result, policy_source=bootstrap.PolicySource.POLICY),
                replace(result, owner_authorization="OPTIONAL"),
                replace(result, post_merge_proof="OPTIONAL")):
            with self.subTest(forged_result=forged_result), self.assertRaises(
                    bootstrap.BootstrapError):
                bootstrap.validate_model_d_plan_correspondence(
                    inputs, forged_result, plan)
        for forged_plan in (
                replace(plan, policy_lock_source=bootstrap.PolicySource.POLICY),
                replace(plan, audit_lock_source=bootstrap.PolicySource.POLICY),
                replace(plan, candidate_evidence=bootstrap.CandidateEvidenceDisposition.SKIP),
                replace(plan, protected_evidence=bootstrap.ProtectedEvidenceDisposition.TEST_INDEPENDENT_POLICY),
                replace(plan, downstream_validation=bootstrap.DownstreamValidationDisposition.RUN)):
            with self.subTest(forged_plan=forged_plan), self.assertRaises(
                    bootstrap.BootstrapError):
                bootstrap.validate_model_d_plan_correspondence(inputs, result, forged_plan)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_model_d_plan_correspondence(
                replace(inputs, candidate_baseline=bootstrap.IMMEDIATE_SUCCESSOR),
                result, plan)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.evaluate_model_d_plan(replace(inputs, candidate_sha="0" * 40))

    def test_atomic_model_d_plan_supported_evaluations(self) -> None:
        same = self.inputs()
        result, plan = bootstrap.evaluate_model_d_plan(same)
        self.assertEqual(result, bootstrap.evaluate(same))
        self.assertEqual(plan, bootstrap.derive_model_d_plan(result))
        proof_candidate = self.protected.parent / "proof-candidate-plan"
        shutil.copytree(self.protected, proof_candidate)
        proof = self.inputs(
            event_name="workflow_dispatch", candidate_sha=self.protected_sha,
            candidate_root=proof_candidate, event_ref="refs/heads/main",
            workflow_ref=(bootstrap.REPOSITORY +
                          "/.github/workflows/security-workflows-policy.yml@refs/heads/main"))
        self.assertEqual(bootstrap.evaluate_model_d_plan(proof)[0].evaluation_context,
                         bootstrap.EvaluationContext.STAGE_A_PROTECTED_PROOF)
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        downstream = self.inputs(
            repository=bootstrap.DOWNSTREAM_REPOSITORY,
            base_repository=bootstrap.DOWNSTREAM_REPOSITORY)
        self.assertEqual(bootstrap.evaluate_model_d_plan(downstream)[0].evaluation_context,
                         bootstrap.EvaluationContext.DOWNSTREAM_SECURITY_WORKFLOWS)

    def _model_d_lock_fixture(self) -> None:
        source = Path(__file__).parent
        for root in (self.candidate, self.protected):
            for name in ("requirements-policy.lock", "requirements-audit.lock"):
                (root / name).write_bytes((source / name).read_bytes())
            git(root, "add", "requirements-policy.lock", "requirements-audit.lock")
            git(root, "commit", "-m", "lock identities")
        self.candidate_sha = git(self.candidate, "rev-parse", "HEAD")
        self.protected_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", self.protected_sha)

    def test_d2_normalization_and_lock_sources_follow_atomic_plan(self) -> None:
        self._model_d_lock_fixture()
        inputs = self.inputs()
        for _ in range(2):
            result, plan = bootstrap.normalize_and_validate_model_d_bytes(inputs)
            self.assertEqual((result, plan), bootstrap.evaluate_model_d_plan(inputs))
            self.assertIs(plan.policy_lock_source, bootstrap.PolicySource.CANDIDATE)
            self.assertIs(plan.audit_lock_source, bootstrap.PolicySource.CANDIDATE)
            for root in (self.candidate, self.protected):
                self.assertEqual(git(root, "config", "--local", "--get", "core.autocrlf"),
                                 "false")
                for name in ("requirements-policy.lock", "requirements-audit.lock"):
                    self.assertEqual(git(root, "hash-object", "--no-filters", name),
                                     git(root, "rev-parse", f"HEAD:{name}"))
        with mock.patch.object(bootstrap, "TRANSITION_PROTECTED_BASE", self.protected_sha):
            successor = self.inputs(candidate_baseline=bootstrap.IMMEDIATE_SUCCESSOR)
            result, plan = bootstrap.normalize_and_validate_model_d_bytes(successor)
            self.assertIs(result.version_disposition,
                          bootstrap.VersionDisposition.IMMEDIATE_SUCCESSOR)
            self.assertIs(plan.policy_lock_source, bootstrap.PolicySource.POLICY)
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        downstream = self.inputs(repository=bootstrap.DOWNSTREAM_REPOSITORY,
                                 base_repository=bootstrap.DOWNSTREAM_REPOSITORY)
        result, plan = bootstrap.normalize_and_validate_model_d_bytes(downstream)
        self.assertIs(result.evaluation_context,
                      bootstrap.EvaluationContext.DOWNSTREAM_SECURITY_WORKFLOWS)
        self.assertIs(plan.audit_lock_source, bootstrap.PolicySource.POLICY)

    def test_d3_fixed_outputs_follow_public_d2_for_all_contexts(self) -> None:
        self._model_d_lock_fixture()
        proof_candidate = self.protected.parent / "proof-candidate-d3"
        shutil.copytree(self.protected, proof_candidate)
        proof = self.inputs(
            event_name="workflow_dispatch", candidate_sha=self.protected_sha,
            candidate_root=proof_candidate, event_ref="refs/heads/main",
            workflow_ref=(bootstrap.REPOSITORY +
                          "/.github/workflows/security-workflows-policy.yml@refs/heads/main"))
        cases = [(self.inputs(), None),
                 (self.inputs(candidate_baseline=bootstrap.IMMEDIATE_SUCCESSOR),
                  self.protected_sha), (proof, None)]
        for index, (inputs, transition) in enumerate(cases):
            with self.subTest(index=index), mock.patch.object(
                    bootstrap, "TRANSITION_PROTECTED_BASE", transition):
                result, plan = bootstrap.normalize_and_validate_model_d_bytes(inputs)
                output = Path(self.temp.name).resolve() / f"d3-output-{index}"
                output.write_bytes(b"")
                bootstrap.emit_model_d_output(inputs, result, plan, output)
                lines = output.read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(lines), 11)
                self.assertEqual(tuple(line.split("=", 1)[0] for line in lines),
                                 bootstrap._OUTPUT_KEYS + bootstrap._MODEL_D_OUTPUT_KEYS)
                self.assertEqual(dict(line.split("=", 1) for line in lines),
                                 dict(bootstrap._validated_outputs(result) +
                                      bootstrap._validated_model_d_outputs(plan)))
                forged = replace(plan, policy_lock_source=(
                    bootstrap.PolicySource.POLICY if plan.policy_lock_source is
                    bootstrap.PolicySource.CANDIDATE else bootstrap.PolicySource.CANDIDATE))
                rejected = Path(self.temp.name).resolve() / f"d3-rejected-{index}"
                rejected.write_bytes(b"")
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.emit_model_d_output(inputs, result, forged, rejected)
                self.assertEqual(rejected.read_bytes(), b"")
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        downstream = self.inputs(repository=bootstrap.DOWNSTREAM_REPOSITORY,
                                 base_repository=bootstrap.DOWNSTREAM_REPOSITORY)
        result, plan = bootstrap.normalize_and_validate_model_d_bytes(downstream)
        output = Path(self.temp.name).resolve() / "d3-downstream"
        output.write_bytes(b"")
        bootstrap.emit_model_d_output(downstream, result, plan, output)
        self.assertIn(b"downstream-validation=RUN_DOWNSTREAM_VALIDATION\n",
                      output.read_bytes())

    def test_d3_cli_runs_canonical_d2_and_emits_only_after_success(self) -> None:
        self._model_d_lock_fixture()
        inputs = self.inputs()
        argv = ["run-model-d"]
        for name in ("event-name", "repository", "base-repository", "base-branch",
                     "candidate-sha", "protected-sha", "candidate-root", "protected-root",
                     "event-ref", "default-branch", "workflow-ref"):
            argv.extend((f"--{name}", "bound"))
        output = Path(self.temp.name).resolve() / "d3-cli-output"
        output.write_bytes(b"")
        with mock.patch.object(bootstrap, "_cli_inputs", return_value=inputs), \
             mock.patch.object(bootstrap, "validate_protected_universe"), \
             mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            self.assertEqual(bootstrap.main(argv), 0)
        self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 11)
        output.write_bytes(b"")
        broken = replace(inputs, candidate_sha="0" * 40)
        with mock.patch.object(bootstrap, "_cli_inputs", return_value=broken), \
             mock.patch.object(bootstrap, "validate_protected_universe"), \
             mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
            self.assertEqual(bootstrap.main(argv), 2)
        self.assertEqual(output.read_bytes(), b"")

    def test_d2_lock_byte_and_representation_fail_closed(self) -> None:
        self._model_d_lock_fixture()
        name = "requirements-policy.lock"
        path = self.candidate / name
        original = path.read_bytes()
        mutations = (
            original + b"# drift\n", original.replace(b"\n", b"\r\n"),
            original.replace(b"\n", b"\r", 1), b"\xef\xbb\xbf" + original,
            original + b"\0", b"\xff" + original,
        )
        for changed in mutations:
            with self.subTest(changed=changed[:12]):
                path.write_bytes(changed)
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validate_model_d_lock(
                        self.candidate, self.candidate_sha, name,
                        bootstrap.PolicySource.CANDIDATE)
        path.write_bytes(original)
        path.unlink()
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._validate_model_d_lock(
                self.candidate, self.candidate_sha, name,
                bootstrap.PolicySource.CANDIDATE)

    def test_d2_committed_lock_format_and_type_fail_closed(self) -> None:
        self._model_d_lock_fixture()
        name = "requirements-audit.lock"
        root = self.candidate
        original_sha = self.candidate_sha
        path = root / name
        path.write_bytes(path.read_bytes() + b"unhashed==1.0\n")
        git(root, "add", name)
        git(root, "commit", "-m", "malformed lock")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.normalize_and_validate_model_d_bytes(
                self.inputs(candidate_sha=git(root, "rev-parse", "HEAD")))
        git(root, "reset", "--hard", original_sha)
        for mode, object_id in (("120000", git(root, "hash-object", name)),
                                ("160000", original_sha)):
            with self.subTest(mode=mode):
                git(root, "update-index", "--add", "--cacheinfo",
                    f"{mode},{object_id},{name}")
                git(root, "commit", "-m", f"lock mode {mode}")
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validate_model_d_lock(
                        root, git(root, "rev-parse", "HEAD"), name,
                        bootstrap.PolicySource.CANDIDATE)
                git(root, "reset", "--hard", original_sha)

    def test_d2_swapped_lock_roles_and_protected_identity_fail_closed(self) -> None:
        self._model_d_lock_fixture()
        policy = self.candidate / "requirements-policy.lock"
        audit = self.candidate / "requirements-audit.lock"
        policy_bytes, audit_bytes = policy.read_bytes(), audit.read_bytes()
        policy.write_bytes(audit_bytes)
        audit.write_bytes(policy_bytes)
        git(self.candidate, "add", "requirements-policy.lock", "requirements-audit.lock")
        git(self.candidate, "commit", "-m", "swap lock roles")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.normalize_and_validate_model_d_bytes(self.inputs(
                candidate_sha=git(self.candidate, "rev-parse", "HEAD")))

        protected_policy = self.protected / "requirements-policy.lock"
        protected_policy.write_bytes(policy_bytes + b"# protected drift\n")
        git(self.protected, "add", "requirements-policy.lock")
        git(self.protected, "commit", "-m", "protected lock drift")
        changed_protected = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", changed_protected)
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.normalize_and_validate_model_d_bytes(self.inputs(
                repository=bootstrap.DOWNSTREAM_REPOSITORY,
                base_repository=bootstrap.DOWNSTREAM_REPOSITORY,
                candidate_sha=git(self.candidate, "rev-parse", "HEAD"),
                protected_sha=changed_protected))

    def test_d2_identity_failure_precedes_mutation(self) -> None:
        self._model_d_lock_fixture()
        wrong = replace(self.inputs(), candidate_sha="0" * 40)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.normalize_and_validate_model_d_bytes(wrong)
        self.assertNotEqual(subprocess.run(
            ["git", "-C", str(self.candidate), "config", "--local", "--get",
             "core.autocrlf"], capture_output=True, text=True).stdout.strip(), "false")
        with mock.patch.object(bootstrap, "_git_bytes",
                               side_effect=bootstrap.BootstrapError("Git failure")):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.normalize_and_validate_model_d_bytes(self.inputs())

    def test_d2_public_entry_ignores_forged_root_order_omission_and_addition(self) -> None:
        self._model_d_lock_fixture()
        canonical = (bootstrap.NormalizationRoot.CANDIDATE,
                     bootstrap.NormalizationRoot.POLICY)
        variants = (
            ("reordered", canonical[::-1]),
            ("omitted", canonical[:1]),
            ("added", canonical + ("foreign",)),
        )
        for label, injected_roots in variants:
            with self.subTest(mutation=label):
                inputs = self.inputs()
                result, plan = bootstrap.evaluate_model_d_plan(inputs)
                forged_plan = replace(plan)
                object.__setattr__(forged_plan, "normalization_roots", injected_roots)
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_model_d_plan_correspondence(
                        inputs, result, forged_plan)
                # BootstrapInputs is a value object, not a plan authority.
                object.__setattr__(inputs, "normalization_roots", injected_roots)
                with mock.patch.object(bootstrap, "_git_bytes",
                                       wraps=bootstrap._git_bytes) as git_calls:
                    actual_result, actual_plan = (
                        bootstrap.normalize_and_validate_model_d_bytes(inputs))
                self.assertEqual(actual_result, result)
                self.assertEqual(actual_plan.normalization_roots, canonical)
                normalized_roots = [call.args[0] for call in git_calls.call_args_list
                                    if call.args[1:4] == (
                                        "config", "--local", "core.autocrlf")]
                self.assertEqual(normalized_roots, [self.candidate, self.protected])

    def test_d2_public_entry_protected_proof_context(self) -> None:
        self._model_d_lock_fixture()
        proof_candidate = self.protected.parent / "d2-proof-candidate"
        shutil.copytree(self.protected, proof_candidate)
        inputs = self.inputs(
            event_name="workflow_dispatch", candidate_root=proof_candidate,
            candidate_sha=self.protected_sha, event_ref="refs/heads/main",
            workflow_ref=(bootstrap.REPOSITORY +
                          "/.github/workflows/security-workflows-policy.yml@refs/heads/main"))
        result, plan = bootstrap.normalize_and_validate_model_d_bytes(inputs)
        self.assertEqual((result, plan), bootstrap.evaluate_model_d_plan(inputs))
        self.assertIs(result.evaluation_context,
                      bootstrap.EvaluationContext.STAGE_A_PROTECTED_PROOF)
        self.assertEqual(plan.normalization_roots, (
            bootstrap.NormalizationRoot.CANDIDATE,
            bootstrap.NormalizationRoot.POLICY))
        self.assertIs(plan.policy_lock_source, bootstrap.PolicySource.POLICY)
        self.assertIs(plan.audit_lock_source, bootstrap.PolicySource.POLICY)
        for name in ("requirements-policy.lock", "requirements-audit.lock"):
            self.assertEqual(git(self.protected, "hash-object", "--no-filters", name),
                             git(self.protected, "rev-parse", f"HEAD:{name}"))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.normalize_and_validate_model_d_bytes(
                replace(inputs, protected_sha="0" * 40))

    def test_d2_public_entry_restores_dirty_selected_lock_from_commit(self) -> None:
        self._model_d_lock_fixture()
        name = "requirements-policy.lock"
        path = self.candidate / name
        committed = path.read_bytes()
        path.write_bytes(committed + b"# uncommitted worktree drift\n")
        self.assertNotEqual(git(self.candidate, "hash-object", "--no-filters", name),
                            git(self.candidate, "rev-parse", f"HEAD:{name}"))
        result, plan = bootstrap.normalize_and_validate_model_d_bytes(self.inputs())
        self.assertIs(plan.policy_lock_source, bootstrap.PolicySource.CANDIDATE)
        self.assertIs(result.evaluation_context,
                      bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP)
        self.assertEqual(path.read_bytes(), committed)
        self.assertEqual(git(self.candidate, "hash-object", "--no-filters", name),
                         git(self.candidate, "rev-parse", f"HEAD:{name}"))

    def test_bootstrap_is_standard_library_only_and_pre_environment_importable(self) -> None:
        path = Path(bootstrap.__file__).resolve()
        syntax = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(syntax)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".")[0]
            for node in ast.walk(syntax)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        self.assertEqual(imported, {
            "__future__", "argparse", "hashlib", "os", "re", "stat", "subprocess", "sys",
            "tempfile", "dataclasses", "enum", "pathlib"
        })
        self.assertNotIn("yaml", imported)
        completed = subprocess.run(
            [os.sys.executable, "-I", "-S", "-c",
             "import importlib.util,sys;"
             "p=sys.argv[1];s=importlib.util.spec_from_file_location('b',p);"
             "m=importlib.util.module_from_spec(s);sys.modules['b']=m;s.loader.exec_module(m);"
             "print(m.CURRENT_BASELINE)", str(path)],
            capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), bootstrap.CURRENT_BASELINE)

    def test_constants_and_first_landing_boundary_are_explicit(self) -> None:
        self.assertEqual(bootstrap.CURRENT_BASELINE, "SECURITY-POLICY-BASELINE-1")
        self.assertEqual(bootstrap.IMMEDIATE_SUCCESSOR, "SECURITY-POLICY-BASELINE-2")
        self.assertEqual(bootstrap.TRANSITION_PROTECTED_BASE,
                         "76a811e76edbefc76ab1baf20795e2755f5bb794")
        text = Path(bootstrap.__file__).read_text(encoding="utf-8")
        for statement in ("candidate proposal", "cannot authorize its own landing",
                          "Owner authorization", "post-merge protected proof"):
            self.assertIn(statement, text)

    def test_context_and_policy_source_matrix(self) -> None:
        same = bootstrap.evaluate(self.inputs())
        self.assertEqual(same.evaluation_context, bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP)
        self.assertEqual(same.policy_source, bootstrap.PolicySource.CANDIDATE)
        self.assertEqual(same.version_disposition, bootstrap.VersionDisposition.SAME_VERSION)

        shutil.copytree(self.protected, self.protected.parent / "proof-candidate")
        proof_candidate = (self.protected.parent / "proof-candidate").resolve()
        proof = bootstrap.evaluate(self.inputs(
            event_name="workflow_dispatch", candidate_sha=self.protected_sha,
            candidate_root=proof_candidate, event_ref="refs/heads/main",
            workflow_ref=(bootstrap.REPOSITORY +
                          "/.github/workflows/security-workflows-policy.yml@refs/heads/main"),
        ))
        self.assertEqual(proof.evaluation_context,
                         bootstrap.EvaluationContext.STAGE_A_PROTECTED_PROOF)
        self.assertEqual(proof.policy_source, bootstrap.PolicySource.POLICY)

        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        try:
            for event in ("pull_request", "merge_group"):
                downstream = bootstrap.evaluate(self.inputs(
                    event_name=event, repository=bootstrap.DOWNSTREAM_REPOSITORY,
                    base_repository=bootstrap.DOWNSTREAM_REPOSITORY,
                ))
                self.assertEqual(downstream.evaluation_context,
                                 bootstrap.EvaluationContext.DOWNSTREAM_SECURITY_WORKFLOWS)
                self.assertEqual(downstream.policy_source, bootstrap.PolicySource.POLICY)
        finally:
            git(self.candidate, "remote", "set-url", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")

    def test_exact_successor_and_expiry(self) -> None:
        def identity(root: Path, *arguments: str) -> str:
            if arguments == ("remote", "get-url", "origin"):
                return "https://github.com/KiloAlpha021/security-policy.git"
            if arguments in (("rev-parse", "HEAD"),
                             ("rev-parse", "refs/remotes/origin/main")):
                return (self.candidate_sha if root == self.candidate
                        else bootstrap.TRANSITION_PROTECTED_BASE)
            raise AssertionError(arguments)

        with mock.patch.object(bootstrap, "_git", side_effect=identity):
            eligible_inputs = self.inputs(
                protected_sha=bootstrap.TRANSITION_PROTECTED_BASE,
                candidate_baseline=bootstrap.IMMEDIATE_SUCCESSOR,
            )
            eligible = bootstrap.evaluate(eligible_inputs)
            atomic_result, atomic_plan = bootstrap.evaluate_model_d_plan(eligible_inputs)
            self.assertEqual(atomic_result, eligible)
            self.assertIs(atomic_plan.policy_lock_source, bootstrap.PolicySource.POLICY)
            self.assertEqual(eligible.version_disposition,
                             bootstrap.VersionDisposition.IMMEDIATE_SUCCESSOR)
            self.assertEqual(eligible.policy_source, bootstrap.PolicySource.POLICY)
            self.assertEqual(eligible.owner_authorization, "REQUIRED")
            self.assertEqual(eligible.post_merge_proof, "REQUIRED")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.evaluate(self.inputs(candidate_baseline=bootstrap.IMMEDIATE_SUCCESSOR))

    def test_versions_inputs_and_injection_fail_closed(self) -> None:
        invalid_versions = ("", "SECURITY-POLICY-BASELINE-3", "SECURITY-POLICY-BASELINE-99",
                            "latest", "baseline-2", "SECURITY-POLICY-BASELINE-1..2",
                            "security-policy-baseline-2", "SECURITY-POLICY-BASELINE-0")
        for version in invalid_versions:
            with self.subTest(version=version), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.evaluate(self.inputs(candidate_baseline=version))
        for field, value in (
            ("repository", "KiloAlpha021/other"), ("base_repository", "KiloAlpha021/other"),
            ("base_branch", "dev"), ("event_name", "push"),
            ("candidate_sha", "0" * 39), ("protected_sha", "A" * 40),
            ("repository", "KiloAlpha021/security-policy\npolicy-source=policy"),
            ("base_branch", "main\0other"),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.evaluate(self.inputs(**{field: value}))

    def test_git_root_remote_and_sha_fail_closed(self) -> None:
        cases = (
            {"candidate_root": self.protected},
            {"candidate_root": self.candidate / "missing"},
            {"candidate_root": Path("relative")},
            {"candidate_sha": "0" * 40},
            {"protected_sha": "0" * 40},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.evaluate(self.inputs(**changes))
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/other.git")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.evaluate(self.inputs())
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")
        git_metadata = self.candidate / ".git"
        hidden_metadata = self.candidate / "git-metadata-disabled"
        git_metadata.replace(hidden_metadata)
        try:
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap.evaluate(self.inputs())
        finally:
            hidden_metadata.replace(git_metadata)

    def test_output_contract_is_closed_and_deterministic(self) -> None:
        result = bootstrap.evaluate(self.inputs())
        self.assertEqual(result.as_outputs(), result.as_outputs())
        self.assertEqual(dict(result.as_outputs()), {
            "evaluation-context": "SELF_PR_BOOTSTRAP",
            "policy-source": "candidate",
            "version-disposition": "SAME_VERSION",
            "owner-authorization": "REQUIRED",
            "post-merge-proof": "REQUIRED",
        })
        self.assertFalse(hasattr(bootstrap.BootstrapInputs, "policy_source"))
        self.assertFalse(hasattr(bootstrap.BootstrapInputs, "supported_successor"))


class ProtectedBootstrapP0b1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.candidate = base / "candidate with spaces"
        self.protected = base / "protected with spaces"
        for root in (self.candidate, self.protected):
            root.mkdir()
            git(root, "init", "-b", "main")
            git(root, "config", "user.name", "P0b1 Test")
            git(root, "config", "user.email", "p0b1@example.invalid")
            git(root, "remote", "add", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")
            self.write_universe(root, bootstrap.CURRENT_BASELINE)
            git(root, "add", ".")
            git(root, "commit", "-m", "protected universe v2")
        self.candidate_sha = git(self.candidate, "rev-parse", "HEAD")
        self.protected_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", self.protected_sha)

    @staticmethod
    def write_universe(root: Path, baseline: str) -> None:
        for member in bootstrap.PROTECTED_UNIVERSE:
            path = root / member
            path.parent.mkdir(parents=True, exist_ok=True)
            if member == bootstrap.CANDIDATE_BASELINE_PATH:
                path.write_bytes(
                    b"name: policy\nenv:\n  POLICY_BASELINE_VERSION: "
                    + baseline.encode("ascii") + b"\n"
                )
            else:
                path.write_bytes((member + "\n").encode("utf-8"))

    def cli_arguments(self) -> list[str]:
        return [
            "evaluate", "--event-name", "pull_request",
            "--repository", bootstrap.REPOSITORY,
            "--base-repository", bootstrap.REPOSITORY,
            "--base-branch", "main", "--candidate-sha", self.candidate_sha,
            "--protected-sha", self.protected_sha,
            "--candidate-root", str(self.candidate),
            "--protected-root", str(self.protected),
            "--event-ref", "refs/pull/1/merge", "--default-branch", "main",
            "--workflow-ref", "KiloAlpha021/security-policy/.github/workflows/security-workflows-policy.yml@refs/pull/1/merge",
        ]

    def run_cli(self, arguments: list[str] | None = None,
                destination: Path | None = None) -> subprocess.CompletedProcess[str]:
        output = destination or (Path(self.temp.name).resolve() / "github-output")
        if not output.exists():
            output.write_bytes(b"")
        environment = os.environ.copy()
        environment["GITHUB_OUTPUT"] = str(output)
        return subprocess.run(
            [os.sys.executable, "-I", "-S", str(Path(bootstrap.__file__).resolve()),
             *(arguments if arguments is not None else self.cli_arguments())],
            env=environment, capture_output=True, text=True,
        )

    def test_cli_is_strict_stdlib_and_emits_fixed_schema(self) -> None:
        output = Path(self.temp.name).resolve() / "github-output"
        output.write_bytes(b"")
        completed = self.run_cli(destination=output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(output.read_bytes(), (
            b"evaluation-context=SELF_PR_BOOTSTRAP\n"
            b"policy-source=candidate\n"
            b"version-disposition=SAME_VERSION\n"
            b"owner-authorization=REQUIRED\n"
            b"post-merge-proof=REQUIRED\n"
        ))
        help_result = self.run_cli(["--help"])
        self.assertEqual(help_result.returncode, 0)
        for arguments in (
            [], ["unknown"], self.cli_arguments()[:-2],
            self.cli_arguments() + ["--unknown", "value"],
            self.cli_arguments() + ["--repository", bootstrap.REPOSITORY],
            self.cli_arguments() + ["--candidate-baseline", bootstrap.CURRENT_BASELINE],
        ):
            with self.subTest(arguments=arguments):
                result = self.run_cli(arguments)
                self.assertNotEqual(result.returncode, 0)

    def test_baseline_extraction_matrix(self) -> None:
        workflow = self.candidate / bootstrap.CANDIDATE_BASELINE_PATH
        for baseline in (bootstrap.CURRENT_BASELINE, bootstrap.IMMEDIATE_SUCCESSOR):
            self.write_universe(self.candidate, baseline)
            self.assertEqual(bootstrap.extract_candidate_baseline(self.candidate), baseline)
        invalid = (
            b"name: policy\n", b"  POLICY_BASELINE_VERSION: latest\n",
            b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-3\n",
            b"  policy_baseline_version: SECURITY-POLICY-BASELINE-1\n",
            b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1..2\n",
            b"  POLICY_BASELINE_VERSION: security-policy-baseline-1\n",
            b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\r\n",
            b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\r",
            (b"name: policy\n"
             b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\r\n"),
            b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\x00\n",
            b"\xef\xbb\xbf  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\n",
            "  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\n".encode("utf-16"),
            b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\xff\n",
            (b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\n" * 2),
            b"x: 'POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1'\n",
        )
        for data in invalid:
            with self.subTest(data=data):
                workflow.write_bytes(data)
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.extract_candidate_baseline(self.candidate)

    def test_output_schema_destination_and_injection_fail_closed(self) -> None:
        inputs = bootstrap.BootstrapInputs(
            "pull_request", bootstrap.REPOSITORY, bootstrap.REPOSITORY, "main",
            self.candidate_sha, self.protected_sha, self.candidate, self.protected,
            bootstrap.CURRENT_BASELINE,
        )
        result = bootstrap.evaluate(inputs)
        outside = Path(self.temp.name).resolve() / "output"
        outside.write_bytes(b"")
        bootstrap.emit_github_output(result, outside, self.candidate, self.protected)
        self.assertEqual(len(outside.read_text(encoding="utf-8").splitlines()), 5)

        for destination in (
            Path("relative"), self.candidate / "output", self.protected / "output",
            Path(self.temp.name).resolve() / "missing",
        ):
            if destination.is_absolute() and destination.parent.exists() and destination.name == "output":
                destination.write_bytes(b"")
            with self.subTest(destination=destination), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.emit_github_output(result, destination, self.candidate, self.protected)

        nonempty = Path(self.temp.name).resolve() / "nonempty"
        nonempty.write_bytes(b"prior=value\n")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.emit_github_output(result, nonempty, self.candidate, self.protected)
        self.assertEqual(nonempty.read_bytes(), b"prior=value\n")

        malformed = bootstrap.BootstrapResult(
            bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
            bootstrap.PolicySource.CANDIDATE,
            bootstrap.VersionDisposition.SAME_VERSION,
            "REQUIRED\npolicy-source=policy", "REQUIRED",
        )
        empty = Path(self.temp.name).resolve() / "empty"
        empty.write_bytes(b"")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.emit_github_output(malformed, empty, self.candidate, self.protected)
        self.assertEqual(empty.read_bytes(), b"")
        malformed_schemas = (
            (("unknown", "value"),),
            (("evaluation-context", "SELF_PR_BOOTSTRAP"),) * 5,
            (("evaluation-context", "SELF_PR_BOOTSTRAP"),
             ("policy-source", "policy"),
             ("version-disposition", "IMMEDIATE_SUCCESSOR"),
             ("owner-authorization", "REQUIRED"),
             ("post-merge-proof", "REQUIRED")),
        )
        for schema in malformed_schemas:
            empty.write_bytes(b"")
            with self.subTest(schema=schema), mock.patch.object(
                    bootstrap.BootstrapResult, "as_outputs", return_value=schema):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.emit_github_output(result, empty, self.candidate, self.protected)
                self.assertEqual(empty.read_bytes(), b"")

    def test_exact_universe_membership_and_git_identity(self) -> None:
        bootstrap.validate_universe_members(bootstrap.PROTECTED_UNIVERSE)
        bootstrap.validate_protected_universe(self.protected, self.protected_sha)
        invalid_members = (
            bootstrap.PROTECTED_UNIVERSE[:-1],
            bootstrap.PROTECTED_UNIVERSE + ("foreign.py",),
            bootstrap.PROTECTED_UNIVERSE + (bootstrap.PROTECTED_UNIVERSE[-1],),
            bootstrap.PROTECTED_UNIVERSE[:-1] + ("Protected_policy_bootstrap.py",),
            bootstrap.PROTECTED_UNIVERSE[:-1] + ("../protected_policy_bootstrap.py",),
            bootstrap.PROTECTED_UNIVERSE[:-1] + ("C:/protected_policy_bootstrap.py",),
            bootstrap.PROTECTED_UNIVERSE[:-1] + ("dir\\protected_policy_bootstrap.py",),
        )
        for members in invalid_members:
            with self.subTest(members=members), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_universe_members(members)

    def test_universe_rejects_delete_mode_symlink_and_gitlink(self) -> None:
        component = bootstrap.PROTECTED_UNIVERSE[-1]
        variants: list[tuple[str, list[str]]] = [
            ("delete", ["rm", component]),
            ("mode", ["update-index", "--chmod=+x", component]),
            ("symlink", []),
        ]
        for name, command in variants:
            with self.subTest(name=name):
                root = Path(self.temp.name).resolve() / f"variant-{name}"
                shutil.copytree(self.protected, root)
                if name == "symlink":
                    link_blob = git(root, "hash-object", "requirements-policy.lock")
                    git(root, "update-index", "--cacheinfo",
                        "120000," + link_blob + "," + component)
                else:
                    git(root, *command)
                git(root, "commit", "-m", name)
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_protected_universe(root, git(root, "rev-parse", "HEAD"))

        root = Path(self.temp.name).resolve() / "variant-gitlink"
        shutil.copytree(self.protected, root)
        git(root, "rm", bootstrap.CANDIDATE_BASELINE_PATH)
        git(root, "update-index", "--add", "--cacheinfo",
            "160000," + self.protected_sha + "," + bootstrap.CANDIDATE_BASELINE_PATH)
        git(root, "commit", "-m", "gitlink")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_protected_universe(root, git(root, "rev-parse", "HEAD"))

    def test_cli_failure_leaves_no_partial_authority(self) -> None:
        output = Path(self.temp.name).resolve() / "failed-output"
        output.write_bytes(b"")
        bad = self.cli_arguments()
        bad[bad.index("--repository") + 1] = "KiloAlpha021/other"
        completed = self.run_cli(bad, output)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("bootstrap error:", completed.stderr)
        self.assertEqual(output.read_bytes(), b"")

        output.write_bytes(b"")
        environment = os.environ.copy()
        environment.pop("GITHUB_OUTPUT", None)
        completed = subprocess.run(
            [os.sys.executable, "-I", "-S", str(Path(bootstrap.__file__).resolve()),
             *self.cli_arguments()], env=environment, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 2)

    def test_cli_proof_and_downstream_contexts(self) -> None:
        proof_candidate = Path(self.temp.name).resolve() / "proof candidate"
        shutil.copytree(self.protected, proof_candidate)
        proof_output = Path(self.temp.name).resolve() / "proof-output"
        proof_output.write_bytes(b"")
        proof_arguments = self.cli_arguments()
        replacements = {
            "--event-name": "workflow_dispatch",
            "--candidate-sha": self.protected_sha,
            "--candidate-root": str(proof_candidate),
            "--event-ref": "refs/heads/main",
            "--workflow-ref": (bootstrap.REPOSITORY
                + "/.github/workflows/security-workflows-policy.yml@refs/heads/main"),
        }
        for option, value in replacements.items():
            proof_arguments[proof_arguments.index(option) + 1] = value
        completed = self.run_cli(proof_arguments, proof_output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(b"evaluation-context=STAGE_A_PROTECTED_PROOF\n",
                      proof_output.read_bytes())
        self.assertIn(b"policy-source=policy\n", proof_output.read_bytes())

        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        downstream_output = Path(self.temp.name).resolve() / "downstream-output"
        downstream_output.write_bytes(b"")
        downstream_arguments = self.cli_arguments()
        for option in ("--repository", "--base-repository"):
            downstream_arguments[downstream_arguments.index(option) + 1] = (
                bootstrap.DOWNSTREAM_REPOSITORY)
        completed = self.run_cli(downstream_arguments, downstream_output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(b"evaluation-context=DOWNSTREAM_SECURITY_WORKFLOWS\n",
                      downstream_output.read_bytes())
        self.assertIn(b"policy-source=policy\n", downstream_output.read_bytes())

    def test_p0a_api_and_authority_boundary_remain_closed(self) -> None:
        self.assertFalse(hasattr(bootstrap.BootstrapInputs, "policy_source"))
        self.assertFalse(hasattr(bootstrap.BootstrapInputs, "supported_successor"))
        self.assertFalse("candidate-baseline" in " ".join(self.cli_arguments()))
        self.assertEqual(bootstrap.PROTECTED_UNIVERSE, (
            ".github/workflows/security-workflows-policy.yml",
            "requirements-audit.lock", "requirements-policy.lock",
            "test_verify_security_workflows.py", "verify_security_workflows.py",
            "protected_policy_bootstrap.py",
        ))
        source = Path(bootstrap.__file__).read_text(encoding="utf-8")
        self.assertIn("candidate proposal", source)
        self.assertIn("cannot authorize its own landing", source)


class ModelDPlanV1Tests(unittest.TestCase):
    @staticmethod
    def result(context: bootstrap.EvaluationContext,
               source: bootstrap.PolicySource,
               version: bootstrap.VersionDisposition) -> bootstrap.BootstrapResult:
        return bootstrap.BootstrapResult(
            context, source, version,
            bootstrap.OWNER_AUTHORIZATION, bootstrap.POST_MERGE_PROOF)

    def test_exact_closed_plan_matrix(self) -> None:
        self.assertEqual(bootstrap.MODEL_D_PLAN_OPERATION, "MODEL_D_PLAN_V1")
        matrix = (
            (bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
             bootstrap.PolicySource.CANDIDATE,
             bootstrap.VersionDisposition.SAME_VERSION,
             bootstrap.CandidateEvidenceDisposition.RUN_STAGE_A,
             bootstrap.ProtectedEvidenceDisposition.RUN_LEGACY_HEALTH,
             bootstrap.DownstreamValidationDisposition.SKIP),
            (bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
             bootstrap.PolicySource.POLICY,
             bootstrap.VersionDisposition.IMMEDIATE_SUCCESSOR,
             bootstrap.CandidateEvidenceDisposition.RUN_STAGE_A,
             bootstrap.ProtectedEvidenceDisposition.RUN_LEGACY_HEALTH,
             bootstrap.DownstreamValidationDisposition.SKIP),
            (bootstrap.EvaluationContext.STAGE_A_PROTECTED_PROOF,
             bootstrap.PolicySource.POLICY,
             bootstrap.VersionDisposition.SAME_VERSION,
             bootstrap.CandidateEvidenceDisposition.RUN_STAGE_A,
             bootstrap.ProtectedEvidenceDisposition.APPLY_STAGE_A_TO_CANDIDATE,
             bootstrap.DownstreamValidationDisposition.SKIP),
            (bootstrap.EvaluationContext.DOWNSTREAM_SECURITY_WORKFLOWS,
             bootstrap.PolicySource.POLICY,
             bootstrap.VersionDisposition.SAME_VERSION,
             bootstrap.CandidateEvidenceDisposition.SKIP,
             bootstrap.ProtectedEvidenceDisposition.TEST_INDEPENDENT_POLICY,
             bootstrap.DownstreamValidationDisposition.RUN),
        )
        for context, source, version, candidate, protected, downstream in matrix:
            with self.subTest(context=context, source=source, version=version):
                result = self.result(context, source, version)
                plan = bootstrap.derive_model_d_plan(result)
                self.assertEqual(plan, bootstrap.derive_model_d_plan(result))
                self.assertEqual(hash(plan), hash(bootstrap.derive_model_d_plan(result)))
                self.assertEqual(plan.normalization_roots, (
                    bootstrap.NormalizationRoot.CANDIDATE,
                    bootstrap.NormalizationRoot.POLICY,
                ))
                self.assertIs(plan.policy_lock_source, source)
                self.assertIs(plan.audit_lock_source, source)
                self.assertIs(plan.candidate_evidence, candidate)
                self.assertIs(plan.protected_evidence, protected)
                self.assertIs(plan.downstream_validation, downstream)

    def test_plan_schema_is_exact_immutable_and_closed(self) -> None:
        self.assertEqual(tuple(bootstrap.ModelDOrchestrationPlan.__dataclass_fields__), (
            "normalization_roots", "policy_lock_source", "audit_lock_source",
            "candidate_evidence", "protected_evidence", "downstream_validation",
        ))
        plan = bootstrap.derive_model_d_plan(self.result(
            bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
            bootstrap.PolicySource.CANDIDATE,
            bootstrap.VersionDisposition.SAME_VERSION))
        with self.assertRaises((AttributeError, TypeError)):
            plan.policy_lock_source = bootstrap.PolicySource.POLICY
        with self.assertRaises(ValueError):
            bootstrap.CandidateEvidenceDisposition("RUN_ARBITRARY")
        with self.assertRaises(ValueError):
            bootstrap.ProtectedEvidenceDisposition("candidate\nINJECT")
        with self.assertRaises(ValueError):
            bootstrap.DownstreamValidationDisposition("DEFAULT_SUCCESS")
        for field, invalid in (
                ("normalization_roots", [bootstrap.NormalizationRoot.CANDIDATE,
                                          bootstrap.NormalizationRoot.POLICY]),
                ("normalization_roots", ("candidate", bootstrap.NormalizationRoot.POLICY)),
                ("policy_lock_source", "candidate"),
                ("audit_lock_source", "candidate"),
                ("candidate_evidence", "RUN_STAGE_A"),
                ("protected_evidence", "RUN_LEGACY_HEALTH"),
                ("downstream_validation", "SKIP")):
            with self.subTest(field=field), self.assertRaises(bootstrap.BootstrapError):
                replace(plan, **{field: invalid})

    def test_unsupported_authority_combinations_fail_closed(self) -> None:
        supported = {
            (bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
             bootstrap.PolicySource.CANDIDATE,
             bootstrap.VersionDisposition.SAME_VERSION),
            (bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
             bootstrap.PolicySource.POLICY,
             bootstrap.VersionDisposition.IMMEDIATE_SUCCESSOR),
            (bootstrap.EvaluationContext.STAGE_A_PROTECTED_PROOF,
             bootstrap.PolicySource.POLICY,
             bootstrap.VersionDisposition.SAME_VERSION),
            (bootstrap.EvaluationContext.DOWNSTREAM_SECURITY_WORKFLOWS,
             bootstrap.PolicySource.POLICY,
             bootstrap.VersionDisposition.SAME_VERSION),
        }
        for context in bootstrap.EvaluationContext:
            for source in bootstrap.PolicySource:
                for version in bootstrap.VersionDisposition:
                    if (context, source, version) in supported:
                        continue
                    with self.subTest(context=context, source=source, version=version):
                        with self.assertRaises(bootstrap.BootstrapError):
                            bootstrap.derive_model_d_plan(
                                self.result(context, source, version))

    def test_malformed_tampered_and_injected_inputs_fail_closed(self) -> None:
        valid = self.result(
            bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
            bootstrap.PolicySource.CANDIDATE,
            bootstrap.VersionDisposition.SAME_VERSION)
        invalid = (
            None,
            {},
            bootstrap.BootstrapResult(
                "SELF_PR_BOOTSTRAP", bootstrap.PolicySource.CANDIDATE,
                bootstrap.VersionDisposition.SAME_VERSION, "REQUIRED", "REQUIRED"),
            bootstrap.BootstrapResult(
                bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP, "candidate",
                bootstrap.VersionDisposition.SAME_VERSION, "REQUIRED", "REQUIRED"),
            bootstrap.BootstrapResult(
                bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
                bootstrap.PolicySource.CANDIDATE, "SAME_VERSION",
                "REQUIRED", "REQUIRED"),
            bootstrap.BootstrapResult(
                bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
                bootstrap.PolicySource.CANDIDATE,
                bootstrap.VersionDisposition.SAME_VERSION,
                "REQUIRED\npolicy-source=policy", "REQUIRED"),
            bootstrap.BootstrapResult(
                bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
                bootstrap.PolicySource.CANDIDATE,
                bootstrap.VersionDisposition.SAME_VERSION,
                "REQUIRED", "OPTIONAL"),
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.derive_model_d_plan(value)

        object.__setattr__(valid, "candidate_plan", "RUN_ARBITRARY")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.derive_model_d_plan(valid)

        class CandidateResult(bootstrap.BootstrapResult):
            pass

        candidate = CandidateResult(
            bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
            bootstrap.PolicySource.CANDIDATE,
            bootstrap.VersionDisposition.SAME_VERSION,
            bootstrap.OWNER_AUTHORIZATION, bootstrap.POST_MERGE_PROOF)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.derive_model_d_plan(candidate)

    def test_plan_derivation_has_no_io_command_or_mutable_global_authority(self) -> None:
        result = self.result(
            bootstrap.EvaluationContext.STAGE_A_PROTECTED_PROOF,
            bootstrap.PolicySource.POLICY,
            bootstrap.VersionDisposition.SAME_VERSION)
        before = dict(vars(result))
        with mock.patch.object(bootstrap.subprocess, "run",
                               side_effect=AssertionError("command execution")), \
             mock.patch.object(Path, "read_bytes",
                               side_effect=AssertionError("filesystem authority")):
            plan = bootstrap.derive_model_d_plan(result)
        self.assertEqual(vars(result), before)
        self.assertEqual(plan.normalization_roots, (
            bootstrap.NormalizationRoot.CANDIDATE,
            bootstrap.NormalizationRoot.POLICY,
        ))

    def test_d3_workflow_plan_dispositions_and_five_key_contract(self) -> None:
        workflow_path = Path(__file__).parent / ".github/workflows/security-workflows-policy.yml"
        workflow = yaml.load(workflow_path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        by_name = {step["name"]: step for step in steps}
        self.assertEqual(
            by_name["Run candidate Stage A evidence"]["if"],
            "steps.protected-model-d.outputs.candidate-evidence == 'RUN_CANDIDATE_STAGE_A_EVIDENCE'")
        self.assertEqual(
            by_name["Run legacy protected health"]["if"],
            "steps.protected-model-d.outputs.protected-evidence == 'RUN_LEGACY_PROTECTED_HEALTH'")
        self.assertEqual(
            by_name["Apply protected Stage A baseline to candidate target"]["if"],
            "steps.protected-model-d.outputs.protected-evidence == 'APPLY_PROTECTED_STAGE_A_TO_CANDIDATE'")
        self.assertEqual(
            by_name["Test independent root policy"]["if"],
            "steps.protected-model-d.outputs.protected-evidence == 'TEST_INDEPENDENT_ROOT_POLICY'")
        self.assertEqual(
            by_name["Validate downstream security workflows"]["if"],
            "steps.protected-model-d.outputs.downstream-validation == 'RUN_DOWNSTREAM_VALIDATION'")
        self.assertEqual(bootstrap._OUTPUT_KEYS, (
            "evaluation-context", "policy-source", "version-disposition",
            "owner-authorization", "post-merge-proof",
        ))
        self.assertIn("run-model-d", workflow_path.read_text(encoding="utf-8"))

    def test_d3_workflow_has_one_plan_source_and_fatal_mechanics(self) -> None:
        text = (Path(__file__).parent /
                ".github/workflows/security-workflows-policy.yml").read_text(encoding="utf-8")
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        names = [step["name"] for step in steps]
        self.assertNotIn("Normalize and verify committed policy bytes", names)
        self.assertEqual(text.count("run-model-d --event-name"), 1)
        self.assertNotIn("foreach ($root in @('candidate', 'policy'))", text)
        self.assertNotIn("$env:POLICY_SOURCE/requirements-", text)
        self.assertNotIn("$env:POLICY_LOCK_ROOT", text)
        self.assertNotIn("$env:AUDIT_LOCK_ROOT", text)
        self.assertNotIn("GITHUB_ENV", text)
        authority = names.index("Resolve protected bootstrap authority")
        admission = names.index("Enforce exact Model D maintenance admission")
        plan = names.index("Resolve protected Model D orchestration")
        install = names.index("Install isolated hash-locked policy environment")
        self.assertLess(authority, admission)
        self.assertLess(admission, plan)
        self.assertLess(plan, install)
        for step in steps:
            if "run" in step and step["name"] not in (
                    "Assert protected bootstrap outputs", "Assert protected Model D outputs"):
                self.assertIn("$LASTEXITCODE -ne 0", step["run"])
        for name in ("Run candidate Stage A evidence", "Run legacy protected health",
                     "Apply protected Stage A baseline to candidate target",
                     "Test independent root policy", "Validate downstream security workflows"):
            self.assertIn("steps.protected-model-d.outputs.",
                          next(step for step in steps if step["name"] == name)["if"])
            self.assertNotIn("evaluation-context",
                             next(step for step in steps if step["name"] == name)["if"])

    def test_d3_every_native_command_has_immediate_fatal_guard(self) -> None:
        workflow = yaml.load(
            (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml")
            .read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        command = re.compile(
            r"^(?:git\s|python\s|\.\\(?:policy-env|audit-env)\\Scripts\\python\.exe\s|"
            r"\$[A-Za-z]+\s*=\s*\(?(?:git|python)\s)")
        guard = "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"

        def missing_guard(run: str) -> bool:
            lines = [line.strip() for line in run.splitlines() if line.strip()]
            return any(command.match(line) and (index + 1 == len(lines) or
                       lines[index + 1] != guard)
                       for index, line in enumerate(lines))

        checked = 0
        for step in steps:
            if "run" not in step:
                continue
            run = step["run"]
            self.assertFalse(missing_guard(run), step["name"])
            for index, line in enumerate(run.splitlines()):
                if line.strip() != guard:
                    continue
                changed = run.splitlines()
                changed[index] = "  $null = 1"
                if missing_guard("\n".join(changed)):
                    checked += 1
        self.assertGreaterEqual(checked, 20)


class ModelDClosedPowerShellProfileTests(unittest.TestCase):
    """D4 closed profile for the one protected Model D workflow, not generic PS."""

    _AST_TYPES = frozenset({
        "ArrayExpressionAst", "ArrayLiteralAst", "AssignmentStatementAst",
        "BinaryExpressionAst", "CommandAst", "CommandExpressionAst",
        "CommandParameterAst", "ConstantExpressionAst", "ExitStatementAst",
        "ExpandableStringExpressionAst", "IfStatementAst", "InvokeMemberExpressionAst",
        "NamedBlockAst", "ParenExpressionAst", "PipelineAst", "ScriptBlockAst",
        "StatementBlockAst", "StringConstantExpressionAst", "ThrowStatementAst",
        "VariableExpressionAst",
    })
    _COMMANDS = {
        "Assert exact CPython runtime": ("python",),
        "Acquire protected Git identity": ("git", "Out-File"),
        "Resolve protected bootstrap authority": ("git", "git", "git", "git", "git", "python"),
        "Assert protected bootstrap outputs": (),
        "Enforce exact Model D maintenance admission": ("python",),
        "Resolve protected Model D orchestration": ("python",),
        "Assert protected Model D outputs": (),
        "Install isolated hash-locked policy environment":
            ("python",) + (r".\policy-env\Scripts\python.exe",) * 3,
        "Run candidate Stage A evidence": (r".\policy-env\Scripts\python.exe",),
        "Run legacy protected health": (r".\policy-env\Scripts\python.exe",),
        "Apply protected Stage A baseline to candidate target":
            (r".\policy-env\Scripts\python.exe",),
        "Test independent root policy": (r".\policy-env\Scripts\python.exe",),
        "Install isolated hash-locked audit environment":
            ("python",) + (r".\audit-env\Scripts\python.exe",) * 3,
        "Audit locked policy dependencies": (r".\audit-env\Scripts\python.exe",),
        "Validate downstream security workflows": (r".\policy-env\Scripts\python.exe",),
    }
    # Fixed command/argument forms and GitHub bindings for this one workflow.
    # AST parsing uses BOUND placeholders, so source expressions are pinned separately.
    _COMMAND_DIGESTS = {
        "Assert exact CPython runtime": "ff4765d5070a8f20c672195931f3296bd7f98d025cc603a3253336a1909ef10a",
        "Acquire protected Git identity": "c46b07aa33fec226c61a81e56ac420d8ca2d7335557f1098132ba9a518dd3de4",
        "Resolve protected bootstrap authority": "1033bc372e862723b7301df8269c8d55268af0263a4049e665c44a2bd491e9d1",
        "Enforce exact Model D maintenance admission": "a27a6cb21b57491d4f10396fcd1e05d9f1db6cc2e3570a5b6c28b2828c6fab66",
        "Resolve protected Model D orchestration": "55508070002061086a43cc0996f426eda44cb46106fb1094c77bcb7cd3885713",
        "Install isolated hash-locked policy environment": "ee8dac9367b0f079fcccfb636cceee965b4802e963649a1645a5da2be9fb3520",
        "Run candidate Stage A evidence": "c6a33626a4760d1526501debed802cb4d810f4885103ab660032ed345d92d296",
        "Run legacy protected health": "435b6b77a7e2d99f14a71ee6474e163492bd72b0dd516bd63f305393af4853fa",
        "Apply protected Stage A baseline to candidate target": "5ad3325fe6559847a7a7cdaddee067938df81bfe0156b179dc6dcbaf0c77d8d6",
        "Test independent root policy": "435b6b77a7e2d99f14a71ee6474e163492bd72b0dd516bd63f305393af4853fa",
        "Install isolated hash-locked audit environment": "b96ce83b8b71555e5b23570d0f7d92f5ff1fc3f38b5b264ad7902f119980813f",
        "Audit locked policy dependencies": "0c70fcfd7f2074edd996e1deaf7ca5ac06ab49c6e578e525a6321c8bb7ec17ec",
        "Validate downstream security workflows": "98622aeb4b2c26df74de7cbcd68750ffebb2ad7de78a6abd1b6df9c7045d8be8",
    }
    _EXPRESSION_DIGESTS = {
        "Acquire protected Git identity": "837295a19625c7f7bacd0c82e6bfe4238723e8266b416182ada72993d5b20023",
        "Resolve protected bootstrap authority": "d10fe55d40daab7b732dc2414601063a036a64f8fd75abe71ecfa089546a4ff2",
        "Enforce exact Model D maintenance admission": "29db63d8930ddf1d99aec626572563076a3f2c429d6c7b4e6c23889c7b4484aa",
        "Resolve protected Model D orchestration": "3b75d73c87092e553ff4a60922371a26049cb145e72d34863a65df263987a6c7",
        "Install isolated hash-locked policy environment": "6d079a592228d8f8d41be75c44f12aadbf9c7a04a268939af4f9ab330c84ed45",
        "Install isolated hash-locked audit environment": "14db3625de27e1630df2c448364e8b26521bb169aecceac851a270172d6ffa61",
        "Audit locked policy dependencies": "6d079a592228d8f8d41be75c44f12aadbf9c7a04a268939af4f9ab330c84ed45",
    }
    _ASSIGNMENT_DIGESTS = {
        "Assert exact CPython runtime": "d28dad29c037f617afecde27704bef3d358314acff79e6e0dc6e838ef68ddbab",
        "Acquire protected Git identity": "a7957a942a016cffc750015c04cc690d6976cd3094083d8b79f364380ba25791",
        "Resolve protected bootstrap authority": "7345417463fdbf2b043e1c7a229cc9ce631efc2c8de8348111022a2d6e8df5d6",
    }
    _STOP_ASSIGNMENT_DIGEST = "a6ff9ace77f1623d434a131b94c045ea59228ca4c1afaffe3900356c386bb1a5"
    _IF = {
        "Enforce exact Model D maintenance admission":
            "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP'",
        "Run candidate Stage A evidence":
            "steps.protected-model-d.outputs.candidate-evidence == 'RUN_CANDIDATE_STAGE_A_EVIDENCE'",
        "Run legacy protected health":
            "steps.protected-model-d.outputs.protected-evidence == 'RUN_LEGACY_PROTECTED_HEALTH'",
        "Apply protected Stage A baseline to candidate target":
            "steps.protected-model-d.outputs.protected-evidence == 'APPLY_PROTECTED_STAGE_A_TO_CANDIDATE'",
        "Test independent root policy":
            "steps.protected-model-d.outputs.protected-evidence == 'TEST_INDEPENDENT_ROOT_POLICY'",
        "Validate downstream security workflows":
            "steps.protected-model-d.outputs.downstream-validation == 'RUN_DOWNSTREAM_VALIDATION'",
    }
    _ASSERTIONS = {
        "Assert exact CPython runtime": ("$pythonVersion -ne '3.12.10'",),
        "Acquire protected Git identity": ("$protectedSha -notmatch '^[0-9a-f]{40}$'",),
        "Resolve protected bootstrap authority": (
            "$observedHead -ne $candidateSha",
            "$expectedBlob -notmatch '^[0-9a-f]{40}$'",
            "$actualBlob -ne $expectedBlob",
        ),
        "Assert protected bootstrap outputs": (
            "$env:EVALUATION_CONTEXT -notin @('SELF_PR_BOOTSTRAP', 'STAGE_A_PROTECTED_PROOF', 'DOWNSTREAM_SECURITY_WORKFLOWS')",
            "$env:POLICY_SOURCE -notin @('candidate', 'policy')",
            "$env:VERSION_DISPOSITION -notin @('SAME_VERSION', 'IMMEDIATE_SUCCESSOR')",
            "$env:OWNER_AUTHORIZATION -ne 'REQUIRED'",
            "$env:POST_MERGE_PROOF -ne 'REQUIRED'",
        ),
        "Assert protected Model D outputs": (
            "$env:MODEL_D_CONTEXT -ne $env:D0_CONTEXT -or $env:MODEL_D_SOURCE -ne $env:D0_SOURCE -or $env:MODEL_D_VERSION -ne $env:D0_VERSION",
            "$env:MODEL_D_OWNER -ne 'REQUIRED' -or $env:MODEL_D_PROOF -ne 'REQUIRED'",
            "$env:NORMALIZATION_ROOTS -notmatch '^[a-z]+(,[a-z]+)*$'",
            "$env:POLICY_LOCK_SOURCE -notin @('candidate', 'policy')",
            "$env:AUDIT_LOCK_SOURCE -notin @('candidate', 'policy')",
            "$env:CANDIDATE_EVIDENCE -notin @('RUN_CANDIDATE_STAGE_A_EVIDENCE', 'SKIP')",
            "$env:PROTECTED_EVIDENCE -notin @('RUN_LEGACY_PROTECTED_HEALTH', 'APPLY_PROTECTED_STAGE_A_TO_CANDIDATE', 'TEST_INDEPENDENT_ROOT_POLICY')",
            "$env:DOWNSTREAM_VALIDATION -notin @('RUN_DOWNSTREAM_VALIDATION', 'SKIP')",
        ),
    }
    _VARIABLES = frozenset({
        "actualBlob", "candidateRoot", "candidateSha", "ErrorActionPreference",
        "expectedBlob", "LASTEXITCODE", "observedHead", "protectedSha",
        "pythonVersion", "workflowPath", "env:GITHUB_OUTPUT",
        "env:AUDIT_LOCK_SOURCE", "env:CANDIDATE_EVIDENCE", "env:D0_CONTEXT",
        "env:D0_SOURCE", "env:D0_VERSION", "env:DOWNSTREAM_VALIDATION",
        "env:EVALUATION_CONTEXT", "env:MODEL_D_CONTEXT", "env:MODEL_D_OWNER",
        "env:MODEL_D_PROOF", "env:MODEL_D_SOURCE", "env:MODEL_D_VERSION",
        "env:NORMALIZATION_ROOTS", "env:OWNER_AUTHORIZATION",
        "env:POLICY_LOCK_SOURCE", "env:POLICY_SOURCE", "env:POST_MERGE_PROOF",
        "env:PROTECTED_EVIDENCE", "env:VERSION_DISPOSITION",
    })
    _ASSIGNMENTS = frozenset({
        "$ErrorActionPreference", "$pythonVersion", "$protectedSha",
        "$candidateRoot", "$candidateSha", "$observedHead", "$workflowPath",
        "$expectedBlob", "$actualBlob",
    })
    _INSPECTOR = r'''
$ErrorActionPreference = 'Stop'
$items = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
$reports = @(foreach ($item in $items) {
  $source = [regex]::Replace([string]$item.run, '\$\{\{.*?\}\}', 'BOUND')
  $tokens = $null; $errors = $null
  $tree = [System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors)
  $nodes = @($tree.FindAll({param($node) $true}, $true))
  $ifs = @($nodes | Where-Object { $_ -is [System.Management.Automation.Language.IfStatementAst] })
  [pscustomobject]@{
    name = $item.name
    errors = @($errors | ForEach-Object { $_.Message })
    types = @($nodes | ForEach-Object { $_.GetType().Name } | Select-Object -Unique)
    commands = @($nodes | Where-Object { $_ -is [System.Management.Automation.Language.CommandAst] } | ForEach-Object { $_.GetCommandName() })
    commandTexts = @($nodes | Where-Object { $_ -is [System.Management.Automation.Language.CommandAst] } | ForEach-Object { $_.Extent.Text })
    variables = @($nodes | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] } | ForEach-Object { $_.VariablePath.UserPath } | Select-Object -Unique)
    assignments = @($nodes | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] } | ForEach-Object { $_.Left.Extent.Text })
    assignmentTexts = @($nodes | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] } | ForEach-Object { $_.Extent.Text })
    outputPipelines = @($nodes | Where-Object { $_ -is [System.Management.Automation.Language.PipelineAst] -and $_.Extent.Text -match '\bOut-File\b' } | ForEach-Object { $_.Extent.Text })
    conditions = @($ifs | ForEach-Object { $_.Clauses[0].Item1.Extent.Text })
    bodies = @($ifs | ForEach-Object { $_.Clauses[0].Item2.Extent.Text.Trim() })
    elseCount = @($ifs | Where-Object { $_.ElseClause -or $_.Clauses.Count -ne 1 }).Count
  }
})
ConvertTo-Json -InputObject $reports -Depth 5 -Compress
'''

    @staticmethod
    def _parse_workflow(text: str) -> dict[str, object]:
        node = yaml.compose(text, Loader=yaml.BaseLoader)
        if node is None:
            raise AssertionError("Empty Model D workflow")

        def visit(current: yaml.Node) -> None:
            if isinstance(current, yaml.MappingNode):
                seen: set[str] = set()
                for key, value in current.value:
                    if not isinstance(key, yaml.ScalarNode) or key.value in seen:
                        raise AssertionError("Duplicate or non-scalar Model D YAML key")
                    seen.add(key.value)
                    visit(value)
            elif isinstance(current, yaml.SequenceNode):
                for member in current.value:
                    visit(member)

        visit(node)
        return yaml.load(text, Loader=yaml.BaseLoader)

    @classmethod
    def _workflow(cls) -> dict[str, object]:
        path = Path(__file__).parent / ".github/workflows/security-workflows-policy.yml"
        return cls._parse_workflow(path.read_text(encoding="utf-8"))

    def _inspect(self, steps: list[dict[str, object]]) -> dict[str, dict[str, object]]:
        blocks = [{"name": step["name"], "run": step["run"]}
                  for step in steps if "run" in step]
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", self._INSPECTOR],
            input=json.dumps(blocks), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        reports = json.loads(result.stdout)
        self.assertEqual(len(reports), len(blocks))
        return {report["name"]: report for report in reports}

    def _assert_closed(self, workflow: dict[str, object]) -> None:
        self.assertEqual(set(workflow), {"name", "on", "permissions", "env", "jobs"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(workflow["on"]), {"pull_request", "merge_group", "workflow_dispatch"})
        self.assertEqual(workflow["env"], {
            "POLICY_BASELINE_VERSION": bootstrap.CURRENT_BASELINE,
            "MODEL_D_MAINTENANCE_GENERATION": bootstrap.MODEL_D_MAINTENANCE_GENERATION,
        })
        self.assertEqual(tuple(workflow["jobs"]), ("security-workflows-policy",))
        job = workflow["jobs"]["security-workflows-policy"]
        self.assertEqual(set(job), {"name", "runs-on", "steps"})
        self.assertEqual(job["runs-on"], "windows-latest")
        steps = job["steps"]
        self.assertEqual([step["name"] for step in steps], [
            "Check out exact candidate", "Check out independent root policy",
            "Set up CPython", *self._COMMANDS,
        ])
        self.assertEqual({step["name"]: step["if"] for step in steps if "if" in step},
                         self._IF)
        self.assertTrue(all("continue-on-error" not in step for step in steps))
        for step in steps:
            allowed = ({"name", "uses", "with"} if "uses" in step else
                       {"name", "shell", "run"} |
                       ({"id"} if "id" in step else set()) |
                       ({"if"} if "if" in step else set()) |
                       ({"env"} if "env" in step else set()))
            self.assertEqual(set(step), allowed, step["name"])
            if "run" in step:
                self.assertEqual(step["shell"], "pwsh", step["name"])
        expected_env = {
            "Assert protected bootstrap outputs": {
                "EVALUATION_CONTEXT": "evaluation-context",
                "POLICY_SOURCE": "policy-source",
                "VERSION_DISPOSITION": "version-disposition",
                "OWNER_AUTHORIZATION": "owner-authorization",
                "POST_MERGE_PROOF": "post-merge-proof",
            },
            "Assert protected Model D outputs": {
                "D0_CONTEXT": "evaluation-context", "D0_SOURCE": "policy-source",
                "D0_VERSION": "version-disposition",
                "MODEL_D_CONTEXT": "evaluation-context", "MODEL_D_SOURCE": "policy-source",
                "MODEL_D_VERSION": "version-disposition",
                "MODEL_D_OWNER": "owner-authorization", "MODEL_D_PROOF": "post-merge-proof",
                "NORMALIZATION_ROOTS": "normalization-roots",
                "POLICY_LOCK_SOURCE": "policy-lock-source",
                "AUDIT_LOCK_SOURCE": "audit-lock-source",
                "CANDIDATE_EVIDENCE": "candidate-evidence",
                "PROTECTED_EVIDENCE": "protected-evidence",
                "DOWNSTREAM_VALIDATION": "downstream-validation",
            },
        }
        self.assertEqual({step["name"] for step in steps if "env" in step},
                         set(expected_env) | {"Apply protected Stage A baseline to candidate target"})
        by_name = {step["name"]: step for step in steps}
        for name, keys in expected_env.items():
            expected = {}
            for key, output in keys.items():
                source = ("protected-bootstrap" if name == "Assert protected bootstrap outputs"
                          or key.startswith("D0_") else "protected-model-d")
                expected[key] = "${{ steps." + source + ".outputs." + output + " }}"
            self.assertEqual(by_name[name]["env"], expected)
        self.assertEqual(set(by_name["Apply protected Stage A baseline to candidate target"]["env"]), {
            "POLICY_CANDIDATE_ROOT", "POLICY_PROTECTED_ROOT", "POLICY_EXPECTED_REPOSITORY",
            "POLICY_EXPECTED_CANDIDATE_SHA", "POLICY_EXPECTED_PROTECTED_SHA",
            "POLICY_EXPECTED_BASE_REPOSITORY", "POLICY_EXPECTED_BASE_BRANCH",
            "POLICY_EXPECTED_EVENT",
        })
        self.assertEqual({step["name"]: step["id"] for step in steps if "id" in step}, {
            "Acquire protected Git identity": "protected-git",
            "Resolve protected bootstrap authority": "protected-bootstrap",
            "Resolve protected Model D orchestration": "protected-model-d",
        })
        self.assertEqual(steps[0]["with"]["path"], "candidate")
        self.assertEqual(steps[1]["with"]["path"], "policy")
        self.assertEqual(steps[0]["with"]["fetch-depth"], "0")
        self.assertEqual(steps[1]["with"]["fetch-depth"], "0")
        self.assertEqual(steps[2]["with"]["python-version"], "3.12.10")
        self.assertIn('policy/protected_policy_bootstrap.py" evaluate',
                      by_name["Resolve protected bootstrap authority"]["run"])
        self.assertIn('policy/protected_policy_bootstrap.py" admit-maintenance',
                      by_name["Enforce exact Model D maintenance admission"]["run"])
        self.assertIn('policy/protected_policy_bootstrap.py" run-model-d',
                      by_name["Resolve protected Model D orchestration"]["run"])
        for name, output, lock in (
                ("Install isolated hash-locked policy environment", "policy-lock-source", "requirements-policy.lock"),
                ("Install isolated hash-locked audit environment", "audit-lock-source", "requirements-audit.lock"),
                ("Audit locked policy dependencies", "policy-lock-source", "requirements-policy.lock")):
            self.assertIn(f"${{{{ steps.protected-model-d.outputs.{output} }}}}/{lock}",
                          by_name[name]["run"])
        reports = self._inspect(steps)
        for name, commands in self._COMMANDS.items():
            run = by_name[name]["run"]
            report = reports[name]
            self.assertEqual(report["errors"], [], name)
            self.assertTrue(set(report["types"]) <= self._AST_TYPES, name)
            self.assertEqual(tuple(report["commands"]), commands, name)
            command_digest = hashlib.sha256(
                "\0".join(report["commandTexts"]).encode("utf-8")).hexdigest()
            self.assertEqual(command_digest, self._COMMAND_DIGESTS.get(
                name, hashlib.sha256(b"").hexdigest()), name)
            expressions = re.findall(r"\$\{\{.*?\}\}", run)
            expression_digest = hashlib.sha256(
                "\0".join(expressions).encode("utf-8")).hexdigest()
            self.assertEqual(expression_digest, self._EXPRESSION_DIGESTS.get(
                name, hashlib.sha256(b"").hexdigest()), name)
            self.assertTrue(set(report["variables"]) <= self._VARIABLES, name)
            self.assertTrue(set(report["assignments"]) <= self._ASSIGNMENTS, name)
            assignment_digest = hashlib.sha256(
                "\0".join(report["assignmentTexts"]).encode("utf-8")).hexdigest()
            self.assertEqual(assignment_digest, self._ASSIGNMENT_DIGESTS.get(
                name, self._STOP_ASSIGNMENT_DIGEST), name)
            self.assertEqual(report["outputPipelines"],
                             ['"protected-sha=$protectedSha" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append']
                             if name == "Acquire protected Git identity" else [], name)
            self.assertEqual(report["elseCount"], 0, name)
            self.assertTrue(run.lstrip().startswith("$ErrorActionPreference = 'Stop'"), name)
            assertions = tuple(condition for condition in report["conditions"]
                               if condition != "$LASTEXITCODE -ne 0")
            self.assertEqual(assertions, self._ASSERTIONS.get(name, ()), name)
            guard_count = report["conditions"].count("$LASTEXITCODE -ne 0")
            self.assertEqual(guard_count,
                             len(commands) - (1 if "Out-File" in commands else 0), name)
            for condition, body in zip(report["conditions"], report["bodies"]):
                if condition == "$LASTEXITCODE -ne 0":
                    self.assertEqual(body, "{ exit $LASTEXITCODE }", name)
                else:
                    self.assertRegex(body, r"^\{ throw '[^'\r\n]+' \}$", name)

    def test_current_workflow_has_closed_ast_and_structure(self) -> None:
        self._assert_closed(self._workflow())

    def test_comments_and_string_text_do_not_create_ast_authority(self) -> None:
        workflow = self._workflow()
        step = workflow["jobs"]["security-workflows-policy"]["steps"][3]
        step["run"] += "\n# Invoke-Expression $env:GITHUB_ENV is forbidden as code\n"
        step["run"] = step["run"].replace(
            "Unexpected CPython version",
            "Invoke-Expression $env:GITHUB_ENV is inert inside this string")
        self._assert_closed(workflow)

    def test_duplicate_yaml_output_key_rejects_before_profile(self) -> None:
        path = Path(__file__).parent / ".github/workflows/security-workflows-policy.yml"
        source = path.read_text(encoding="utf-8")
        marker = "          MODEL_D_CONTEXT: ${{ steps.protected-model-d.outputs.evaluation-context }}"
        self.assertIn(marker, source)
        mutated = source.replace(marker, marker + "\n" + marker, 1)
        with self.assertRaisesRegex(AssertionError, "Duplicate"):
            self._parse_workflow(mutated)

    def test_protected_output_assertion_executes_and_rejects_mutations(self) -> None:
        workflow = self._workflow()
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        run = next(step["run"] for step in steps
                   if step["name"] == "Assert protected Model D outputs")
        values = {
            "D0_CONTEXT": "SELF_PR_BOOTSTRAP", "D0_SOURCE": "candidate",
            "D0_VERSION": "SAME_VERSION", "MODEL_D_CONTEXT": "SELF_PR_BOOTSTRAP",
            "MODEL_D_SOURCE": "candidate", "MODEL_D_VERSION": "SAME_VERSION",
            "MODEL_D_OWNER": "REQUIRED", "MODEL_D_PROOF": "REQUIRED",
            "NORMALIZATION_ROOTS": "candidate,policy", "POLICY_LOCK_SOURCE": "candidate",
            "AUDIT_LOCK_SOURCE": "candidate",
            "CANDIDATE_EVIDENCE": "RUN_CANDIDATE_STAGE_A_EVIDENCE",
            "PROTECTED_EVIDENCE": "RUN_LEGACY_PROTECTED_HEALTH",
            "DOWNSTREAM_VALIDATION": "SKIP",
        }

        def execute(changes: dict[str, str | None]) -> subprocess.CompletedProcess[str]:
            environment = os.environ.copy()
            environment.update(values)
            for key, value in changes.items():
                if value is None:
                    environment.pop(key, None)
                else:
                    environment[key] = value
            return subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-Command", run],
                env=environment, capture_output=True, text=True)

        self.assertEqual(execute({}).returncode, 0)
        mutations = (
            {"MODEL_D_CONTEXT": "DOWNSTREAM_SECURITY_WORKFLOWS"},
            {"POLICY_LOCK_SOURCE": None}, {"AUDIT_LOCK_SOURCE": "foreign"},
            {"CANDIDATE_EVIDENCE": "RUN_CANDIDATE_STAGE_A_EVIDENCE\nX=Y"},
            {"PROTECTED_EVIDENCE": "SKIP"}, {"DOWNSTREAM_VALIDATION": "RUN_OTHER"},
            {"MODEL_D_OWNER": "OPTIONAL"}, {"NORMALIZATION_ROOTS": "policy,candidate\nX=Y"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.assertNotEqual(execute(mutation).returncode, 0)

    def test_real_powershell_propagates_native_failure_immediately(self) -> None:
        workflow = self._workflow()
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        for name in ("Resolve protected Model D orchestration",
                     "Install isolated hash-locked policy environment",
                     "Run candidate Stage A evidence", "Run legacy protected health",
                     "Install isolated hash-locked audit environment",
                     "Audit locked policy dependencies", "Validate downstream security workflows"):
            run = next(step["run"] for step in steps if step["name"] == name)
            guard = next(line.strip() for line in run.splitlines()
                         if line.strip().startswith("if ($LASTEXITCODE -ne 0)"))
            probe = "python -c 'import sys; sys.exit(23)'\n" + guard + "\nWrite-Output REACHED"
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-Command", probe],
                capture_output=True, text=True)
            with self.subTest(step=name):
                self.assertEqual(result.returncode, 23, result.stderr or result.stdout)
                self.assertNotIn("REACHED", result.stdout)

    def test_model_d_output_schema_tampering_fails_closed(self) -> None:
        result = bootstrap.BootstrapResult(
            bootstrap.EvaluationContext.SELF_PR_BOOTSTRAP,
            bootstrap.PolicySource.CANDIDATE,
            bootstrap.VersionDisposition.SAME_VERSION,
            bootstrap.OWNER_AUTHORIZATION, bootstrap.POST_MERGE_PROOF)
        plan = bootstrap.derive_model_d_plan(result)
        self.assertEqual(len(bootstrap._validated_model_d_outputs(plan)), 6)
        for schema in (
                bootstrap._MODEL_D_OUTPUT_KEYS[:-1],
                bootstrap._MODEL_D_OUTPUT_KEYS[:-1] +
                (bootstrap._MODEL_D_OUTPUT_KEYS[0],),
                bootstrap._MODEL_D_OUTPUT_KEYS[:-1] + ("unknown-output",)):
            with self.subTest(schema=schema), mock.patch.object(
                    bootstrap, "_MODEL_D_OUTPUT_KEYS", schema):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap._validated_model_d_outputs(plan)
        object.__setattr__(plan, "candidate_evidence", "RUN\nforged=value")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._validated_model_d_outputs(plan)

    def test_authority_control_and_order_mutations_reject(self) -> None:
        original = self._workflow()
        cases = (
            ("context branch", "Run candidate Stage A evidence", "if",
             "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP'"),
            ("missing disposition", "Run candidate Stage A evidence", "if", ""),
            ("candidate authority", "Run candidate Stage A evidence", "if",
             "github.event.pull_request.head.sha != ''"),
            ("ignored error", "Install isolated hash-locked policy environment",
             "run", "continue-on-error: true"),
        )
        for label, step_name, field, value in cases:
            with self.subTest(label=label):
                workflow = json.loads(json.dumps(original))
                step = next(item for item in workflow["jobs"]["security-workflows-policy"]["steps"]
                            if item["name"] == step_name)
                if field == "run":
                    step[field] += "\n" + value
                else:
                    step[field] = value
                with self.assertRaises(AssertionError):
                    self._assert_closed(workflow)
        for label, mutate in (
                ("later authority", lambda steps: steps.insert(10, steps.pop(8))),
                ("missing validation", lambda steps: steps.pop(9)),
                ("downstream before authority", lambda steps: steps.insert(5, steps.pop(-1)))):
            with self.subTest(label=label):
                workflow = json.loads(json.dumps(original))
                mutate(workflow["jobs"]["security-workflows-policy"]["steps"])
                with self.assertRaises(AssertionError):
                    self._assert_closed(workflow)

    def test_ast_forbidden_and_failure_mutations_reject(self) -> None:
        original = self._workflow()
        mutations = (
            "\nInvoke-Expression 'python -V'",
            "\n& python -V",
            "\ntry { python -V } catch { exit 0 }",
            "\ntrap { continue }",
            "\nStart-Job { python -V }",
            "\n$global:POLICY_SOURCE = 'candidate'",
            "\n$env:GITHUB_ENV = 'authority'",
            "\nif ($env:POLICY_SOURCE -eq 'policy') { exit 0 }",
            "\nforeach ($root in @('policy','candidate')) { git -C $root reset --hard HEAD }",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                workflow = json.loads(json.dumps(original))
                step = workflow["jobs"]["security-workflows-policy"]["steps"][5]
                step["run"] += mutation
                with self.assertRaises(AssertionError):
                    self._assert_closed(workflow)
        for label, before, after in (
                ("missing guard", "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }", ""),
                ("default success", "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                 "if ($LASTEXITCODE -ne 0) { exit 0 }"),
                ("error suppression", "$ErrorActionPreference = 'Stop'",
                 "$ErrorActionPreference = 'Continue'")):
            with self.subTest(label=label):
                workflow = json.loads(json.dumps(original))
                step = workflow["jobs"]["security-workflows-policy"]["steps"][5]
                step["run"] = step["run"].replace(before, after, 1)
                with self.assertRaises(AssertionError):
                    self._assert_closed(workflow)
        for label, step_name, before, after in (
                ("candidate SHA source", "Resolve protected bootstrap authority",
                 '--candidate-sha "${{ github.sha }}"',
                 '--candidate-sha "${{ github.event.pull_request.head.sha }}"'),
                ("venv isolation", "Install isolated hash-locked policy environment",
                 "python -m venv policy-env", "python -m venv policy-env --system-site-packages"),
                ("lock source", "Install isolated hash-locked audit environment",
                 "steps.protected-model-d.outputs.audit-lock-source",
                 "steps.protected-bootstrap.outputs.policy-source"),
                ("root literal", "Resolve protected bootstrap authority",
                 '${{ github.workspace }}/candidate', '${{ github.workspace }}/policy'),
                ("protected output key", "Acquire protected Git identity",
                 '"protected-sha=$protectedSha" | Out-File',
                 '"candidate-sha=$protectedSha" | Out-File'),
                ("parse error", "Resolve protected Model D orchestration",
                 "$ErrorActionPreference = 'Stop'", "$ErrorActionPreference = 'Stop'\nif (")):
            with self.subTest(label=label):
                workflow = json.loads(json.dumps(original))
                step = next(item for item in workflow["jobs"]["security-workflows-policy"]["steps"]
                            if item["name"] == step_name)
                self.assertIn(before, step["run"])
                step["run"] = step["run"].replace(before, after, 1)
                with self.assertRaises(AssertionError):
                    self._assert_closed(workflow)


class ModelDMaintenanceAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.protected = self.base / "protected authority with spaces"
        source = Path(__file__).parent.resolve()
        git_metadata = source / ".git"
        source_git_dir = git_metadata
        if git_metadata.is_file():
            source_git_dir = Path(
                git_metadata.read_text(encoding="utf-8").strip().removeprefix("gitdir: ")
            ).resolve()
        subprocess.run(
            ["git", "-c", f"safe.directory={source}",
             "-c", f"safe.directory={source_git_dir}", "clone", "--no-hardlinks",
             "--no-checkout", str(source), str(self.protected)],
            check=True, capture_output=True, text=True,
        )
        self._configure(self.protected)
        git(self.protected, "checkout", "-B", "main",
            "6a60970906f7bdf8d7a691f8309e38c09f8071e4")
        self.protected_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main",
            self.protected_sha)
        self.candidate = self._candidate("valid", bootstrap.MODEL_D_MAINTENANCE_PATHS)
        self.candidate_sha = git(self.candidate, "rev-parse", "HEAD")

    @staticmethod
    def _configure(root: Path) -> None:
        intended_head = git(root, "rev-parse", "HEAD")
        git(root, "config", "user.name", "Model D Admission Test")
        git(root, "config", "user.email", "model-d@example.invalid")
        git(root, "config", "core.autocrlf", "false")
        git(root, "reset", "--hard", intended_head)
        if git(root, "rev-parse", "HEAD") != intended_head:
            raise AssertionError("D0 fixture HEAD materialization mismatch")
        workflow = bootstrap.CANDIDATE_BASELINE_PATH
        committed_blob = git(root, "rev-parse", f"{intended_head}:{workflow}")
        worktree_blob = git(root, "hash-object", "--no-filters", workflow)
        if worktree_blob != committed_blob:
            raise AssertionError("D0 fixture workflow bytes differ from committed blob")
        git(root, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")

    @staticmethod
    def _modify(root: Path, paths: tuple[str, ...]) -> None:
        for name in paths:
            path = root / name
            path.write_bytes(path.read_bytes() + b"\n# model-d-admission-test\n")
        if "protected_policy_bootstrap.py" in paths:
            path = root / "protected_policy_bootstrap.py"
            data = path.read_bytes()
            old = (b'MODEL_D_MAINTENANCE_LIFECYCLE = '
                   b'"MODEL_D_ORCHESTRATION_V1_GENERATION_1:ACTIVE"')
            new = (b'MODEL_D_MAINTENANCE_LIFECYCLE = '
                   b'"MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED"')
            if data.count(old) == 1 and data.count(new) == 0:
                path.write_bytes(data.replace(old, new))
            elif data.count(old) == 0 and data.count(new) == 1:
                pass
            else:
                raise AssertionError("D0 candidate active-state declaration mismatch")

    def _candidate(self, name: str, paths: tuple[str, ...],
                   mutate=None) -> Path:
        root = self.base / f"candidate-{name}"
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--no-checkout",
             str(self.protected), str(root)],
            check=True, capture_output=True, text=True,
        )
        self._configure(root)
        git(root, "checkout", "-b", f"candidate-{name}")
        self._modify(root, paths)
        git(root, "add", "-A")
        if mutate is not None:
            mutate(root)
        git(root, "commit", "-m", name)
        return root

    def _validate(self, candidate: Path | None = None,
                  protected: Path | None = None,
                  operation: str | None = None,
                  generation: str | None = None) -> None:
        candidate_root = candidate or self.candidate
        protected_root = protected or self.protected
        bootstrap.validate_model_d_maintenance(
            (bootstrap.MODEL_D_MAINTENANCE_OPERATION
             if operation is None else operation),
            (bootstrap.MODEL_D_MAINTENANCE_GENERATION
             if generation is None else generation),
            candidate_root, protected_root,
            git(candidate_root, "rev-parse", "HEAD"),
            git(protected_root, "rev-parse", "HEAD"),
        )

    def test_exact_operation_base_scope_and_required_dispositions(self) -> None:
        self._validate()
        self.assertEqual(bootstrap.MODEL_D_MAINTENANCE_GENERATION,
                         "MODEL_D_ORCHESTRATION_V1_GENERATION_1")
        self.assertEqual(
            bootstrap.MODEL_D_MAINTENANCE_LIFECYCLE,
            "MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED")
        self.assertEqual(bootstrap.MODEL_D_MAINTENANCE_PATHS, (
            ".github/workflows/security-workflows-policy.yml",
            "protected_policy_bootstrap.py",
            "test_verify_security_workflows.py",
        ))
        self.assertEqual(bootstrap.OWNER_AUTHORIZATION, "REQUIRED")
        self.assertEqual(bootstrap.POST_MERGE_PROOF, "REQUIRED")
        self.assertEqual(len(bootstrap._OUTPUT_KEYS), 5)

    def test_operation_grammar_and_cli_fail_closed(self) -> None:
        arguments = [
            "admit-maintenance", "--maintenance-operation",
            bootstrap.MODEL_D_MAINTENANCE_OPERATION,
            "--maintenance-generation",
            bootstrap.MODEL_D_MAINTENANCE_GENERATION,
            "--candidate-sha", self.candidate_sha,
            "--protected-sha", self.protected_sha,
            "--candidate-root", str(self.candidate),
            "--protected-root", str(self.protected),
        ]
        completed = subprocess.run(
            [os.sys.executable, "-I", "-S",
             str(Path(bootstrap.__file__).resolve()), *arguments],
            capture_output=True, text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for bad in (
            arguments[2:],
            ["unknown-operation"],
            arguments[:2] + ["UNKNOWN"] + arguments[3:],
            arguments + ["--maintenance-operation",
                         bootstrap.MODEL_D_MAINTENANCE_OPERATION],
            arguments + ["--maintenance-generation",
                         bootstrap.MODEL_D_MAINTENANCE_GENERATION],
            arguments + ["--candidate-baseline", bootstrap.CURRENT_BASELINE],
            arguments + ["--protected-base", "latest"],
            arguments + ["--policy-source", "candidate"],
            arguments + ["--protected-universe", "candidate"],
        ):
            with self.subTest(arguments=bad):
                result = subprocess.run(
                    [os.sys.executable, "-I", "-S",
                     str(Path(bootstrap.__file__).resolve()), *bad],
                    capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
        for operation in ("", "model-d-orchestration-v1", "latest",
                          "MODEL_D_ORCHESTRATION_V1\nOTHER"):
            with self.subTest(operation=operation), self.assertRaises(
                    bootstrap.BootstrapError):
                self._validate(operation=operation)
        for generation in ("", "generation-1", "latest",
                           "MODEL_D_ORCHESTRATION_V1_GENERATION_1\nOTHER"):
            with self.subTest(generation=generation), self.assertRaises(
                    bootstrap.BootstrapError):
                self._validate(generation=generation)

    def test_record_parser_rejects_count_status_path_and_duplicates(self) -> None:
        valid = b"".join(
            b"M\0" + path.encode("utf-8") + b"\0"
            for path in bootstrap.MODEL_D_MAINTENANCE_PATHS
        )
        self.assertEqual(
            tuple(path for _status, path in bootstrap._model_d_records(valid)),
            bootstrap.MODEL_D_MAINTENANCE_PATHS,
        )
        paths = bootstrap.MODEL_D_MAINTENANCE_PATHS
        invalid = (
            b"",
            b"M\0" + paths[0].encode() + b"\0",
            valid + b"M\0foreign.py\0",
            valid.replace(b"M\0", b"A\0", 1),
            valid.replace(b"M\0", b"D\0", 1),
            valid.replace(b"M\0", b"R100\0", 1),
            valid.replace(b"M\0", b"C100\0", 1),
            valid.replace(paths[1].encode(), paths[0].encode()),
            valid.replace(paths[1].encode(), b"Protected_policy_bootstrap.py"),
            valid.replace(paths[1].encode(), b"dir\\protected_policy_bootstrap.py"),
            valid.replace(paths[1].encode(), b"../protected_policy_bootstrap.py"),
            valid.replace(paths[1].encode(), b"C:/protected_policy_bootstrap.py"),
            valid.replace(paths[1].encode(), paths[1].encode() + b"\nforeign"),
            valid[:-1],
        )
        for output in invalid:
            with self.subTest(output=output), self.assertRaises(
                    bootstrap.BootstrapError):
                bootstrap._model_d_records(output)

    def test_real_git_rejects_wrong_counts_foreign_and_deleted_paths(self) -> None:
        def foreign(root: Path) -> None:
            (root / "foreign.py").write_text("foreign\n", encoding="utf-8")
            git(root, "add", "foreign.py")

        def delete(root: Path) -> None:
            git(root, "rm", bootstrap.MODEL_D_MAINTENANCE_PATHS[0])

        def case_mutation(root: Path) -> None:
            git(root, "mv", "protected_policy_bootstrap.py",
                "Protected_policy_bootstrap.py")

        cases = (
            ("one", bootstrap.MODEL_D_MAINTENANCE_PATHS[:1], None),
            ("two", bootstrap.MODEL_D_MAINTENANCE_PATHS[:2], None),
            ("four", bootstrap.MODEL_D_MAINTENANCE_PATHS, foreign),
            ("delete", bootstrap.MODEL_D_MAINTENANCE_PATHS[1:], delete),
            ("case", bootstrap.MODEL_D_MAINTENANCE_PATHS[::2], case_mutation),
        )
        for name, paths, mutator in cases:
            candidate = self._candidate(name, paths, mutator)
            with self.subTest(name=name), self.assertRaises(bootstrap.BootstrapError):
                self._validate(candidate=candidate)

    def test_real_git_rejects_mode_symlink_and_gitlink(self) -> None:
        def mode(root: Path) -> None:
            git(root, "update-index", "--chmod=+x", "protected_policy_bootstrap.py")

        def symlink(root: Path) -> None:
            blob = git(root, "hash-object", "requirements-policy.lock")
            git(root, "update-index", "--cacheinfo",
                "120000," + blob + ",protected_policy_bootstrap.py")

        def gitlink(root: Path) -> None:
            git(root, "update-index", "--cacheinfo",
                "160000," + self.protected_sha + ",protected_policy_bootstrap.py")

        for name, mutator in (("mode", mode), ("symlink", symlink),
                              ("gitlink", gitlink)):
            candidate = self._candidate(
                name, bootstrap.MODEL_D_MAINTENANCE_PATHS, mutator)
            with self.subTest(name=name), self.assertRaises(bootstrap.BootstrapError):
                self._validate(candidate=candidate)

    def test_base_binding_expiry_remote_and_candidate_substitution(self) -> None:
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_model_d_maintenance(
                bootstrap.MODEL_D_MAINTENANCE_OPERATION,
                bootstrap.MODEL_D_MAINTENANCE_GENERATION,
                self.candidate, self.protected, self.candidate_sha,
                "97774bf4f5885a5900a1ccea98c98af12482f9e0",
            )
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/other.git")
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate()
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")

        git(self.protected, "checkout", "-b", "consume-operation")
        git(self.protected, "fetch", str(self.candidate), self.candidate_sha)
        git(self.protected, "merge", "--no-ff", "FETCH_HEAD",
            "-m", "Consume Model D operation")
        consumed_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", consumed_sha)
        replay = self._candidate("replay", bootstrap.MODEL_D_MAINTENANCE_PATHS)
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate(candidate=replay, protected=self.protected)

    def test_generation_survives_sequential_test_only_maintenance(self) -> None:
        for index in range(2):
            path = self.protected / "test_verify_security_workflows.py"
            path.write_bytes(path.read_bytes() + f"\n# maintenance-{index}\n".encode())
            git(self.protected, "add", "test_verify_security_workflows.py")
            git(self.protected, "commit", "-m", f"Protected test maintenance {index}")
            self.protected_sha = git(self.protected, "rev-parse", "HEAD")
            git(self.protected, "update-ref", "refs/remotes/origin/main",
                self.protected_sha)
            candidate = self._candidate(
                f"after-maintenance-{index}", bootstrap.MODEL_D_MAINTENANCE_PATHS)
            self._validate(candidate=candidate)

    def test_generation_survives_unrelated_ancestry_movement(self) -> None:
        path = self.protected / "README.md"
        path.write_bytes(path.read_bytes() + b"\n")
        git(self.protected, "add", "README.md")
        git(self.protected, "commit", "-m", "Unrelated governed maintenance")
        self.protected_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main",
            self.protected_sha)
        candidate = self._candidate(
            "after-unrelated-maintenance", bootstrap.MODEL_D_MAINTENANCE_PATHS)
        self._validate(candidate=candidate)

    def test_protected_generation_mutations_fail_closed(self) -> None:
        mutations = (
            ("workflow-generation", ".github/workflows/security-workflows-policy.yml",
             b"MODEL_D_ORCHESTRATION_V1_GENERATION_1",
             b"MODEL_D_ORCHESTRATION_V1_GENERATION_2"),
            ("bootstrap-generation", "protected_policy_bootstrap.py",
             b'MODEL_D_MAINTENANCE_GENERATION = "MODEL_D_ORCHESTRATION_V1_GENERATION_1"',
             b'MODEL_D_MAINTENANCE_GENERATION = "MODEL_D_ORCHESTRATION_V1_GENERATION_2"'),
            ("bootstrap-state", "protected_policy_bootstrap.py",
             b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:ACTIVE',
             b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED'),
        )
        for name, relative, old, new in mutations:
            root = self.base / f"protected-{name}"
            subprocess.run(
                ["git", "clone", "--no-hardlinks", "--no-checkout",
                 str(self.protected), str(root)],
                check=True, capture_output=True, text=True)
            git(root, "config", "user.name", "Model D Admission Test")
            git(root, "config", "user.email", "model-d@example.invalid")
            git(root, "config", "core.autocrlf", "false")
            git(root, "checkout", "-B", "main", self.protected_sha)
            git(root, "remote", "set-url", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")
            path = root / relative
            data = path.read_bytes()
            self.assertEqual(data.count(old), 1)
            path.write_bytes(data.replace(old, new))
            git(root, "add", relative)
            git(root, "commit", "-m", name)
            changed_sha = git(root, "rev-parse", "HEAD")
            git(root, "update-ref", "refs/remotes/origin/main", changed_sha)
            with self.subTest(name=name), self.assertRaises(bootstrap.BootstrapError):
                bootstrap.validate_model_d_maintenance(
                    bootstrap.MODEL_D_MAINTENANCE_OPERATION,
                    bootstrap.MODEL_D_MAINTENANCE_GENERATION,
                    self.candidate, root, self.candidate_sha, changed_sha)

    def test_candidate_cannot_substitute_or_extend_generation(self) -> None:
        cases = (
            ("candidate-generation", ".github/workflows/security-workflows-policy.yml",
             b"MODEL_D_ORCHESTRATION_V1_GENERATION_1",
             b"MODEL_D_ORCHESTRATION_V1_GENERATION_2"),
            ("candidate-active", "protected_policy_bootstrap.py",
             b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED',
             b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:ACTIVE'),
            ("candidate-missing", "protected_policy_bootstrap.py",
             b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED', b""),
            ("candidate-malformed", "protected_policy_bootstrap.py",
             b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED',
             b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:LATEST'),
        )
        for name, relative, old, new in cases:
            candidate = self._candidate(name, bootstrap.MODEL_D_MAINTENANCE_PATHS)
            path = candidate / relative
            data = path.read_bytes()
            self.assertEqual(data.count(old), 1)
            path.write_bytes(data.replace(old, new))
            git(candidate, "add", relative)
            git(candidate, "commit", "--amend", "--no-edit")
            with self.subTest(name=name), self.assertRaises(bootstrap.BootstrapError):
                self._validate(candidate=candidate)

    def test_full_lifecycle_consumption_and_replay_remain_expired(self) -> None:
        self._validate()
        git(self.protected, "checkout", "-b", "comprehensive-model-d")
        git(self.protected, "fetch", str(self.candidate), self.candidate_sha)
        git(self.protected, "merge", "--no-ff", "FETCH_HEAD",
            "-m", "Consume comprehensive Model D generation")
        consumed_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", consumed_sha)
        replay = self._candidate("immediate-replay", bootstrap.MODEL_D_MAINTENANCE_PATHS)
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate(candidate=replay, protected=self.protected)
        path = self.protected / "test_verify_security_workflows.py"
        path.write_bytes(path.read_bytes() + b"\n# post-consumption-maintenance\n")
        git(self.protected, "add", "test_verify_security_workflows.py")
        git(self.protected, "commit", "-m", "Post-consumption test maintenance")
        later_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", later_sha)
        replay = self._candidate("later-replay", bootstrap.MODEL_D_MAINTENANCE_PATHS)
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate(candidate=replay, protected=self.protected)
        bootstrap_path = self.protected / "protected_policy_bootstrap.py"
        data = bootstrap_path.read_bytes()
        consumed = b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED'
        active = b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:ACTIVE'
        self.assertEqual(data.count(consumed), 1)
        bootstrap_path.write_bytes(data.replace(consumed, active))
        git(self.protected, "add", "protected_policy_bootstrap.py")
        git(self.protected, "commit", "-m", "Attempt generation rollback")
        rollback_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", rollback_sha)
        replay = self._candidate("rollback-replay", bootstrap.MODEL_D_MAINTENANCE_PATHS)
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate(candidate=replay, protected=self.protected)

    def test_protected_history_completeness_fails_closed(self) -> None:
        bootstrap._require_model_d_history(self.protected, self.protected_sha)

        shallow = self.base / "protected-shallow"
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", "main",
             self.protected.as_uri(), str(shallow)],
            check=True, capture_output=True, text=True)
        git(shallow, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")
        shallow_sha = git(shallow, "rev-parse", "HEAD")
        git(shallow, "update-ref", "refs/remotes/origin/main", shallow_sha)
        self.assertEqual(git(shallow, "rev-parse", "--is-shallow-repository"), "true")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._require_model_d_history(shallow, shallow_sha)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_model_d_maintenance(
                bootstrap.MODEL_D_MAINTENANCE_OPERATION,
                bootstrap.MODEL_D_MAINTENANCE_GENERATION,
                self.candidate, shallow, self.candidate_sha, shallow_sha)

        unrelated = self.base / "protected-unrelated"
        unrelated.mkdir()
        git(unrelated, "init", "-b", "main")
        git(unrelated, "config", "user.name", "Model D Admission Test")
        git(unrelated, "config", "user.email", "model-d@example.invalid")
        (unrelated / "unrelated.txt").write_text("unrelated\n", encoding="utf-8")
        git(unrelated, "add", ".")
        git(unrelated, "commit", "-m", "unrelated history")
        git(unrelated, "fetch", str(self.protected),
            bootstrap.MODEL_D_MAINTENANCE_HISTORY_ANCHOR)
        unrelated_sha = git(unrelated, "rev-parse", "HEAD")
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._require_model_d_history(unrelated, unrelated_sha)

        original = bootstrap._git_bytes
        def fail_git(root: Path, *arguments: str) -> bytes:
            if arguments and arguments[0] == "cat-file":
                raise bootstrap.BootstrapError("simulated unavailable history object")
            return original(root, *arguments)
        with mock.patch.object(bootstrap, "_git_bytes", side_effect=fail_git):
            with self.assertRaises(bootstrap.BootstrapError):
                bootstrap._require_model_d_history(
                    self.protected, self.protected_sha)

    def test_candidate_history_cannot_replace_protected_history(self) -> None:
        bootstrap._require_model_d_history(self.protected, self.protected_sha)
        shallow_candidate = self.base / "candidate-shallow-history"
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", "main",
             self.protected.as_uri(), str(shallow_candidate)],
            check=True, capture_output=True, text=True)
        self.assertEqual(
            git(shallow_candidate, "rev-parse", "--is-shallow-repository"), "true")
        bootstrap._require_model_d_history(self.protected, self.protected_sha)

    def test_protected_history_reads_cannot_lazy_fetch(self) -> None:
        with mock.patch.object(
                bootstrap.subprocess, "run",
                wraps=bootstrap.subprocess.run) as run:
            bootstrap._require_model_d_history(
                self.protected, self.protected_sha)
        self.assertEqual(run.call_count, 3)
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["GIT_NO_LAZY_FETCH"], "1")

    def test_generation_specific_consumption_is_isolated(self) -> None:
        self.assertFalse(bootstrap._model_d_generation_was_consumed(
            self.protected, self.protected_sha,
            "MODEL_D_ORCHESTRATION_V1_GENERATION_2"))
        git(self.protected, "checkout", "-b", "consume-g1-for-isolation")
        git(self.protected, "fetch", str(self.candidate), self.candidate_sha)
        git(self.protected, "merge", "--no-ff", "FETCH_HEAD",
            "-m", "Consume generation one")
        consumed_sha = git(self.protected, "rev-parse", "HEAD")
        self.assertTrue(bootstrap._model_d_generation_was_consumed(
            self.protected, consumed_sha,
            "MODEL_D_ORCHESTRATION_V1_GENERATION_1"))
        self.assertFalse(bootstrap._model_d_generation_was_consumed(
            self.protected, consumed_sha,
            "MODEL_D_ORCHESTRATION_V1_GENERATION_2"))
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._model_d_generation_was_consumed(
                self.protected, consumed_sha, "foreign-generation")

    def test_lifecycle_record_rejects_duplicate_conflict_and_malformed(self) -> None:
        cases = (
            ("duplicate", b'\nMODEL_D_MAINTENANCE_LIFECYCLE = '
             b'"MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED"\n'),
            ("conflict", b'\nMODEL_D_MAINTENANCE_LIFECYCLE = '
             b'"MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE"\n'),
            ("malformed", b'\nMODEL_D_MAINTENANCE_LIFECYCLE="latest"\n'),
        )
        for name, addition in cases:
            candidate = self._candidate(name, bootstrap.MODEL_D_MAINTENANCE_PATHS)
            path = candidate / "protected_policy_bootstrap.py"
            path.write_bytes(path.read_bytes() + addition)
            git(candidate, "add", "protected_policy_bootstrap.py")
            git(candidate, "commit", "--amend", "--no-edit")
            with self.subTest(name=name), self.assertRaises(bootstrap.BootstrapError):
                self._validate(candidate=candidate)

    def test_accumulated_d1_d4_path_reaches_one_d5_consumption(self) -> None:
        """Admit the exact accumulated worktree, then prove its protected route."""
        root = self.base / "accumulated-model-d"
        subprocess.run(
            ["git", "clone", "--no-hardlinks", "--no-checkout",
             str(self.protected), str(root)],
            check=True, capture_output=True, text=True)
        self._configure(root)
        git(root, "checkout", "-b", "accumulated-model-d")
        source = Path(__file__).parent.resolve()
        for name in bootstrap.MODEL_D_MAINTENANCE_PATHS:
            (root / name).write_bytes((source / name).read_bytes())
        git(root, "add", *bootstrap.MODEL_D_MAINTENANCE_PATHS)
        git(root, "commit", "-m", "Comprehensive D1-D4 Model D candidate")
        for name in bootstrap.MODEL_D_MAINTENANCE_PATHS:
            self.assertEqual(git(root, "rev-parse", f"HEAD:{name}"),
                             git(source, "hash-object", "--no-filters", name))
        self.assertEqual(bootstrap._model_d_generation_state(
            self.protected, self.protected_sha), "ACTIVE")
        self.assertEqual(bootstrap._model_d_generation_state(
            root, git(root, "rev-parse", "HEAD")), "CONSUMED")
        self._validate(candidate=root)

        # The old protected CLI cannot run the new candidate-only operation.
        old_bootstrap = self.base / "protected-base-bootstrap.py"
        old_bootstrap.write_bytes(subprocess.run(
            ["git", "-C", str(self.protected), "show",
             f"{self.protected_sha}:protected_policy_bootstrap.py"],
            check=True, capture_output=True).stdout)
        candidate_sha = git(root, "rev-parse", "HEAD")
        old_output = self.base / "protected-base-output"
        old_output.write_bytes(b"")
        old_evaluate = subprocess.run([
            os.sys.executable, "-I", "-S", str(old_bootstrap), "evaluate",
            "--event-name", "pull_request",
            "--repository", bootstrap.REPOSITORY,
            "--base-repository", bootstrap.REPOSITORY,
            "--base-branch", "main",
            "--candidate-sha", candidate_sha,
            "--protected-sha", self.protected_sha,
            "--candidate-root", str(root),
            "--protected-root", str(self.protected),
            "--event-ref", "refs/pull/1/merge",
            "--default-branch", "main",
            "--workflow-ref", (bootstrap.REPOSITORY +
                               "/.github/workflows/security-workflows-policy.yml@refs/pull/1/merge"),
        ], env={**os.environ, "GITHUB_OUTPUT": str(old_output)},
           capture_output=True, text=True)
        self.assertEqual(old_evaluate.returncode, 0, old_evaluate.stderr)
        self.assertEqual(len(old_output.read_text(encoding="utf-8").splitlines()), 5)
        old_admission = subprocess.run([
            os.sys.executable, "-I", "-S", str(old_bootstrap), "admit-maintenance",
            "--maintenance-operation", bootstrap.MODEL_D_MAINTENANCE_OPERATION,
            "--maintenance-generation", bootstrap.MODEL_D_MAINTENANCE_GENERATION,
            "--candidate-sha", candidate_sha,
            "--protected-sha", self.protected_sha,
            "--candidate-root", str(root),
            "--protected-root", str(self.protected),
        ], capture_output=True, text=True)
        self.assertEqual(old_admission.returncode, 0, old_admission.stderr)
        first_landing = subprocess.run(
            [os.sys.executable, "-I", "-S", str(old_bootstrap), "run-model-d"],
            capture_output=True, text=True)
        self.assertNotEqual(first_landing.returncode, 0)
        self.assertIn("invalid choice: 'run-model-d'", first_landing.stderr)

        git(self.protected, "checkout", "-b", "comprehensive-model-d")
        git(self.protected, "fetch", str(root), git(root, "rev-parse", "HEAD"))
        git(self.protected, "merge", "--no-ff", "FETCH_HEAD",
            "-m", "Consume exact comprehensive Model D candidate")
        consumed_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", consumed_sha)
        self.assertEqual(bootstrap._model_d_generation_state(
            self.protected, consumed_sha), "CONSUMED")
        self.assertTrue(bootstrap._model_d_generation_was_consumed(
            self.protected, consumed_sha))
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate(candidate=root, protected=self.protected)

        proof_candidate = self.base / "protected-proof-candidate"
        subprocess.run(["git", "clone", "--no-hardlinks", "--no-checkout",
                        str(self.protected), str(proof_candidate)],
                       check=True, capture_output=True, text=True)
        git(proof_candidate, "checkout", "-B", "main", consumed_sha)
        self._configure(proof_candidate)
        output = self.base / "protected-proof-output"
        output.write_bytes(b"")
        proof = subprocess.run([
            os.sys.executable, "-I", "-S",
            str(self.protected / "protected_policy_bootstrap.py"), "run-model-d",
            "--event-name", "workflow_dispatch",
            "--repository", bootstrap.REPOSITORY,
            "--base-repository", bootstrap.REPOSITORY,
            "--base-branch", "main",
            "--candidate-sha", consumed_sha,
            "--protected-sha", consumed_sha,
            "--candidate-root", str(proof_candidate),
            "--protected-root", str(self.protected),
            "--event-ref", "refs/heads/main",
            "--default-branch", "main",
            "--workflow-ref", (bootstrap.REPOSITORY +
                               "/.github/workflows/security-workflows-policy.yml@refs/heads/main"),
        ], env={**os.environ, "GITHUB_OUTPUT": str(output)},
           capture_output=True, text=True)
        self.assertEqual(proof.returncode, 0, proof.stderr)
        self.assertEqual(len(output.read_text(encoding="utf-8").splitlines()), 11)

    def test_workflow_uses_only_protected_bridge_and_preserves_outputs(self) -> None:
        workflow = yaml.load(
            (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text(
                encoding="utf-8"), Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        admission = next(
            step for step in steps
            if step["name"] == "Enforce exact Model D maintenance admission")
        run = admission["run"]
        self.assertEqual(run.count("admit-maintenance"), 1)
        self.assertIn(
            '--maintenance-generation "${{ env.MODEL_D_MAINTENANCE_GENERATION }}"', run)
        self.assertIn("policy/protected_policy_bootstrap.py", run)
        self.assertNotIn("candidate/protected_policy_bootstrap.py", run)
        self.assertNotIn("1211595f9b0b5d1e76dd892bb210fece54f24b53", run)
        self.assertEqual(bootstrap._OUTPUT_KEYS, (
            "evaluation-context", "policy-source", "version-disposition",
            "owner-authorization", "post-merge-proof",
        ))


if __name__ == "__main__":
    unittest.main()
