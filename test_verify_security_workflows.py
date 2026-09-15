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
        assert isinstance(syntax, yaml.MappingNode)
        env_nodes = [value for key, value in syntax.value
                     if isinstance(key, yaml.ScalarNode) and key.value == "env"]
        self.assertEqual(len(env_nodes), 1)
        self.assertIsInstance(env_nodes[0], yaml.MappingNode)
        versions = [value for key, value in env_nodes[0].value
                    if isinstance(key, yaml.ScalarNode)
                    and key.value == "POLICY_BASELINE_VERSION"]
        self.assertEqual(len(versions), 1)
        self.assertIsInstance(versions[0], yaml.ScalarNode)
        self.assertEqual(versions[0].value, self.BASELINE_VERSION)

        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow["on"]), {"pull_request", "merge_group", "workflow_dispatch"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertNotIn("continue-on-error", text)
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]

        def role(label: str, token: str) -> tuple[int, dict[str, object]]:
            found = [(index, step) for index, step in enumerate(steps)
                     if token in str(step.get("run", step.get("uses", "")))]
            self.assertEqual(len(found), 1, label)
            return found[0]

        candidate_checkout = [(i, s) for i, s in enumerate(steps)
                              if s.get("with", {}).get("path") == "candidate"]
        protected_checkout = [(i, s) for i, s in enumerate(steps)
                              if s.get("with", {}).get("path") == "policy"]
        self.assertEqual(len(candidate_checkout), 1)
        self.assertEqual(len(protected_checkout), 1)
        context = role("context", "Unsupported or ambiguous policy evaluation context")
        normalization = role("normalization", "Policy lock bytes differ from committed Git bytes")
        setup = role("Python setup", "actions/setup-python@")
        python_gate = role("Python gate", "platform.python_version()")
        policy_install = role("policy install", "-m pip install --require-hashes --only-binary=:all: -r \"$env:POLICY_SOURCE/requirements-policy.lock\"")
        candidate_tests = role("candidate evidence", "-m unittest discover -s candidate")
        protected_tests = role("protected Stage A baseline", "test_protected_source_and_candidate_target_contract")
        policy_discovery = [(index, step) for index, step in enumerate(steps)
                            if "-m unittest discover -s policy" in step.get("run", "")]
        self.assertEqual(len(policy_discovery), 2)
        legacy_matches = [item for item in policy_discovery
                          if item[1].get("if") == "env.EVALUATION_CONTEXT == 'SELF_PR_BOOTSTRAP'"]
        downstream_matches = [item for item in policy_discovery
                              if item[1].get("if") == "env.EVALUATION_CONTEXT == 'DOWNSTREAM_SECURITY_WORKFLOWS'"]
        self.assertEqual(len(legacy_matches), 1)
        self.assertEqual(len(downstream_matches), 1)
        legacy_tests = legacy_matches[0]
        downstream_tests = downstream_matches[0]
        audit_install_matches = [(index, step) for index, step in enumerate(steps)
                                 if "requirements-audit.lock" in step.get("run", "")
                                 and "-m pip install" in step.get("run", "")]
        self.assertEqual(len(audit_install_matches), 1, "audit install")
        audit_install = audit_install_matches[0]
        audit = role("dependency audit", "-m pip_audit --no-deps")
        validator = role("protected validator", "policy/verify_security_workflows.py --candidate candidate")

        candidate_with = candidate_checkout[0][1]["with"]
        self.assertEqual(candidate_with["repository"], "${{ github.repository }}")
        self.assertEqual(candidate_with["ref"], "${{ github.sha }}")
        self.assertEqual(candidate_with["fetch-depth"], "0")
        protected_with = protected_checkout[0][1]["with"]
        self.assertEqual(protected_with["repository"], self.POLICY_REPOSITORY)
        self.assertEqual(protected_with["ref"], "main")
        self.assertEqual(protected_with["fetch-depth"], "0")

        dispatch = context[1]["run"]
        for fragment in (
            "$env:EVENT_NAME -eq 'workflow_dispatch'", "$env:EVENT_REF -eq 'refs/heads/main'",
            "$env:WORKFLOW_REF -eq $protectedWorkflowRef", "$evaluationContext = 'STAGE_A_PROTECTED_PROOF'",
            "$env:EVENT_NAME -eq 'pull_request'", "$env:EVENT_REPOSITORY -eq $selfRepository",
            "$env:BASE_REPOSITORY -eq $selfRepository", "$env:BASE_BRANCH -eq 'main'",
            "$evaluationContext = 'SELF_PR_BOOTSTRAP'", "$policySource = 'candidate'",
            "$env:EVENT_NAME -in @('pull_request', 'merge_group')",
            "$env:EVENT_REPOSITORY -eq $downstreamRepository",
            "$evaluationContext = 'DOWNSTREAM_SECURITY_WORKFLOWS'", "$policySource = 'policy'",
            "throw 'Unsupported or ambiguous policy evaluation context'", "^[0-9a-f]{40}$",
            "Candidate and protected-policy roots must be separate",
            "Candidate checkout repository mismatch", "Protected-policy checkout repository mismatch",
            "Candidate checkout does not match event SHA", "Protected-policy checkout is not protected main",
            "git -C candidate diff --name-only $policyHead $candidateHead",
            "$stageABase = '5adc147258fb7e8aa709d030221c4eec97b75641'",
            "$stageAVersion = 'SECURITY-POLICY-BASELINE-1'", "$stageAAllowed = @(",
            "$stageAStatusesExact", "$policyHead -eq $stageABase", "$baselineExact",
            "$stageATransition = $policyHead -eq $stageABase -and $baselineExact -and $stageAExact -and $stageAStatusesExact",
            "Protected proof roots must use the same protected-main SHA",
            "Security-policy self-PR exceeds the bounded five-file scope",
        ):
            self.assertIn(fragment, dispatch)
        self.assertNotIn("HashSet", dispatch)
        self.assertNotIn("Policy lock changes require protected contract tests", dispatch)

        for fragment in ("foreach ($root in @('candidate', 'policy'))",
                         "config core.autocrlf false", "reset --hard HEAD",
                         "hash-object --no-filters", "Policy lock bytes differ"):
            self.assertIn(fragment, normalization[1]["run"])
        self.assertEqual(setup[1]["with"]["python-version"], "3.12.10")
        self.assertIn("$pythonVersion -ne '3.12.10'", python_gate[1]["run"])
        self.assertIn("throw 'Unexpected CPython version'", python_gate[1]["run"])
        for run, expected in ((policy_install[1]["run"], "6.0.3"),
                              (audit_install[1]["run"], "pip-audit 2.10.1")):
            self.assertIn("--require-hashes", run)
            self.assertIn("--only-binary=:all:", run)
            self.assertIn("-m pip check", run)
            self.assertIn(expected, run)
        proof_condition = "env.EVALUATION_CONTEXT == 'SELF_PR_BOOTSTRAP' || env.EVALUATION_CONTEXT == 'STAGE_A_PROTECTED_PROOF'"
        self.assertEqual(candidate_tests[1]["name"], "Run candidate Stage A evidence")
        self.assertEqual(candidate_tests[1]["if"], proof_condition)
        self.assertEqual(legacy_tests[1]["name"], "Run legacy protected health")
        self.assertEqual(legacy_tests[1]["if"], "env.EVALUATION_CONTEXT == 'SELF_PR_BOOTSTRAP'")
        self.assertEqual(protected_tests[1]["name"], "Apply protected Stage A baseline to candidate target")
        self.assertEqual(protected_tests[1]["if"], "env.EVALUATION_CONTEXT == 'STAGE_A_PROTECTED_PROOF'")
        self.assertEqual(protected_tests[1]["env"], {
            "POLICY_CANDIDATE_ROOT": "${{ github.workspace }}/candidate",
            "POLICY_PROTECTED_ROOT": "${{ github.workspace }}/policy",
            "POLICY_EXPECTED_REPOSITORY": "${{ github.repository }}",
            "POLICY_EXPECTED_CANDIDATE_SHA": "${{ github.sha }}",
            "POLICY_EXPECTED_BASE_REPOSITORY": "${{ github.event.pull_request.base.repo.full_name || github.repository }}",
            "POLICY_EXPECTED_BASE_BRANCH": "${{ github.event.pull_request.base.ref || 'main' }}",
            "POLICY_EXPECTED_EVENT": "${{ github.event_name }}",
        })
        self.assertEqual(downstream_tests[1]["if"], "env.EVALUATION_CONTEXT == 'DOWNSTREAM_SECURITY_WORKFLOWS'")
        self.assertEqual(validator[1]["if"], "env.EVALUATION_CONTEXT == 'DOWNSTREAM_SECURITY_WORKFLOWS'")
        for method in (
            "test_protected_source_and_candidate_target_contract",
            "test_stage_a_candidate_invariants",
            "test_stage_a_target_binding_executes_in_isolated_git_roots",
        ):
            self.assertNotIn(method, legacy_tests[1]["run"])
            self.assertIn(method, protected_tests[1]["run"])
        self.assertNotIn("candidate/test_verify_security_workflows.py", legacy_tests[1]["run"])
        self.assertNotIn("candidate/test_verify_security_workflows.py", protected_tests[1]["run"])
        self.assertNotIn("candidate/verify_security_workflows.py", validator[1]["run"])
        order = [candidate_checkout[0][0], protected_checkout[0][0], context[0], normalization[0],
                 setup[0], python_gate[0], policy_install[0], candidate_tests[0], legacy_tests[0], protected_tests[0],
                 downstream_tests[0], audit_install[0], audit[0], validator[0]]
        self.assertEqual(order, sorted(order))
        for _, step in (context, normalization, python_gate, policy_install, candidate_tests,
                        legacy_tests, protected_tests, downstream_tests, audit_install, audit, validator):
            self.assertIn("$ErrorActionPreference = 'Stop'", step["run"])
            self.assertIn("$LASTEXITCODE -ne 0", step["run"])

    def test_policy_dependency_workflow_contract(self) -> None:
        root = Path(os.environ.get("POLICY_CONTRACT_TARGET", Path(__file__).parent))
        self._stage_a_contract(root)
        original = (root / ".github/workflows/security-workflows-policy.yml").read_text(encoding="utf-8")
        mutations = (
            ("  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\n", ""),
            ("SECURITY-POLICY-BASELINE-1", "SECURITY-POLICY-BASELINE-2"),
            ("SECURITY-POLICY-BASELINE-1", "security-policy-baseline-1"),
            ("  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1",
             "  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\n  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1"),
            ("throw 'Unsupported or ambiguous policy evaluation context'", "$evaluationContext = 'SELF_PR_BOOTSTRAP'"),
            ("$stageABase = '5adc147258fb7e8aa709d030221c4eec97b75641'", "$stageABase = '0'"),
            ("$policyHead -eq $stageABase", "$true"),
            ("-and $stageAStatusesExact", "-and $true"),
            ("$env:WORKFLOW_REF -eq $protectedWorkflowRef", "$true"),
            ("Protected proof roots must use the same protected-main SHA", "proof mismatch ignored"),
            ("^[0-9a-f]{40}$", ".*"),
            ("throw 'Candidate and protected-policy roots must be separate'", "Write-Output ignored"),
            ("throw 'Security-policy self-PR exceeds the bounded five-file scope'", "Write-Output ignored"),
            (" --require-hashes", ""), (" --only-binary=:all:", ""),
            ("-m unittest discover -s candidate", "-m unittest discover -s policy"),
            ("Run legacy protected health", "Run candidate Stage A evidence"),
            ("env.EVALUATION_CONTEXT == 'SELF_PR_BOOTSTRAP'\n        shell: pwsh\n        run: |\n          $ErrorActionPreference = 'Stop'\n          .\\policy-env\\Scripts\\python.exe -m unittest discover -s policy",
             "env.EVALUATION_CONTEXT == 'STAGE_A_PROTECTED_PROOF'\n        shell: pwsh\n        run: |\n          $ErrorActionPreference = 'Stop'\n          .\\policy-env\\Scripts\\python.exe -m unittest discover -s policy"),
            ("if: env.EVALUATION_CONTEXT == 'STAGE_A_PROTECTED_PROOF'\n        shell: pwsh\n        env:\n          POLICY_CANDIDATE_ROOT",
             "if: env.EVALUATION_CONTEXT == 'SELF_PR_BOOTSTRAP'\n        shell: pwsh\n        env:\n          POLICY_CANDIDATE_ROOT"),
            ("test_protected_source_and_candidate_target_contract", "test_policy_dependency_workflow_contract"),
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
        source_root = Path(__file__).parent
        workflow = yaml.load(
            (source_root / ".github/workflows/security-workflows-policy.yml").read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        context_steps = [step for step in workflow["jobs"]["security-workflows-policy"]["steps"]
                         if "Unsupported or ambiguous policy evaluation context" in step.get("run", "")]
        self.assertEqual(len(context_steps), 1)
        original_script = context_steps[0]["run"]

        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory)
            policy = runner / "policy"
            candidate = runner / "candidate"
            ignored = shutil.ignore_patterns(".git", "__pycache__", "*.pyc")
            shutil.copytree(source_root, policy, ignore=ignored)
            git(policy, "init", "-b", "main")
            git(policy, "config", "core.autocrlf", "false")
            git(policy, "config", "user.name", "Stage A Test")
            git(policy, "config", "user.email", "stage-a@example.invalid")
            git(policy, "remote", "add", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")
            git(policy, "add", ".")
            git(policy, "commit", "-m", "protected fixture")
            protected_sha = git(policy, "rev-parse", "HEAD")
            git(policy, "update-ref", "refs/remotes/origin/main", protected_sha)
            shutil.copytree(policy, candidate)

            def reset_candidate() -> None:
                git(candidate, "reset", "--hard", protected_sha)
                git(candidate, "clean", "-fd")

            def commit_paths(paths: tuple[str, ...]) -> str:
                reset_candidate()
                for name in paths:
                    target = candidate / name
                    target.write_text(target.read_text(encoding="utf-8") + "\n# stage-a-admission-fixture\n",
                                      encoding="utf-8", newline="\n")
                git(candidate, "add", ".")
                git(candidate, "commit", "-m", "candidate fixture")
                return git(candidate, "rev-parse", "HEAD")

            script = original_script.replace(
                "5adc147258fb7e8aa709d030221c4eec97b75641", protected_sha
            )

            def execute(event: str, candidate_sha: str, **overrides: str) -> subprocess.CompletedProcess[str]:
                output = runner / "github-env.txt"
                output.write_text("", encoding="utf-8")
                environment = os.environ.copy()
                environment.update({
                    "EVENT_REPOSITORY": self.POLICY_REPOSITORY,
                    "CANDIDATE_SHA": candidate_sha,
                    "BASE_REPOSITORY": self.POLICY_REPOSITORY,
                    "BASE_BRANCH": "main",
                    "EVENT_NAME": event,
                    "EVENT_REF": "refs/heads/main" if event == "workflow_dispatch" else "refs/pull/1/merge",
                    "DEFAULT_BRANCH": "main",
                    "WORKFLOW_REF": "KiloAlpha021/security-policy/.github/workflows/security-workflows-policy.yml@refs/heads/main",
                    "POLICY_BASELINE_VERSION": self.BASELINE_VERSION,
                    "GITHUB_ENV": str(output),
                })
                environment.update(overrides)
                return subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
                    cwd=runner, env=environment, capture_output=True, text=True,
                )

            transition_sha = commit_paths((
                ".github/workflows/security-workflows-policy.yml",
                "test_verify_security_workflows.py",
            ))
            positive = execute("pull_request", transition_sha)
            self.assertEqual(positive.returncode, 0, positive.stderr or positive.stdout)
            self.assertIn("EVALUATION_CONTEXT=SELF_PR_BOOTSTRAP",
                          (runner / "github-env.txt").read_text(encoding="utf-8"))

            for label, paths in (
                ("one_file", ("test_verify_security_workflows.py",)),
                ("third_file", (".github/workflows/security-workflows-policy.yml",
                                "test_verify_security_workflows.py", "README.md")),
                ("policy_lock", (".github/workflows/security-workflows-policy.yml",
                                 "test_verify_security_workflows.py", "requirements-policy.lock")),
                ("validator", (".github/workflows/security-workflows-policy.yml",
                               "test_verify_security_workflows.py", "verify_security_workflows.py")),
                ("manifest", (".github/workflows/security-workflows-policy.yml",
                              "test_verify_security_workflows.py", "policy-manifest.json")),
            ):
                with self.subTest(label=label):
                    sha = commit_paths(paths)
                    self.assertNotEqual(execute("pull_request", sha).returncode, 0)

            reset_candidate()
            proof = execute("workflow_dispatch", protected_sha)
            self.assertEqual(proof.returncode, 0, proof.stderr or proof.stdout)
            proof_env = (runner / "github-env.txt").read_text(encoding="utf-8")
            self.assertIn("EVALUATION_CONTEXT=STAGE_A_PROTECTED_PROOF", proof_env)
            self.assertIn("POLICY_SOURCE=policy", proof_env)

            negative_contexts = (
                {"EVENT_REPOSITORY": "KiloAlpha021/other"},
                {"EVENT_REF": "refs/heads/other"},
                {"DEFAULT_BRANCH": "other"},
                {"WORKFLOW_REF": "KiloAlpha021/security-policy/.github/workflows/security-workflows-policy.yml@refs/heads/other"},
                {"CANDIDATE_SHA": "0" * 40},
            )
            for override in negative_contexts:
                with self.subTest(proof_override=override):
                    self.assertNotEqual(execute("workflow_dispatch", protected_sha, **override).returncode, 0)

            moved_script = script.replace(f"$stageABase = '{protected_sha}'", "$stageABase = '0'", 1)
            output = runner / "github-env.txt"
            env = os.environ.copy()
            env.update({
                "EVENT_REPOSITORY": self.POLICY_REPOSITORY,
                "CANDIDATE_SHA": transition_sha,
                "BASE_REPOSITORY": self.POLICY_REPOSITORY,
                "BASE_BRANCH": "main", "EVENT_NAME": "pull_request",
                "EVENT_REF": "refs/pull/1/merge", "DEFAULT_BRANCH": "main",
                "WORKFLOW_REF": "KiloAlpha021/security-policy/.github/workflows/security-workflows-policy.yml@refs/heads/main",
                "POLICY_BASELINE_VERSION": self.BASELINE_VERSION, "GITHUB_ENV": str(output),
            })
            self.assertNotEqual(subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-Command", moved_script],
                cwd=runner, env=env, capture_output=True, text=True,
            ).returncode, 0)

    def test_stage_a_transition_removal_is_required_after_bootstrap(self) -> None:
        text = (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("$stageABase = '5adc147258fb7e8aa709d030221c4eec97b75641'", text)
        self.assertIn("$policyHead -eq $stageABase", text)
        self.assertNotIn("$policyHead -ne $stageABase", text)
        self.assertIn("historical bootstrap", text.lower())

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
                result = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
                     "[void][scriptblock]::Create([Console]::In.ReadToEnd())"],
                    input=block, capture_output=True, text=True,
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
            "__future__", "argparse", "os", "re", "stat", "subprocess", "sys",
            "tempfile", "dataclasses", "enum", "pathlib"
        })
        self.assertNotIn("yaml", path.read_text(encoding="utf-8").lower())
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
            eligible = bootstrap.evaluate(self.inputs(
                protected_sha=bootstrap.TRANSITION_PROTECTED_BASE,
                candidate_baseline=bootstrap.IMMEDIATE_SUCCESSOR,
            ))
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
            b"  POLICY_BASELINE_VERSION: SECURITY-POLICY-BASELINE-1\x00\n",
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


if __name__ == "__main__":
    unittest.main()
