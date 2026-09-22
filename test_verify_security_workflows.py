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

from verify_security_workflows import (action_references, validate_tests,
                                       validate_verifier, validate_workflow, verify)
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
          repository: KiloAlpha021/automated-trading-bot
          ref: ${{ github.sha }}
          path: candidate
          fetch-depth: 0
      - uses: actions/checkout@1111111111111111111111111111111111111111
        with:
          repository: KiloAlpha021/security-workflows
          ref: main
          path: trusted
      - uses: actions/setup-python@1111111111111111111111111111111111111111
      - name: Enforce separate candidate and trusted identities
        env:
          EVENT_REPOSITORY: ${{ github.repository }}
          CANDIDATE_SHA: ${{ github.sha }}
          EVENT_NAME: ${{ github.event_name }}
        run: |
          $ErrorActionPreference = 'Stop'
          python trusted/verify_candidate.py --candidate candidate --trusted trusted --event-repository $env:EVENT_REPOSITORY --candidate-sha $env:CANDIDATE_SHA --event-name $env:EVENT_NAME
          if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
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
TRUSTED_REF = "refs/remotes/origin/main"
def verify(candidate, trusted, event_repository, candidate_sha, event_name):
    candidate = candidate.resolve(strict=True)
    trusted = trusted.resolve(strict=True)
    if candidate == trusted or candidate in trusted.parents or trusted in candidate.parents: raise ValueError("Candidate and trusted roots must be separate")
    if event_repository != CANDIDATE_REPOSITORY: raise ValueError("Wrong target repository")
    if event_name not in {"pull_request", "merge_group"}: raise ValueError("Unsupported required-workflow event")
    if not SHA.fullmatch(candidate_sha): raise ValueError("Invalid candidate SHA")
    if repository(candidate) != CANDIDATE_REPOSITORY: raise ValueError("Wrong candidate checkout")
    if git(candidate, "rev-parse", "HEAD") != candidate_sha: raise ValueError("Candidate checkout does not match event SHA")
    if git(candidate, "rev-parse", "--is-shallow-repository") != "false": raise ValueError("Required candidate history is unavailable")
    if repository(trusted) != TRUSTED_REPOSITORY: raise ValueError("Wrong trusted checkout")
    if git(trusted, "rev-parse", "HEAD") != git(trusted, "rev-parse", TRUSTED_REF): raise ValueError("Trusted checkout is not protected main")
    if actual_lock != expected_lock: raise ValueError("Candidate dependency lock differs from trusted lock")
    raise ValueError("Trusted M1 control mismatch")
def identities(line):
    raise ValueError("Malformed trusted identity")
def duplicate():
    raise ValueError("Unsafe or duplicate trusted identity")
'''
        tests = "\n".join(f"def {name}(): pass" for name in (
            "test_valid_candidate_and_protected_controls", "test_reversed_roots_fail",
            "test_wrong_candidate_sha_fails", "test_malformed_identity_fails"))
        tests += "\ndef test_wrong_target_repository_fails():\n    with self.assertRaisesRegex(ValueError, 'target repository'):\n        self.check(repository='KiloAlpha021/security-workflows')\n"
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

    def test_current_fixed_target_static_contract(self) -> None:
        workflow = (self.candidate / ".github/workflows/m1-trusted.yml").read_text(encoding="utf-8")
        validate_workflow(workflow)
        cases = {
            "wrong_trading_repository": ("repository: KiloAlpha021/automated-trading-bot",
                                         "repository: Other/trading-bot"),
            "mutable_repository": ("repository: KiloAlpha021/automated-trading-bot",
                                   "repository: ${{ inputs.repository }}"),
            "wrong_candidate_path": ("path: candidate", "path: other"),
            "mutable_ref": ("ref: ${{ github.sha }}", "ref: main"),
            "wrong_trusted_repository": ("repository: KiloAlpha021/security-workflows",
                                         "repository: Other/security-workflows"),
            "wrong_trusted_ref": ("ref: main", "ref: develop"),
            "wrong_trusted_path": ("path: trusted", "path: other"),
            "wrong_event": ("EVENT_REPOSITORY: ${{ github.repository }}",
                            "EVENT_REPOSITORY: ${{ inputs.repository }}"),
            "wrong_sha": ("CANDIDATE_SHA: ${{ github.sha }}",
                          "CANDIDATE_SHA: ${{ github.event.pull_request.head.sha }}"),
            "substituted_verifier": ("python trusted/verify_candidate.py",
                                     "python candidate/verify_candidate.py"),
            "missing_verifier": ("python trusted/verify_candidate.py", "Write-Host accepted"),
            "ignored_exit": ("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                             "Write-Host accepted"),
            "malformed_yaml": ("jobs:", "jobs: ["),
            "duplicate_key": ("          path: candidate", "          path: candidate\n          path: candidate"),
            "hidden_checkout": ("      - name: Enforce separate candidate and trusted identities",
                                "      - uses: actions/checkout@" + "1" * 40 +
                                "\n      - name: Enforce separate candidate and trusted identities"),
        }
        for name, (old, new) in cases.items():
            with self.subTest(name=name):
                self.assertIn(old, workflow)
                changed = workflow.replace(old, new, 1)
                with self.assertRaises(ValueError):
                    validate_workflow(changed)
        decoy = workflow.replace("repository: KiloAlpha021/automated-trading-bot",
                                 "repository: Other/trading-bot", 1)
        decoy += "\n# repository: KiloAlpha021/automated-trading-bot\n"
        with self.assertRaises(ValueError):
            validate_workflow(decoy)

    def test_current_fixed_target_runtime_and_adversarial_contract(self) -> None:
        verifier = (self.candidate / "verify_candidate.py").read_text(encoding="utf-8")
        tests = (self.candidate / "test_verify_candidate.py").read_text(encoding="utf-8")
        validate_verifier(verifier)
        validate_tests(tests)
        for old, new in (
            ('KiloAlpha021/automated-trading-bot', 'Other/trading-bot'),
            ('if event_repository != CANDIDATE_REPOSITORY', 'if False'),
            ('if event_name not in {"pull_request", "merge_group"}', 'if False'),
            ('if candidate == trusted or candidate in trusted.parents or trusted in candidate.parents', 'if False'),
            ('if repository(candidate) != CANDIDATE_REPOSITORY', 'if False'),
            ('if git(candidate, "rev-parse", "HEAD") != candidate_sha', 'if False'),
            ('if repository(trusted) != TRUSTED_REPOSITORY', 'if False'),
            ('if actual_lock != expected_lock', 'if False'),
        ):
            with self.subTest(guard=old):
                self.assertIn(old, verifier)
                changed = verifier.replace(old, new, 1) + "\n# " + old + "\n"
                with self.assertRaises(ValueError):
                    validate_verifier(changed)
        missing_test = tests.replace("def test_wrong_target_repository_fails", "def renamed_test")
        with self.assertRaises(ValueError):
            validate_tests(missing_test + "\n# test_wrong_target_repository_fails\n")
        ineffective_test = tests.replace("repository='KiloAlpha021/security-workflows'",
                                         "repository='KiloAlpha021/automated-trading-bot'")
        with self.assertRaises(ValueError):
            validate_tests(ineffective_test)

    def test_structural_action_references(self) -> None:
        workflow = (self.candidate / ".github/workflows/m1-trusted.yml").read_text()
        sha = "1" * 40
        refs = action_references(workflow)
        self.assertEqual([ref for _, ref in refs],
                         [f"actions/checkout@{sha}"] * 2 + [f"actions/setup-python@{sha}"])
        named = workflow.replace("- uses: actions/checkout@", "- name: checkout\n        uses: actions/checkout@")
        self.assertEqual([ref for _, ref in action_references(named)],
                         [f"actions/checkout@{sha}"] * 2 + [f"actions/setup-python@{sha}"])
        quoted = workflow.replace("- uses: actions/checkout@" + sha,
                                  '- uses: "actions/checkout@' + sha + '"')
        self.assertEqual([ref for _, ref in action_references(quoted)],
                         [f"actions/checkout@{sha}"] * 2 + [f"actions/setup-python@{sha}"])
        escaped_key = workflow.replace("- uses:", '- "\\u0075ses":', 1)
        self.assertEqual([ref for _, ref in action_references(escaped_key)],
                         [f"actions/checkout@{sha}"] * 2 + [f"actions/setup-python@{sha}"])
        reusable = workflow.replace("    steps:\n", f"    uses: KiloAlpha021/security-policy/.github/workflows/evaluator.yml@{sha}\n    steps:\n", 1)
        self.assertEqual(len(action_references(reusable)), 4)
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
        self.assertEqual(len(observed), 4)
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
            "G2_MAINTENANCE_GENERATION": bootstrap.G2_MAINTENANCE_GENERATION,
        })
        self.assertNotIn("continue-on-error", text)
        self.assertNotIn("GITHUB_ENV", text)

        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        names = [step["name"] for step in steps]
        expected = [
            "Check out exact candidate", "Check out independent root policy", "Set up CPython",
            "Assert exact CPython runtime", "Acquire protected Git identity",
            "Resolve exact B3 proposal identities",
            "Check out exact B3 establishment proposal E",
            "Check out exact selected B1 provenance P",
            "Resolve protected bootstrap authority", "Assert protected bootstrap outputs",
            "Enforce exact Model D maintenance admission",
            "Enforce exact DESIGN-B terminal admission",
            "Resolve protected Model D orchestration", "Assert protected Model D outputs",
            "Install isolated hash-locked policy environment", "Run candidate Stage A evidence",
            "Run legacy protected health", "Apply protected Stage A baseline to candidate target",
            "Test independent root policy", "Install isolated hash-locked audit environment",
            "Audit locked policy dependencies", "Validate downstream security workflows",
        ]
        self.assertEqual(names, expected)
        by_name = {step["name"]: step for step in steps}
        self.assertIn(
            'python -I -S "${{ github.workspace }}/policy/protected_policy_bootstrap.py" select-b3-p',
            by_name["Resolve exact B3 proposal identities"]["run"])

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
                         names.index("Check out exact selected B1 provenance P") + 1)
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
        self.assertEqual(
            admission["if"],
            "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP' && steps.protected-git.outputs.b3-enabled != 'true'")
        for fragment in (
            'python -I -S "${{ github.workspace }}/policy/protected_policy_bootstrap.py"',
            "admit-maintenance", "--maintenance-operation MODEL_D_ORCHESTRATION_V1",
            '--maintenance-generation "${{ env.G2_MAINTENANCE_GENERATION }}"',
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
        syntax = ast.parse(validator)
        functions = {node.name for node in syntax.body if isinstance(node, ast.FunctionDef)}
        self.assertTrue({"verify", "validate_workflow", "validate_verifier",
                         "validate_identities", "validate_tests"} <= functions)
        for fragment in (
            "KiloAlpha021/automated-trading-bot",
            "if event_repository != CANDIDATE_REPOSITORY",
            "repository(candidate) != CANDIDATE_REPOSITORY",
            "Candidate checkout does not match event SHA",
            "Candidate and trusted roots must be separate",
            "Trusted M1 control mismatch",
        ):
            self.assertIn(fragment, validator)

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
                ("KiloAlpha021/automated-trading-bot", "KiloAlpha021/other"),
                ("if event_repository != CANDIDATE_REPOSITORY", "if False"),
                ("repository(candidate) != CANDIDATE_REPOSITORY", "False"),
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
                         "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP' && steps.protected-git.outputs.b3-enabled != 'true'")
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
            "unknown_repository_accepted": ("verify_candidate.py", "if event_repository != CANDIDATE_REPOSITORY", "if False"),
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
            "repository_dispatch_weakened": ("verify_candidate.py", "if event_repository != CANDIDATE_REPOSITORY", "if False"),
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
            "__future__", "argparse", "ast", "hashlib", "os", "re", "stat", "subprocess", "sys",
            "tempfile", "dataclasses", "enum", "pathlib", "unicodedata"
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
        "VariableExpressionAst", "IndexExpressionAst", "MemberExpressionAst",
        "SubExpressionAst", "TypeExpressionAst",
    })
    _COMMANDS = {
        "Assert exact CPython runtime": ("python",),
        "Acquire protected Git identity": ("git", "Out-File", "Get-Content", "Out-File"),
        "Resolve exact B3 proposal identities": ("git", "python", "Out-File", "Out-File"),
        "Enforce exact DESIGN-B terminal admission": ("python",),
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
        "Acquire protected Git identity": "42f84cc61849df6f624e89aec24b79d879613e3ee90093e7419a088f8a99fc9f",
        "Resolve exact B3 proposal identities": "85e9480bc77b27871892d2f6f99f8dda934a59fb798351b1679593c2cbb61dec",
        "Enforce exact DESIGN-B terminal admission": "624d07da700b166d38005a31c72cbb95afe780cf94081748aebb4f5da9b2f8fd",
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
        "Acquire protected Git identity": "626f38d5235646eebb8630cef6a809250712768735127c17c93ea94bcc65fb15",
        "Resolve exact B3 proposal identities": "4bc0bbaf4a3b93b158c80966d4c245a28cb5a621c85bb7d462a38433f6155878",
        "Enforce exact DESIGN-B terminal admission": "d96cbb766649076440ed894b7c091515c566b09a1800d22cd2119d24b27aacbe",
        "Resolve protected bootstrap authority": "d10fe55d40daab7b732dc2414601063a036a64f8fd75abe71ecfa089546a4ff2",
        "Enforce exact Model D maintenance admission": "244ee8225afbae50176f170eadf00b1e403fcc339a10ed5a59a70cb5434bac83",
        "Resolve protected Model D orchestration": "3b75d73c87092e553ff4a60922371a26049cb145e72d34863a65df263987a6c7",
        "Install isolated hash-locked policy environment": "6d079a592228d8f8d41be75c44f12aadbf9c7a04a268939af4f9ab330c84ed45",
        "Install isolated hash-locked audit environment": "14db3625de27e1630df2c448364e8b26521bb169aecceac851a270172d6ffa61",
        "Audit locked policy dependencies": "6d079a592228d8f8d41be75c44f12aadbf9c7a04a268939af4f9ab330c84ed45",
    }
    _ASSIGNMENT_DIGESTS = {
        "Assert exact CPython runtime": "d28dad29c037f617afecde27704bef3d358314acff79e6e0dc6e838ef68ddbab",
        "Acquire protected Git identity": "320593180ff57d38faec11febbe67cf71e3b903ef323baf07f8150ce28aec235",
        "Resolve exact B3 proposal identities": "ea68267ec2ebaa3edb2418ab0e26adf76f576a5fbdf95761535eeb4cd52acf2e",
        "Resolve protected bootstrap authority": "7345417463fdbf2b043e1c7a229cc9ce631efc2c8de8348111022a2d6e8df5d6",
    }
    _STOP_ASSIGNMENT_DIGEST = "a6ff9ace77f1623d434a131b94c045ea59228ca4c1afaffe3900356c386bb1a5"
    _IF = {
        "Enforce exact Model D maintenance admission":
            "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP' && steps.protected-git.outputs.b3-enabled != 'true'",
        "Resolve exact B3 proposal identities":
            "steps.protected-git.outputs.b3-enabled == 'true' && github.event_name == 'pull_request'",
        "Check out exact B3 establishment proposal E":
            "steps.protected-git.outputs.b3-enabled == 'true' && github.event_name == 'pull_request'",
        "Check out exact selected B1 provenance P":
            "steps.protected-git.outputs.b3-enabled == 'true' && github.event_name == 'pull_request'",
        "Enforce exact DESIGN-B terminal admission":
            "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP' && steps.protected-git.outputs.b3-enabled == 'true'",
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
        "Acquire protected Git identity": (
            "$protectedSha -notmatch '^[0-9a-f]{40}$'",
            "[regex]::Matches($bootstrap, '(?m)^[ \\t]*B3_ENABLEMENT[ \\t]*=').Count -gt 1",
        ),
        "Resolve exact B3 proposal identities": (
            "$eSha -notmatch '^[0-9a-f]{40}$'",
            "$fields.Count -ne 3 -or $fields[0] -ne $eSha",
            "$proposedP -notmatch '^[0-9a-f]{40}$'",
            "$pSha -notmatch '^[0-9a-f]{40}$'",
            "$proposedP -ne $pSha",
        ),
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
        "bootstrap", "b3Enabled", "eSha", "parents", "fields", "proposedP", "pSha",
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
        "$ErrorActionPreference", "$pythonVersion", "$protectedSha", "$bootstrap",
        "$b3Enabled", "$eSha", "$parents", "$fields", "$proposedP", "$pSha",
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
            "G2_MAINTENANCE_GENERATION": bootstrap.G2_MAINTENANCE_GENERATION,
        })
        self.assertEqual(tuple(workflow["jobs"]), ("security-workflows-policy",))
        job = workflow["jobs"]["security-workflows-policy"]
        self.assertEqual(set(job), {"name", "runs-on", "steps"})
        self.assertEqual(job["runs-on"], "windows-latest")
        steps = job["steps"]
        self.assertEqual([step["name"] for step in steps], [
            "Check out exact candidate", "Check out independent root policy",
            "Set up CPython", "Assert exact CPython runtime",
            "Acquire protected Git identity", "Resolve exact B3 proposal identities",
            "Check out exact B3 establishment proposal E",
            "Check out exact selected B1 provenance P",
            "Resolve protected bootstrap authority", "Assert protected bootstrap outputs",
            "Enforce exact Model D maintenance admission",
            "Enforce exact DESIGN-B terminal admission",
            "Resolve protected Model D orchestration", "Assert protected Model D outputs",
            "Install isolated hash-locked policy environment",
            "Run candidate Stage A evidence", "Run legacy protected health",
            "Apply protected Stage A baseline to candidate target",
            "Test independent root policy", "Install isolated hash-locked audit environment",
            "Audit locked policy dependencies", "Validate downstream security workflows",
        ])
        self.assertEqual({step["name"]: step["if"] for step in steps if "if" in step},
                         self._IF)
        self.assertTrue(all("continue-on-error" not in step for step in steps))
        for step in steps:
            allowed = (({"name", "uses", "with"} |
                        ({"if"} if "if" in step else set())) if "uses" in step else
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
            "Resolve exact B3 proposal identities": "b3-identities",
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
            expected_pipelines = {
                "Acquire protected Git identity": [
                    '"protected-sha=$protectedSha" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append',
                    '"b3-enabled=$($b3Enabled.ToString().ToLowerInvariant())" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append'],
                "Resolve exact B3 proposal identities": [
                    '"e-sha=$eSha" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append',
                    '"p-sha=$pSha" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append'],
            }
            self.assertEqual(report["outputPipelines"], expected_pipelines.get(name, []), name)
            self.assertEqual(report["elseCount"], 0, name)
            self.assertTrue(run.lstrip().startswith("$ErrorActionPreference = 'Stop'"), name)
            assertions = tuple(condition for condition in report["conditions"]
                               if condition != "$LASTEXITCODE -ne 0")
            self.assertEqual(assertions, self._ASSERTIONS.get(name, ()), name)
            guard_count = report["conditions"].count("$LASTEXITCODE -ne 0")
            self.assertEqual(guard_count,
                             sum(command not in {"Out-File", "Get-Content"}
                                 for command in commands), name)
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
        historical_model_d = "2c1ea96e13e480cd13b4f6185c3763539d865400"
        for name in bootstrap.MODEL_D_MAINTENANCE_PATHS:
            (root / name).write_bytes(subprocess.run(
                ["git", "-C", str(source), "show", f"{historical_model_d}:{name}"],
                check=True, capture_output=True).stdout)
        git(root, "add", *bootstrap.MODEL_D_MAINTENANCE_PATHS)
        git(root, "commit", "-m", "Comprehensive D1-D4 Model D candidate")
        for name in bootstrap.MODEL_D_MAINTENANCE_PATHS:
            self.assertEqual(git(root, "rev-parse", f"HEAD:{name}"),
                              git(source, "rev-parse", f"{historical_model_d}:{name}"))
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
            '--maintenance-generation "${{ env.G2_MAINTENANCE_GENERATION }}"', run)
        self.assertIn("policy/protected_policy_bootstrap.py", run)
        self.assertNotIn("candidate/protected_policy_bootstrap.py", run)
        self.assertNotIn("1211595f9b0b5d1e76dd892bb210fece54f24b53", run)
        self.assertEqual(bootstrap._OUTPUT_KEYS, (
            "evaluation-context", "policy-source", "version-disposition",
            "owner-authorization", "post-merge-proof",
        ))


class B2BindingTests(unittest.TestCase):
    """Exercise one protected S0-to-S1 binding without implementing B3."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = Path(__file__).parent.resolve()
        self.protected = self.root / "protected"
        subprocess.run(["git", "clone", "--no-hardlinks", "--no-checkout", str(self.source),
                        str(self.protected)], check=True, capture_output=True)
        git(self.protected, "config", "user.name", "B2 Test")
        git(self.protected, "config", "user.email", "b2@example.invalid")
        git(self.protected, "config", "core.autocrlf", "false")
        git(self.protected, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")
        git(self.protected, "checkout", "-B", "main", bootstrap.G2_BOUND_ORIGIN)
        git(self.protected, "checkout", "-b", "b2-binding")
        for name in bootstrap.G2_BINDING_PATHS:
            (self.protected / name).write_bytes((self.source / name).read_bytes())
        git(self.protected, "add", *bootstrap.G2_BINDING_PATHS)
        git(self.protected, "commit", "-m", "Synthetic B2 binding proposal")
        self.binding_proposal = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "checkout", "main")
        git(self.protected, "merge", "--no-ff", "b2-binding", "-m",
            "Synthetic protected B2 binding")
        self.s1 = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", self.s1)

    def test_exact_s1_binding_introduction(self) -> None:
        bootstrap.validate_g2_bound_authority(self.protected, self.s1)
        self.assertEqual(bootstrap.G2_MAINTENANCE_LIFECYCLE,
                         bootstrap.G2_MAINTENANCE_GENERATION + ":ACTIVE_BOUND")
        self.assertEqual(bootstrap.G2_BOUND_ORIGIN,
                         "985bdf2801f07d8f2447d1bcde96c7a7a59669ad")
        self.assertEqual(bootstrap.G2_BOUND_CANDIDATE_TREE,
                         "4272cb4707345a1a3da41382525e9833e0f1a7e1")
        self.assertEqual(bootstrap.G2_EXPECTED_CANDIDATE_BLOBS, (
            (bootstrap.MODEL_D_MAINTENANCE_PATHS[0],
             "e8a2ff5957c77f03f1c5b8b16ae707820f11159f"),
            (bootstrap.MODEL_D_MAINTENANCE_PATHS[1],
             "7edbdf8c216aa336bae95af44fef8b9e4a582731"),
            (bootstrap.MODEL_D_MAINTENANCE_PATHS[2],
             "cd5ce5f194cef50dd016ca529f2857cf8c7a6082"),
        ))

    def test_wrong_s0_structure_and_protected_drift_reject(self) -> None:
        with mock.patch.object(bootstrap, "G2_BOUND_ORIGIN", "0" * 40), \
             self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_g2_bound_authority(self.protected, self.s1)
        git(self.protected, "commit", "--allow-empty", "-m", "Unrelated S2 drift")
        drift = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", drift)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "exact protected binding merge"):
            bootstrap.validate_g2_bound_authority(self.protected, drift)

        nested = self.root / "nested-binding"
        subprocess.run(["git", "clone", "--no-hardlinks", "--no-checkout", str(self.source),
                        str(nested)], check=True, capture_output=True)
        git(nested, "config", "user.name", "B2 Test")
        git(nested, "config", "user.email", "b2@example.invalid")
        git(nested, "config", "core.autocrlf", "false")
        git(nested, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")
        git(nested, "checkout", "-B", "main", bootstrap.G2_BOUND_ORIGIN)
        git(nested, "checkout", "-b", "nested-proposal")
        git(nested, "commit", "--allow-empty", "-m", "Unrelated proposal parent")
        for name in bootstrap.G2_BINDING_PATHS:
            (nested / name).write_bytes((self.source / name).read_bytes())
        git(nested, "add", *bootstrap.G2_BINDING_PATHS)
        git(nested, "commit", "-m", "Nested B2 binding proposal")
        git(nested, "checkout", "main")
        git(nested, "merge", "--no-ff", "nested-proposal", "-m", "Nested binding")
        nested_s1 = git(nested, "rev-parse", "HEAD")
        git(nested, "update-ref", "refs/remotes/origin/main", nested_s1)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "directly on S0"):
            bootstrap.validate_g2_bound_authority(nested, nested_s1)

    def test_binding_declarations_are_unique_and_candidate_cannot_replace_them(self) -> None:
        source = (self.source / "protected_policy_bootstrap.py").read_bytes()
        bootstrap._require_g2_bound_declarations(source)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._require_g2_bound_declarations(
                source + b'\nG2_BOUND_CANDIDATE_TREE = "0000000000000000000000000000000000000000"\n')
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap._require_g2_bound_declarations(
                source.replace(bootstrap.G2_BOUND_CANDIDATE_TREE.encode(), b"0" * 40))

    def _mock_bound_candidate(self, **changes: object) -> None:
        candidate = self.root / "candidate"
        candidate.mkdir(exist_ok=True)
        revision = "1" * 40
        parent = str(changes.get("parent", bootstrap.G2_BOUND_ORIGIN))
        tree = str(changes.get("tree", bootstrap.G2_BOUND_CANDIDATE_TREE))
        paths = changes.get("paths", bootstrap.MODEL_D_MAINTENANCE_PATHS)
        blobs = dict(bootstrap.G2_EXPECTED_CANDIDATE_BLOBS)
        blobs.update(changes.get("blobs", {}))
        remote = str(changes.get("remote", "https://github.com/KiloAlpha021/security-policy.git"))
        source = str(changes.get(
            "source",
            f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_BOUND_EXPECTED_TERMINAL}"\n'))

        def identity(root: Path, *arguments: str) -> str:
            if arguments == ("rev-parse", "HEAD"):
                return revision
            if arguments == ("remote", "get-url", "origin"):
                return remote
            if arguments == ("rev-list", "--parents", "-n", "1", revision):
                return f"{revision} {parent}"
            if arguments == ("rev-parse", f"{revision}^{{tree}}"):
                return tree
            if len(arguments) == 2 and arguments[0] == "rev-parse" and \
                    arguments[1].startswith(revision + ":"):
                return blobs[arguments[1].split(":", 1)[1]]
            raise AssertionError(arguments)

        diff = b"".join(b"M\0" + path.encode() + b"\0" for path in paths)

        def raw(root: Path, *arguments: str) -> bytes:
            if arguments[:4] == ("diff", "--name-status", "-z", "--no-renames"):
                return diff
            if arguments == ("show", f"{revision}:protected_policy_bootstrap.py"):
                return source.encode()
            raise AssertionError(arguments)

        entries = {path: ("100644", "blob") for path in bootstrap.MODEL_D_MAINTENANCE_PATHS}
        with mock.patch.object(bootstrap, "validate_g2_bound_authority"), \
             mock.patch.object(bootstrap, "_git", side_effect=identity), \
             mock.patch.object(bootstrap, "_git_bytes", side_effect=raw), \
             mock.patch.object(bootstrap, "_tree_entries", return_value=entries), \
             mock.patch.object(bootstrap, "validate_protected_universe"):
            bootstrap.validate_g2_bound_candidate_identity(
                candidate, revision, self.protected, self.s1)

    def test_exact_future_b1_identity_model(self) -> None:
        self._mock_bound_candidate()

    def test_wrong_tree_parent_paths_blobs_repository_and_rebase_reject(self) -> None:
        cases = (
            {"tree": "0" * 40},
            {"parent": "2" * 40},
            {"parent": self.s1},
            {"paths": bootstrap.MODEL_D_MAINTENANCE_PATHS[:-1]},
            {"blobs": {bootstrap.MODEL_D_MAINTENANCE_PATHS[1]: "0" * 40}},
            {"remote": "https://github.com/KiloAlpha021/security-workflows.git"},
            {"source": (f'G2_MAINTENANCE_LIFECYCLE = "'
                        f'{bootstrap.G2_MAINTENANCE_GENERATION}:ACTIVE_BOUND"\n')},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(bootstrap.BootstrapError):
                self._mock_bound_candidate(**changes)

    def test_exact_s1_abandonment_is_terminal(self) -> None:
        candidate = self.root / "abandonment"
        subprocess.run(["git", "clone", "--no-hardlinks", str(self.protected),
                        str(candidate)], check=True, capture_output=True)
        git(candidate, "config", "user.name", "B2 Test")
        git(candidate, "config", "user.email", "b2@example.invalid")
        git(candidate, "config", "core.autocrlf", "false")
        git(candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")
        source = candidate / "protected_policy_bootstrap.py"
        protected_source = bootstrap._git_bytes(
            self.protected, "show", f"{self.s1}:protected_policy_bootstrap.py")
        source.write_bytes(protected_source.replace(
            f'{bootstrap.G2_MAINTENANCE_GENERATION}:ACTIVE_BOUND'.encode(),
            f'{bootstrap.G2_MAINTENANCE_GENERATION}:CONSUMED'.encode()))
        git(candidate, "add", "protected_policy_bootstrap.py")
        git(candidate, "commit", "-m", "Abandon bound G2")
        candidate_sha = git(candidate, "rev-parse", "HEAD")
        bootstrap.validate_g2_maintenance(
            bootstrap.G2_MAINTENANCE_GENERATION, candidate, self.protected,
            candidate_sha, self.s1)
        git(self.protected, "fetch", str(candidate), candidate_sha)
        git(self.protected, "merge", "--no-ff", "FETCH_HEAD", "-m", "Expire bound G2")
        terminal = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", terminal)
        self.assertTrue(bootstrap._g2_generation_was_consumed(self.protected, terminal))
        with self.assertRaisesRegex(bootstrap.BootstrapError, "permanently consumed"):
            bootstrap.validate_g2_bound_authority(self.protected, terminal)

    def test_bound_rollback_and_ordinary_rebinding_reject(self) -> None:
        for replacement in (
                f'{bootstrap.G2_MAINTENANCE_GENERATION}:ACTIVE_UNBOUND',
                'G2_BOUND_CANDIDATE_TREE = "' + "0" * 40 + '"'):
            with self.subTest(replacement=replacement):
                candidate = self.root / ("mutation-" + str(len(list(self.root.iterdir()))))
                subprocess.run(["git", "clone", "--no-hardlinks", str(self.protected),
                                str(candidate)], check=True, capture_output=True)
                git(candidate, "config", "user.name", "B2 Test")
                git(candidate, "config", "user.email", "b2@example.invalid")
                git(candidate, "config", "core.autocrlf", "false")
                git(candidate, "remote", "set-url", "origin",
                    "https://github.com/KiloAlpha021/security-policy.git")
                source = candidate / "protected_policy_bootstrap.py"
                data = bootstrap._git_bytes(
                    self.protected, "show", f"{self.s1}:protected_policy_bootstrap.py")
                if replacement.endswith("ACTIVE_UNBOUND"):
                    data = data.replace(
                        f'{bootstrap.G2_MAINTENANCE_GENERATION}:ACTIVE_BOUND'.encode(),
                        replacement.encode())
                else:
                    declaration = (f'G2_BOUND_CANDIDATE_TREE = "'
                                   f'{bootstrap.G2_BOUND_CANDIDATE_TREE}"').encode()
                    data = data.replace(declaration, replacement.encode())
                source.write_bytes(data)
                git(candidate, "add", "protected_policy_bootstrap.py")
                git(candidate, "commit", "-m", "Attempt bound authority mutation")
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_g2_maintenance(
                        bootstrap.G2_MAINTENANCE_GENERATION, candidate, self.protected,
                        git(candidate, "rev-parse", "HEAD"), self.s1)

    def test_public_admission_does_not_implement_b3(self) -> None:
        with mock.patch.object(bootstrap, "validate_g2_bound_candidate_identity"), \
             self.assertRaisesRegex(bootstrap.BootstrapError, "B3 admission is not implemented"):
            candidate = self.root / "synthetic-b1"
            subprocess.run(["git", "clone", "--no-hardlinks", str(self.protected),
                            str(candidate)], check=True, capture_output=True)
            git(candidate, "remote", "set-url", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")
            git(candidate, "checkout", "-b", "candidate")
            marker = candidate / "README.md"
            marker.write_bytes(marker.read_bytes() + b"\n")
            git(candidate, "config", "user.name", "B2 Test")
            git(candidate, "config", "user.email", "b2@example.invalid")
            git(candidate, "add", "README.md")
            git(candidate, "commit", "-m", "Synthetic B1")
            bootstrap.validate_g2_maintenance(
                bootstrap.G2_MAINTENANCE_GENERATION, candidate, self.protected,
                git(candidate, "rev-parse", "HEAD"), self.s1)


class B3DesignBTests(unittest.TestCase):
    """Exercise finite enablement and separate P/E/T identities."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.protected = self.root / "protected"
        self.p = self.root / "p"
        self.e = self.root / "e"
        for path in (self.protected, self.p, self.e):
            path.mkdir()

    @staticmethod
    def _s1_declarations() -> bytes:
        lines = [
            f'MODEL_D_MAINTENANCE_GENERATION = "{bootstrap.MODEL_D_MAINTENANCE_GENERATION}"',
            f'MODEL_D_MAINTENANCE_LIFECYCLE = "{bootstrap.MODEL_D_MAINTENANCE_LIFECYCLE}"',
            f'G2_MAINTENANCE_GENERATION = "{bootstrap.G2_MAINTENANCE_GENERATION}"',
            f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_MAINTENANCE_GENERATION}:ACTIVE_BOUND"',
            f'G2_MAINTENANCE_PURPOSE = "{bootstrap.G2_MAINTENANCE_PURPOSE}"',
            f'G2_BOUND_ORIGIN = "{bootstrap.G2_BOUND_ORIGIN}"',
            f'G2_BOUND_CANDIDATE_TREE = "{bootstrap.G2_BOUND_CANDIDATE_TREE}"',
            f'G2_BOUND_WORKFLOW_BLOB = "{bootstrap.G2_BOUND_WORKFLOW_BLOB}"',
            f'G2_BOUND_BOOTSTRAP_BLOB = "{bootstrap.G2_BOUND_BOOTSTRAP_BLOB}"',
            f'G2_BOUND_TEST_BLOB = "{bootstrap.G2_BOUND_TEST_BLOB}"',
            f'G2_BOUND_EXPECTED_TERMINAL = "{bootstrap.G2_BOUND_EXPECTED_TERMINAL}"',
        ]
        return ("\n".join(lines) + "\n").encode()

    @classmethod
    def _enablement_source(cls, extra: str = "") -> bytes:
        source = cls._s1_declarations().decode() + (
            f'B3_AUTHORITY_ORIGIN = "{bootstrap.B3_AUTHORITY_ORIGIN}"\n'
            f'B3_ENABLEMENT = "{bootstrap.B3_ENABLEMENT}"\n')
        return (source + extra).encode()

    def _validate_enablement_candidate_case(
            self, source: bytes, *, protected_sha: str | None = None,
            parents: str | None = None,
            paths: tuple[str, ...] | None = None) -> None:
        proposal = "2" * 40
        protected_sha = protected_sha or bootstrap.B3_AUTHORITY_ORIGIN
        parents = parents or f"{proposal} {bootstrap.B3_AUTHORITY_ORIGIN}"

        def identity(_root: Path, *arguments: str) -> str:
            values = {
                ("rev-parse", "HEAD"): proposal,
                ("remote", "get-url", "origin"):
                    "https://github.com/KiloAlpha021/security-policy.git",
                ("rev-list", "--parents", "-n", "1", proposal): parents,
            }
            return values[arguments]

        def raw(_root: Path, *arguments: str) -> bytes:
            if arguments == ("show", f"{bootstrap.B3_AUTHORITY_ORIGIN}:protected_policy_bootstrap.py"):
                return self._s1_declarations()
            return source

        with mock.patch.object(bootstrap, "validate_g2_bound_authority"), \
             mock.patch.object(bootstrap, "_git", side_effect=identity), \
             mock.patch.object(bootstrap, "_git_bytes", side_effect=raw), \
             mock.patch.object(bootstrap, "_exact_modified_paths",
                               return_value=paths or bootstrap.MODEL_D_MAINTENANCE_PATHS), \
             mock.patch.object(bootstrap, "validate_protected_universe"):
            bootstrap.validate_b3_enablement_candidate(
                self.protected, proposal, self.root, protected_sha)

    def test_design_b_constants_are_frozen_without_future_shas(self) -> None:
        self.assertEqual(bootstrap.B3_AUTHORITY_ORIGIN,
                         "9393099a9060f90689341611457c9b9032959b88")
        self.assertEqual(bootstrap.B3_ENABLEMENT, "DESIGN_B_FINITE_V1")
        source = Path(bootstrap.__file__).read_text(encoding="utf-8")
        self.assertNotRegex(source, r"G2_SELECTED_P_SHA\s*=")

    def test_enablement_rejects_future_p_sha_under_any_declaration_name(self) -> None:
        """S2 must not embed a future P identity under an alternate symbol."""
        selected_p = "a" * 40
        for name in ("FUTURE_P_SHA", "NEXT_P", "AUTHORIZED_PROVENANCE", "CANDIDATE_COMMIT"):
            with self.subTest(name=name), self.assertRaisesRegex(
                    bootstrap.BootstrapError, "closed S1 schema"):
                self._validate_enablement_candidate_case(
                    self._enablement_source(f'{name} = "{selected_p}"\n'))

    def test_closed_enablement_schema_accepts_only_frozen_declarations(self) -> None:
        self._validate_enablement_candidate_case(self._enablement_source(
            'def helper():\n    historical_sha = "' + "a" * 40 + '"\n'))
        mutations = {
            "generation": ("GENERATION_2", "GENERATION_3"),
            "purpose": (bootstrap.G2_MAINTENANCE_PURPOSE, "replacement purpose"),
            "g1-revival": (":CONSUMED", ":ACTIVE"),
            "origin": (bootstrap.G2_BOUND_ORIGIN, "0" * 40),
            "tree": (bootstrap.G2_BOUND_CANDIDATE_TREE, "0" * 40),
            "workflow": (bootstrap.G2_BOUND_WORKFLOW_BLOB, "0" * 40),
            "bootstrap": (bootstrap.G2_BOUND_BOOTSTRAP_BLOB, "0" * 40),
            "test": (bootstrap.G2_BOUND_TEST_BLOB, "0" * 40),
        }
        pristine = self._enablement_source().decode()
        for name, (before, after) in mutations.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                    bootstrap.BootstrapError, "closed S1 schema"):
                self._validate_enablement_candidate_case(
                    pristine.replace(before, after, 1).encode())
        for lifecycle in ("CONSUMED", "ACTIVE_UNBOUND"):
            changed = pristine.replace(":ACTIVE_BOUND", f":{lifecycle}", 1).encode()
            with self.subTest(lifecycle=lifecycle), self.assertRaises(bootstrap.BootstrapError):
                self._validate_enablement_candidate_case(changed)
        duplicate = pristine + (
            f'G2_BOUND_ORIGIN = "{bootstrap.G2_BOUND_ORIGIN}"\n')
        with self.assertRaises(bootstrap.BootstrapError):
            self._validate_enablement_candidate_case(duplicate.encode())
        with self.assertRaisesRegex(bootstrap.BootstrapError, "exact S1"):
            self._validate_enablement_candidate_case(
                self._enablement_source(), protected_sha="0" * 40)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "based directly"):
            self._validate_enablement_candidate_case(
                self._enablement_source(), parents="2" * 40 + " " + "3" * 40)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "scope"):
            self._validate_enablement_candidate_case(
                self._enablement_source(), paths=("protected_policy_bootstrap.py",))

    def test_actual_candidate_declaration_schema_is_closed(self) -> None:
        repository = Path(__file__).parent.resolve()
        s1_equivalent = bootstrap._git_bytes(
            repository, "show", f"{bootstrap.B3_AUTHORITY_ORIGIN}:protected_policy_bootstrap.py")
        candidate = bootstrap._git_bytes(
            repository, "show", f"{bootstrap.B3_CORRECTION_BASE}:protected_policy_bootstrap.py")
        bootstrap._require_b3_enablement_declaration_schema(
            s1_equivalent, candidate)

    def test_native_design_b_topology_is_representable(self) -> None:
        repo = self.root / "topology"
        repo.mkdir()
        git(repo, "init", "-b", "main")
        git(repo, "config", "user.name", "B3 Test")
        git(repo, "config", "user.email", "b3@example.invalid")
        (repo / "state").write_text("S0\n", encoding="utf-8")
        git(repo, "add", "state")
        git(repo, "commit", "-m", "S0")
        s0 = git(repo, "rev-parse", "HEAD")
        git(repo, "commit", "--allow-empty", "-m", "S1")
        s1 = git(repo, "rev-parse", "HEAD")
        git(repo, "commit", "--allow-empty", "-m", "S2")
        s2 = git(repo, "rev-parse", "HEAD")
        git(repo, "checkout", "--detach", s0)
        (repo / "state").write_text("terminal\n", encoding="utf-8")
        git(repo, "add", "state")
        git(repo, "commit", "-m", "P")
        p = git(repo, "rev-parse", "HEAD")
        tree = git(repo, "rev-parse", "HEAD^{tree}")

        def commit_tree(message: str, *parents: str) -> str:
            command = ["git", "-C", str(repo), "commit-tree", tree]
            for parent in parents:
                command.extend(("-p", parent))
            return subprocess.run(command, input=message + "\n", text=True,
                                  check=True, capture_output=True).stdout.strip()

        e = commit_tree("E", s2, p)
        t = commit_tree("T", s2, e)
        self.assertEqual(git(repo, "rev-list", "--parents", "-n", "1", e).split(),
                         [e, s2, p])
        self.assertEqual(git(repo, "rev-list", "--parents", "-n", "1", t).split(),
                         [t, s2, e])
        self.assertEqual(git(repo, "rev-parse", f"{e}^{{tree}}"), tree)
        self.assertEqual(git(repo, "rev-parse", f"{t}^{{tree}}"), tree)
        self.assertEqual(git(repo, "rev-list", "--count", f"{s2}..{e}"), "2")
        self.assertEqual(git(repo, "merge-base", s1, s2), s1)

    def test_established_s2_requires_one_exact_protected_enablement(self) -> None:
        s2, proposal = "3" * 40, "2" * 40

        def run(*, head: str | None = None, main: str | None = None,
                merge_parents: str | None = None, proposal_parents: str | None = None,
                proposal_tree: str = "4" * 40, merge_tree: str = "4" * 40,
                source: bytes | None = None,
                paths: tuple[str, ...] | None = None) -> None:
            def identity(_root: Path, *arguments: str) -> str:
                values = {
                    ("rev-parse", "HEAD"): head or s2,
                    ("rev-parse", "refs/remotes/origin/main"): main or s2,
                    ("remote", "get-url", "origin"):
                        "https://github.com/KiloAlpha021/security-policy.git",
                    ("rev-list", "--parents", "-n", "1", s2):
                        merge_parents or f"{s2} {bootstrap.B3_AUTHORITY_ORIGIN} {proposal}",
                    ("rev-list", "--parents", "-n", "1", proposal):
                        proposal_parents or f"{proposal} {bootstrap.B3_AUTHORITY_ORIGIN}",
                    ("rev-parse", f"{proposal}^{{tree}}"): proposal_tree,
                    ("rev-parse", f"{s2}^{{tree}}"): merge_tree,
                }
                return values[arguments]

            def raw(_root: Path, *arguments: str) -> bytes:
                if arguments == ("show", f"{bootstrap.B3_AUTHORITY_ORIGIN}:protected_policy_bootstrap.py"):
                    return self._s1_declarations()
                return source or self._enablement_source()

            with mock.patch.object(bootstrap, "_git", side_effect=identity), \
                 mock.patch.object(bootstrap, "_git_bytes", side_effect=raw), \
                 mock.patch.object(bootstrap, "_exact_modified_paths",
                                   return_value=paths or bootstrap.MODEL_D_MAINTENANCE_PATHS), \
                 mock.patch.object(bootstrap, "validate_protected_universe"):
                bootstrap.validate_b3_enabled_authority(self.protected, s2)

        run()
        cases = (
            ("head", {"head": "0" * 40}, "checkout"),
            ("main", {"main": "0" * 40}, "protected main"),
            ("one-parent", {"merge_parents": f"{s2} {bootstrap.B3_AUTHORITY_ORIGIN}"}, "finite"),
            ("wrong-first-parent", {"merge_parents": f"{s2} {'0' * 40} {proposal}"}, "finite"),
            ("extra-enable", {"proposal_parents": f"{proposal} {'1' * 40}"}, "directly on S1"),
            ("tree-mismatch", {"merge_tree": "5" * 40}, "tree differs"),
            ("scope", {"paths": ("protected_policy_bootstrap.py",)}, "scope"),
            ("closed-schema", {"source": self._enablement_source(
                'NEXT_P = "' + "a" * 40 + '"\n')}, "closed S1 schema"),
        )
        for name, options, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                    bootstrap.BootstrapError, message):
                run(**options)

    def _mock_p(self, *, revision: str = "1" * 40, head: str | None = None,
                parent: str | None = None, parents: str | None = None,
                tree: str | None = None, repository: str | None = None,
                kind: str = "commit", attribution: str | None = None,
                paths: tuple[str, ...] | None = None,
                entries: dict[str, tuple[str, str]] | None = None,
                blobs: dict[str, str] | None = None,
                lifecycle: str = "CONSUMED", terminal: bool = True) -> None:
        parent = parent or bootstrap.G2_BOUND_ORIGIN
        tree = tree or bootstrap.G2_BOUND_CANDIDATE_TREE
        blobs = blobs or dict(bootstrap.G2_EXPECTED_CANDIDATE_BLOBS)

        def identity(root: Path, *arguments: str) -> str:
            if arguments == ("rev-parse", "HEAD"):
                return head or revision
            if arguments == ("remote", "get-url", "origin"):
                return repository or "https://github.com/KiloAlpha021/security-policy.git"
            if arguments == ("cat-file", "-t", revision):
                return kind
            if arguments == ("rev-list", "--parents", "-n", "1", revision):
                return parents or f"{revision} {parent}"
            if arguments == ("rev-parse", f"{revision}^{{tree}}"):
                return tree
            if len(arguments) == 2 and arguments[0] == "rev-parse" and arguments[1].startswith(revision + ":"):
                return blobs[arguments[1].split(":", 1)[1]]
            raise AssertionError(arguments)

        disposition = bootstrap.G2_BOUND_EXPECTED_TERMINAL if terminal else "not-terminal"
        raw = (f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_MAINTENANCE_GENERATION}:{lifecycle}"\n'
               f'# {disposition}\n').encode()
        entries = entries or {path: ("100644", "blob") for path in bootstrap.MODEL_D_MAINTENANCE_PATHS}
        def output(_root: Path, *arguments: str) -> bytes:
            if arguments[:2] == ("show", "-s"):
                value = (attribution if attribution is not None else
                         "B3 Test\0b3@example.invalid\0B3 Test\0b3@example.invalid")
                return (value + "\n").encode()
            return raw
        with mock.patch.object(bootstrap, "_git", side_effect=identity), \
             mock.patch.object(bootstrap, "_git_bytes", side_effect=output), \
             mock.patch.object(bootstrap, "_exact_modified_paths",
                               return_value=paths or bootstrap.MODEL_D_MAINTENANCE_PATHS), \
             mock.patch.object(bootstrap, "_tree_entries", return_value=entries), \
             mock.patch.object(bootstrap, "validate_protected_universe"):
            bootstrap._validate_b1_candidate(self.p, revision)

    def test_exact_p_and_selected_sha_are_required(self) -> None:
        self._mock_p()
        with self.assertRaisesRegex(bootstrap.BootstrapError, "selected P SHA"):
            self._mock_p(head="2" * 40)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "sole parent S0"):
            self._mock_p(parent=bootstrap.B3_AUTHORITY_ORIGIN)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "tree mismatch"):
            self._mock_p(tree="0" * 40)

    def test_p_complete_adversarial_matrix(self) -> None:
        cases = (
            ("repository", {"repository": "https://github.com/KiloAlpha021/security-workflows.git"}, "repository"),
            ("object", {"kind": "tree"}, "not a commit"),
            ("attribution", {"attribution": "\0\0\0"}, "attribution"),
            ("head", {"head": "2" * 40}, "selected P SHA"),
            ("no-parent", {"parents": "1" * 40}, "sole parent S0"),
            ("two-parents", {"parents": "1" * 40 + " " + bootstrap.G2_BOUND_ORIGIN + " " + bootstrap.B3_AUTHORITY_ORIGIN}, "sole parent S0"),
            ("parent-s1", {"parent": bootstrap.B3_AUTHORITY_ORIGIN}, "sole parent S0"),
            ("parent-s2", {"parent": "2" * 40}, "sole parent S0"),
            ("retired-tree", {"tree": "c49159c2076c2e1f1ba9681b32d71264e1cb98f9"}, "tree mismatch"),
            ("forensic-tree", {"tree": "373f05b6fef5e5d2d5e47c45355664d888454c4b"}, "tree mismatch"),
            ("paths-missing", {"paths": bootstrap.MODEL_D_MAINTENANCE_PATHS[:-1]}, "paths mismatch"),
            ("paths-extra", {"paths": bootstrap.MODEL_D_MAINTENANCE_PATHS + ("extra",)}, "paths mismatch"),
            ("active-bound", {"lifecycle": "ACTIVE_BOUND"}, "terminal CONSUMED"),
            ("active-unbound", {"lifecycle": "ACTIVE_UNBOUND"}, "terminal CONSUMED"),
        )
        for name, options, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                    bootstrap.BootstrapError, message):
                self._mock_p(**options)
        for path in bootstrap.MODEL_D_MAINTENANCE_PATHS:
            entries = {item: ("100644", "blob")
                       for item in bootstrap.MODEL_D_MAINTENANCE_PATHS}
            entries[path] = ("100755", "blob")
            with self.subTest(mode=path), self.assertRaisesRegex(
                    bootstrap.BootstrapError, "100644"):
                self._mock_p(entries=entries)
            blobs = dict(bootstrap.G2_EXPECTED_CANDIDATE_BLOBS)
            blobs[path] = "0" * 40
            with self.subTest(blob=path), self.assertRaisesRegex(
                    bootstrap.BootstrapError, "blob mismatch"):
                self._mock_p(blobs=blobs)

    def test_selected_p_sha_rejects_same_content_alternate_commit(self) -> None:
        selected, alternate, s2, e_sha = bootstrap.EXPECTED_P_SHA, "9" * 40, "2" * 40, "3" * 40

        def identity(root: Path, *arguments: str) -> str:
            values = {
                ("rev-parse", "HEAD"): e_sha,
                ("remote", "get-url", "origin"):
                    "https://github.com/KiloAlpha021/security-policy.git",
                ("cat-file", "-t", e_sha): "commit",
                ("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce", e_sha):
                    "B3 Test\0b3@example.invalid\0B3 Test\0b3@example.invalid",
                ("rev-list", "--parents", "-n", "1", e_sha):
                    f"{e_sha} {s2} {alternate}",
            }
            return values[arguments]

        with mock.patch.object(bootstrap, "validate_b3_selected_authority"), \
             mock.patch.object(bootstrap, "_validate_b1_candidate"), \
             mock.patch.object(bootstrap, "_git_attribution"), \
             mock.patch.object(bootstrap, "_git", side_effect=identity):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "selected P"):
                bootstrap.validate_b3_establishment(
                    self.protected, s2, self.p, selected, self.e, e_sha)

    def test_e_requires_selected_p_order_and_terminal_tree(self) -> None:
        s2, p_sha, e_sha = "2" * 40, bootstrap.EXPECTED_P_SHA, "3" * 40

        def identity(root: Path, *arguments: str) -> str:
            if root == self.e and arguments == ("rev-parse", "HEAD"):
                return e_sha
            if root == self.e and arguments == ("remote", "get-url", "origin"):
                return "https://github.com/KiloAlpha021/security-policy.git"
            if root == self.e and arguments == ("cat-file", "-t", e_sha):
                return "commit"
            if root == self.e and arguments == ("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce", e_sha):
                return "B3 Test\0b3@example.invalid\0B3 Test\0b3@example.invalid"
            if root == self.e and arguments == ("rev-list", "--parents", "-n", "1", e_sha):
                return f"{e_sha} {s2} {p_sha}"
            if root == self.e and arguments == ("rev-parse", f"{e_sha}^{{tree}}"):
                return bootstrap.G2_BOUND_CANDIDATE_TREE
            if root == self.e and len(arguments) == 2 and arguments[0] == "rev-parse":
                return dict(bootstrap.G2_EXPECTED_CANDIDATE_BLOBS)[arguments[1].split(":", 1)[1]]
            raise AssertionError((root, arguments))

        terminal = (f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_BOUND_EXPECTED_TERMINAL}"\n').encode()
        with mock.patch.object(bootstrap, "validate_b3_selected_authority"), \
             mock.patch.object(bootstrap, "_validate_b1_candidate"), \
             mock.patch.object(bootstrap, "_git_attribution"), \
             mock.patch.object(bootstrap, "_git", side_effect=identity), \
             mock.patch.object(bootstrap, "_git_bytes", return_value=terminal), \
             mock.patch.object(bootstrap, "validate_protected_universe"):
            bootstrap.validate_b3_establishment(
                self.protected, s2, self.p, p_sha, self.e, e_sha)

    def test_e_complete_adversarial_matrix(self) -> None:
        s2, p_sha, e_sha = "2" * 40, bootstrap.EXPECTED_P_SHA, "3" * 40

        def run(*, head: str | None = None, repository: str | None = None,
                kind: str = "commit", attribution: str | None = None,
                parents: str | None = None, tree: str | None = None,
                blobs: dict[str, str] | None = None,
                lifecycle: str = "CONSUMED") -> None:
            actual_blobs = blobs or dict(bootstrap.G2_EXPECTED_CANDIDATE_BLOBS)

            def identity(root: Path, *arguments: str) -> str:
                values = {
                    ("rev-parse", "HEAD"): head or e_sha,
                    ("remote", "get-url", "origin"):
                        repository or "https://github.com/KiloAlpha021/security-policy.git",
                    ("cat-file", "-t", e_sha): kind,
                    ("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce", e_sha):
                        attribution if attribution is not None else
                        "B3 Test\0b3@example.invalid\0B3 Test\0b3@example.invalid",
                    ("rev-list", "--parents", "-n", "1", e_sha):
                        parents or f"{e_sha} {s2} {p_sha}",
                    ("rev-parse", f"{e_sha}^{{tree}}"): tree or bootstrap.G2_BOUND_CANDIDATE_TREE,
                }
                if (len(arguments) == 2 and arguments[0] == "rev-parse"
                        and arguments[1].startswith(e_sha + ":")):
                    return actual_blobs[arguments[1].split(":", 1)[1]]
                return values[arguments]

            raw = (f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_MAINTENANCE_GENERATION}:{lifecycle}"\n').encode()
            with mock.patch.object(bootstrap, "validate_b3_selected_authority"), \
                 mock.patch.object(bootstrap, "_validate_b1_candidate"), \
                 mock.patch.object(bootstrap, "_git_attribution",
                                   side_effect=(bootstrap.BootstrapError("B3 E attribution is malformed")
                                                if attribution == "\0\0\0" else None)), \
                 mock.patch.object(bootstrap, "_git", side_effect=identity), \
                 mock.patch.object(bootstrap, "_git_bytes", return_value=raw), \
                 mock.patch.object(bootstrap, "validate_protected_universe"):
                bootstrap.validate_b3_establishment(
                    self.protected, s2, self.p, p_sha, self.e, e_sha)

        cases = (
            ("head", {"head": "0" * 40}, "E checkout"),
            ("repository", {"repository": "https://github.com/KiloAlpha021/security-workflows.git"}, "repository"),
            ("object", {"kind": "tree"}, "not a commit"),
            ("attribution", {"attribution": "\0\0\0"}, "attribution"),
            ("one-parent", {"parents": f"{e_sha} {s2}"}, "ordered parents"),
            ("extra-parent", {"parents": f"{e_sha} {s2} {p_sha} {'4' * 40}"}, "ordered parents"),
            ("reversed", {"parents": f"{e_sha} {p_sha} {s2}"}, "ordered parents"),
            ("wrong-s2", {"parents": f"{e_sha} {'4' * 40} {p_sha}"}, "ordered parents"),
            ("wrong-p", {"parents": f"{e_sha} {s2} {'9' * 40}"}, "selected P"),
            ("tree", {"tree": "0" * 40}, "tree mismatch"),
            ("one-byte-result", {"tree": "f" * 40}, "tree mismatch"),
            ("wrong-mode", {"tree": "e" * 40}, "tree mismatch"),
            ("missing-path", {"tree": "d" * 40}, "tree mismatch"),
            ("extra-path", {"tree": "c" * 40}, "tree mismatch"),
            ("mixed-s2-b1", {"tree": "b" * 40}, "tree mismatch"),
            ("wrong-g1", {"tree": "a" * 40}, "tree mismatch"),
            ("replacement-binding", {"tree": "8" * 40}, "tree mismatch"),
            ("unexpected-authority", {"tree": "7" * 40}, "tree mismatch"),
            ("active-bound", {"lifecycle": "ACTIVE_BOUND"}, "terminal CONSUMED"),
            ("active-unbound", {"lifecycle": "ACTIVE_UNBOUND"}, "terminal CONSUMED"),
        )
        for name, options, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                    bootstrap.BootstrapError, message):
                run(**options)
        for path in bootstrap.MODEL_D_MAINTENANCE_PATHS:
            blobs = dict(bootstrap.G2_EXPECTED_CANDIDATE_BLOBS)
            blobs[path] = "0" * 40
            with self.subTest(blob=path), self.assertRaisesRegex(
                    bootstrap.BootstrapError, "terminal blob"):
                run(blobs=blobs)

    def test_b3_establishment_rejects_root_aliases(self) -> None:
        for p_root, e_root in (
                (self.protected, self.e), (self.p, self.protected),
                (self.p, self.p)):
            with self.subTest(p=p_root.name, e=e_root.name), \
                 mock.patch.object(bootstrap, "validate_b3_selected_authority"), \
                 self.assertRaisesRegex(bootstrap.BootstrapError, "roots must be separate"):
                bootstrap.validate_b3_establishment(
                    self.protected, "2" * 40, p_root, bootstrap.EXPECTED_P_SHA,
                    e_root, "3" * 40)

    def test_terminal_requires_exact_order_tree_and_protected_main(self) -> None:
        t, s2, p_sha, e_sha = "4" * 40, "2" * 40, bootstrap.EXPECTED_P_SHA, "3" * 40

        def identity(root: Path, *arguments: str) -> str:
            values = {
                ("rev-parse", "HEAD"): t,
                ("rev-parse", "refs/remotes/origin/main"): t,
                ("cat-file", "-t", t): "commit",
                ("rev-list", "--parents", "-n", "1", t): f"{t} {s2} {e_sha}",
                ("rev-list", "--parents", "-n", "1", e_sha): f"{e_sha} {s2} {p_sha}",
                ("rev-parse", f"{t}^{{tree}}"): bootstrap.G2_BOUND_CANDIDATE_TREE,
            }
            return values[arguments]

        terminal = (f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_BOUND_EXPECTED_TERMINAL}"\n').encode()
        completed = subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(bootstrap, "_git", side_effect=identity), \
             mock.patch.object(bootstrap, "_git_bytes", return_value=terminal), \
             mock.patch.object(bootstrap, "_require_b3_selected_history"), \
             mock.patch.object(bootstrap, "validate_protected_universe"), \
             mock.patch.object(bootstrap.subprocess, "run", return_value=completed):
            bootstrap.validate_b3_terminal(self.protected, t, s2, p_sha, e_sha)

    def test_t_complete_adversarial_matrix(self) -> None:
        t, s2, p_sha, e_sha = "4" * 40, "2" * 40, bootstrap.EXPECTED_P_SHA, "3" * 40

        def run(*, head: str | None = None, main: str | None = None,
                kind: str = "commit", parents: str | None = None,
                e_parents: str | None = None, tree: str | None = None,
                lifecycle: str = "CONSUMED", ancestry: int = 0) -> None:
            def identity(_root: Path, *arguments: str) -> str:
                values = {
                    ("rev-parse", "HEAD"): head or t,
                    ("rev-parse", "refs/remotes/origin/main"): main or t,
                    ("cat-file", "-t", t): kind,
                    ("rev-list", "--parents", "-n", "1", t):
                        parents or f"{t} {s2} {e_sha}",
                    ("rev-list", "--parents", "-n", "1", e_sha):
                        e_parents or f"{e_sha} {s2} {p_sha}",
                    ("rev-parse", f"{t}^{{tree}}"): tree or bootstrap.G2_BOUND_CANDIDATE_TREE,
                }
                return values[arguments]

            raw = (f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_MAINTENANCE_GENERATION}:{lifecycle}"\n').encode()
            completed = subprocess.CompletedProcess([], ancestry, b"", b"")
            with mock.patch.object(bootstrap, "_git", side_effect=identity), \
                 mock.patch.object(bootstrap, "_git_bytes", return_value=raw), \
                 mock.patch.object(bootstrap, "_require_b3_selected_history"), \
                 mock.patch.object(bootstrap, "validate_protected_universe"), \
                 mock.patch.object(bootstrap.subprocess, "run", return_value=completed):
                bootstrap.validate_b3_terminal(self.protected, t, s2, p_sha, e_sha)

        cases = (
            ("head", {"head": "0" * 40}, "protected main"),
            ("later-main", {"main": "0" * 40}, "protected main"),
            ("object", {"kind": "tree"}, "not a commit"),
            ("one-parent", {"parents": f"{t} {s2}"}, "ordered parents"),
            ("extra-parent", {"parents": f"{t} {s2} {e_sha} {'5' * 40}"}, "ordered parents"),
            ("reversed", {"parents": f"{t} {e_sha} {s2}"}, "ordered parents"),
            ("wrong-s2", {"parents": f"{t} {'5' * 40} {e_sha}"}, "ordered parents"),
            ("wrong-e", {"parents": f"{t} {s2} {'5' * 40}"}, "ordered parents"),
            ("malformed-e", {"e_parents": f"{e_sha} {s2}"}, "E and P ancestry"),
            ("wrong-p", {"e_parents": f"{e_sha} {s2} {'9' * 40}"}, "E and P ancestry"),
            ("tree", {"tree": "0" * 40}, "tree mismatch"),
            ("one-byte", {"tree": "f" * 40}, "tree mismatch"),
            ("wrong-blob", {"tree": "e" * 40}, "tree mismatch"),
            ("wrong-mode", {"tree": "d" * 40}, "tree mismatch"),
            ("wrong-g1", {"tree": "c" * 40}, "tree mismatch"),
            ("second-terminal", {"parents": f"{t} {'9' * 40} {e_sha}"}, "ordered parents"),
            ("ancestry", {"ancestry": 1}, "S1 ancestry"),
            ("active-bound", {"lifecycle": "ACTIVE_BOUND"}, "terminal CONSUMED"),
            ("active-unbound", {"lifecycle": "ACTIVE_UNBOUND"}, "terminal CONSUMED"),
        )
        for name, options, message in cases:
            with self.subTest(name=name), self.assertRaisesRegex(
                    bootstrap.BootstrapError, message):
                run(**options)

    def test_b3_terminal_state_cannot_be_reused_as_enablement(self) -> None:
        terminal = "4" * 40
        with mock.patch.object(
                bootstrap, "validate_b3_selected_authority",
                side_effect=bootstrap.BootstrapError(
                    "B3 P selector is not protected main")):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "protected main"):
                bootstrap.validate_b3_establishment(
                    self.protected, terminal, self.p, bootstrap.EXPECTED_P_SHA,
                    self.e, "3" * 40)

    def test_b3_cli_requires_all_explicit_roots_and_shas(self) -> None:
        parser = bootstrap._parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["admit-b3", "--protected-sha", "1" * 40])
        arguments = parser.parse_args([
            "admit-b3", "--protected-sha", "2" * 40,
            "--protected-root", "protected", "--p-sha", "1" * 40,
            "--p-root", "p", "--e-sha", "3" * 40, "--e-root", "e"])
        self.assertEqual(arguments.p_sha, "1" * 40)
        self.assertEqual(arguments.e_sha, "3" * 40)

    def test_b3_cli_rejects_each_missing_or_duplicated_identity(self) -> None:
        parser = bootstrap._parser()
        pairs = (
            ("--protected-sha", "2" * 40),
            ("--protected-root", "protected"),
            ("--p-sha", "1" * 40),
            ("--p-root", "p"),
            ("--e-sha", "3" * 40),
            ("--e-root", "e"),
        )
        complete = ["admit-b3"] + [item for pair in pairs for item in pair]
        for missing in range(len(pairs)):
            arguments = ["admit-b3"] + [item for index, pair in enumerate(pairs)
                                          if index != missing for item in pair]
            with self.subTest(missing=pairs[missing][0]), \
                 self.assertRaises(SystemExit):
                parser.parse_args(arguments)
        with self.assertRaises(SystemExit):
            parser.parse_args(complete + ["--p-sha", "9" * 40])

    def test_workflow_b3_inputs_bind_event_and_separate_authority(self) -> None:
        workflow = yaml.safe_load(
            (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text())
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        by_name = {step["name"]: step for step in steps}
        identity = by_name["Resolve exact B3 proposal identities"]["run"]
        admission = by_name["Enforce exact DESIGN-B terminal admission"]["run"]
        self.assertIn('${{ github.event.pull_request.head.sha }}', identity)
        self.assertIn('$fields[2]', identity)
        self.assertIn('--protected-root "${{ github.workspace }}/policy"', admission)
        self.assertIn('--p-root "${{ github.workspace }}/p-candidate"', admission)
        self.assertIn('--e-root "${{ github.workspace }}/e-candidate"', admission)
        self.assertIn('--protected-sha "${{ steps.protected-git.outputs.protected-sha }}"', admission)
        self.assertIn('--p-sha "${{ steps.b3-identities.outputs.p-sha }}"', admission)
        self.assertIn('--e-sha "${{ steps.b3-identities.outputs.e-sha }}"', admission)
        self.assertNotIn("--expected-tree", admission)
        self.assertNotIn("--expected-s1", admission)
        self.assertNotIn("--expected-s2", admission)

    def test_workflow_separates_protected_p_and_e(self) -> None:
        workflow = (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text()
        for token in ("p-candidate", "e-candidate", "b3-identities.outputs.p-sha",
                      "b3-identities.outputs.e-sha", "admit-b3"):
            self.assertIn(token, workflow)
        self.assertIn("$fields[2]", workflow)
        self.assertIn("policy/protected_policy_bootstrap.py\" admit-b3", workflow)
        self.assertNotIn("p-candidate/protected_policy_bootstrap.py\" admit-b3", workflow)
        self.assertNotIn("e-candidate/protected_policy_bootstrap.py\" admit-b3", workflow)


class G2SeedAdmissionTests(unittest.TestCase):
    """Exercise proposed G2 authority only after a synthetic protected seed merge."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(__file__).parent.resolve()
        self.protected = Path(temporary.name).resolve() / "protected"
        subprocess.run(["git", "clone", "--no-hardlinks", "--no-checkout", str(self.source),
                        str(self.protected)], check=True, capture_output=True)
        self._configure(self.protected)
        git(self.protected, "checkout", "-B", "main",
            "9b78dcb50df2e7ae89cfb32733e37f88659e12ab")
        self.base_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "checkout", "-b", "seed")
        for name in bootstrap.MODEL_D_MAINTENANCE_PATHS:
            destination = self.protected / name
            destination.write_bytes(bootstrap._git_bytes(
                self.source, "show",
                f"bb0e4279954ed7b0600d71091e69d369516e5d75:{name}"))
        git(self.protected, "add", *bootstrap.MODEL_D_MAINTENANCE_PATHS)
        git(self.protected, "commit", "-m", "Synthetic G2 seed proposal")
        self.seed_proposal = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "checkout", "-B", "main", self.base_sha)
        git(self.protected, "merge", "--no-ff", "seed", "-m", "Synthetic protected seed")
        self.seed_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", self.seed_sha)
        self.candidate = Path(temporary.name).resolve() / "candidate"
        subprocess.run(["git", "clone", "--no-hardlinks", "--no-checkout", str(self.protected),
                        str(self.candidate)], check=True, capture_output=True)
        self._configure(self.candidate)
        git(self.candidate, "checkout", "-b", "g2-use")

    @staticmethod
    def _configure(root: Path) -> None:
        head = git(root, "rev-parse", "HEAD")
        git(root, "config", "user.name", "G2 Seed Test")
        git(root, "config", "user.email", "g2@example.invalid")
        git(root, "config", "core.autocrlf", "false")
        git(root, "reset", "--hard", head)
        git(root, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")

    def _proposal(self, paths: tuple[str, ...]) -> str:
        active = f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_MAINTENANCE_GENERATION}:ACTIVE_UNBOUND"'.encode()
        consumed = f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_MAINTENANCE_GENERATION}:CONSUMED"'.encode()
        for name in paths:
            path = self.candidate / name
            original = path.read_bytes()
            path.write_bytes(original.replace(active, consumed) if name ==
                             "protected_policy_bootstrap.py" else original + b"\n# synthetic-g2-test\n")
        git(self.candidate, "add", "-A")
        git(self.candidate, "commit", "-m", "Synthetic G2 proposal")
        return git(self.candidate, "rev-parse", "HEAD")

    def _admit(self, candidate_sha: str | None = None,
               protected_sha: str | None = None,
               generation: str | None = None) -> None:
        bootstrap.validate_g2_maintenance(
            generation or bootstrap.G2_MAINTENANCE_GENERATION,
            self.candidate, self.protected,
            candidate_sha or git(self.candidate, "rev-parse", "HEAD"),
            protected_sha or git(self.protected, "rev-parse", "HEAD"))

    def test_seed_proposal_does_not_admit_itself(self) -> None:
        git(self.protected, "checkout", "-B", "main", self.base_sha)
        git(self.protected, "update-ref", "refs/remotes/origin/main", self.base_sha)
        git(self.candidate, "fetch", str(self.protected), self.seed_proposal)
        git(self.candidate, "checkout", "--detach", "FETCH_HEAD")
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()
        self.assertEqual(bootstrap.MODEL_D_MAINTENANCE_LIFECYCLE,
                         bootstrap.MODEL_D_MAINTENANCE_GENERATION + ":CONSUMED")

    def test_unbound_rejects_exact_scope_and_fail_closed_inputs(self) -> None:
        self._proposal(bootstrap.MODEL_D_MAINTENANCE_PATHS)
        with self.assertRaisesRegex(bootstrap.BootstrapError, "no independently bound"):
            self._admit()
        command = [
            os.sys.executable, "-I", "-S", str(Path(bootstrap.__file__).resolve()),
            "admit-maintenance", "--maintenance-operation",
            bootstrap.MODEL_D_MAINTENANCE_OPERATION,
            "--maintenance-generation", bootstrap.G2_MAINTENANCE_GENERATION,
            "--candidate-sha", git(self.candidate, "rev-parse", "HEAD"),
            "--protected-sha", self.seed_sha,
            "--candidate-root", str(self.candidate),
            "--protected-root", str(self.protected),
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no independently bound", result.stderr)
        with self.assertRaises(bootstrap.BootstrapError):
            bootstrap.validate_model_d_maintenance(
                bootstrap.MODEL_D_MAINTENANCE_OPERATION,
                bootstrap.MODEL_D_MAINTENANCE_GENERATION,
                self.candidate, self.protected,
                git(self.candidate, "rev-parse", "HEAD"), self.seed_sha)
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit(generation="MODEL_D_ORCHESTRATION_V1_GENERATION_3")
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit(protected_sha=self.base_sha)
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()
        git(self.candidate, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-policy.git")
        git(self.protected, "remote", "set-url", "origin",
            "https://github.com/KiloAlpha021/security-workflows.git")
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()

    def test_lifecycle_only_revocation_and_replay_reject(self) -> None:
        self._proposal(("protected_policy_bootstrap.py",))
        self._admit()
        git(self.protected, "fetch", str(self.candidate), "HEAD")
        git(self.protected, "merge", "--no-ff", "FETCH_HEAD", "-m", "Consume G2")
        git(self.protected, "update-ref", "refs/remotes/origin/main",
            git(self.protected, "rev-parse", "HEAD"))
        self.assertTrue(bootstrap._g2_generation_was_consumed(
            self.protected, git(self.protected, "rev-parse", "HEAD")))
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()

    def test_consumed_history_rejects_removed_and_reintroduced_g2(self) -> None:
        self._proposal(("protected_policy_bootstrap.py",))
        self._admit()
        git(self.protected, "fetch", str(self.candidate), "HEAD")
        git(self.protected, "merge", "--no-ff", "FETCH_HEAD", "-m", "Consume G2")
        source = self.protected / "protected_policy_bootstrap.py"
        consumed_source = source.read_bytes()
        declarations = (
            f'G2_MAINTENANCE_GENERATION = "{bootstrap.G2_MAINTENANCE_GENERATION}"',
            f'G2_MAINTENANCE_LIFECYCLE = "{bootstrap.G2_MAINTENANCE_GENERATION}:CONSUMED"',
            f'G2_MAINTENANCE_PURPOSE = "{bootstrap.G2_MAINTENANCE_PURPOSE}"',
        )
        removed_source = consumed_source
        for declaration in declarations:
            line = (declaration + "\n").encode()
            self.assertEqual(removed_source.count(line), 1)
            removed_source = removed_source.replace(line, b"")
        source.write_bytes(removed_source)
        git(self.protected, "add", "protected_policy_bootstrap.py")
        git(self.protected, "commit", "-m", "Remove G2 declarations")
        removed_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "checkout", "-b", "reintroduce")
        active = (f'G2_MAINTENANCE_LIFECYCLE = "'
                  f'{bootstrap.G2_MAINTENANCE_GENERATION}:ACTIVE_UNBOUND"').encode()
        consumed = (f'G2_MAINTENANCE_LIFECYCLE = "'
                    f'{bootstrap.G2_MAINTENANCE_GENERATION}:CONSUMED"').encode()
        source.write_bytes(consumed_source.replace(consumed, active))
        git(self.protected, "add", "protected_policy_bootstrap.py")
        git(self.protected, "commit", "-m", "Reintroduce G2")
        git(self.protected, "checkout", "main")
        self.assertEqual(git(self.protected, "rev-parse", "HEAD"), removed_sha)
        git(self.protected, "merge", "--no-ff", "reintroduce", "-m", "Reintroduce G2 merge")
        reintroduced_sha = git(self.protected, "rev-parse", "HEAD")
        git(self.protected, "update-ref", "refs/remotes/origin/main", reintroduced_sha)
        self.assertTrue(bootstrap._g2_generation_was_consumed(
            self.protected, reintroduced_sha))
        git(self.candidate, "fetch", str(self.protected), "main")
        git(self.candidate, "checkout", "-B", "g2-replay", "FETCH_HEAD")
        self._proposal(("protected_policy_bootstrap.py",))
        with self.assertRaisesRegex(bootstrap.BootstrapError, "permanently consumed"):
            self._admit()

    def test_fourth_path_and_protected_drift_reject(self) -> None:
        self._proposal(bootstrap.MODEL_D_MAINTENANCE_PATHS)
        extra = self.candidate / "verify_security_workflows.py"
        extra.write_bytes(extra.read_bytes() + b"\n# unauthorized\n")
        git(self.candidate, "add", "verify_security_workflows.py")
        git(self.candidate, "commit", "--amend", "--no-edit")
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()
        git(self.protected, "commit", "--allow-empty", "-m", "Protected drift")
        git(self.protected, "update-ref", "refs/remotes/origin/main",
            git(self.protected, "rev-parse", "HEAD"))
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()

    def test_candidate_cannot_widen_g2_purpose(self) -> None:
        self._proposal(bootstrap.MODEL_D_MAINTENANCE_PATHS)
        source = self.candidate / "protected_policy_bootstrap.py"
        source.write_bytes(source.read_bytes().replace(
            bootstrap.G2_MAINTENANCE_PURPOSE.encode(),
            b"general policy maintenance"))
        git(self.candidate, "add", "protected_policy_bootstrap.py")
        git(self.candidate, "commit", "--amend", "--no-edit")
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()

    def test_candidate_claimed_approval_cannot_bind_unbound_g2(self) -> None:
        self._proposal(bootstrap.MODEL_D_MAINTENANCE_PATHS)
        source = self.candidate / "protected_policy_bootstrap.py"
        source.write_bytes(source.read_bytes() +
                           b'\nG2_APPROVED_CANDIDATE_SHA = "0000000000000000000000000000000000000000"\n')
        git(self.candidate, "add", "protected_policy_bootstrap.py")
        git(self.candidate, "commit", "--amend", "--no-edit")
        with self.assertRaisesRegex(bootstrap.BootstrapError, "no independently bound"):
            self._admit()

    def test_candidate_cannot_relabel_consumed_g1(self) -> None:
        self._proposal(bootstrap.MODEL_D_MAINTENANCE_PATHS)
        source = self.candidate / "protected_policy_bootstrap.py"
        source.write_bytes(source.read_bytes().replace(
            b'MODEL_D_MAINTENANCE_GENERATION = "MODEL_D_ORCHESTRATION_V1_GENERATION_1"',
            b'MODEL_D_MAINTENANCE_GENERATION = "MODEL_D_ORCHESTRATION_V1_GENERATION_3"'))
        git(self.candidate, "add", "protected_policy_bootstrap.py")
        git(self.candidate, "commit", "--amend", "--no-edit")
        with self.assertRaises(bootstrap.BootstrapError):
            self._admit()


class S2CCorrectionTests(unittest.TestCase):
    """Exercise the deliberate attribution format and one finite S2 repair."""

    S2 = "580e923a5adb83bda915af32ffacb9c55512a26f"
    GOOD = b"Jos\xc3\xa9\0jose@example.invalid\0Committer\0c@example.invalid\n"

    def test_actual_workflow_b3_detector_routes_lf_and_crlf_exclusively(self) -> None:
        source = Path(__file__).parent.resolve()
        workflow = yaml.safe_load(
            (source / ".github/workflows/security-workflows-policy.yml").read_text())
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        by_name = {step["name"]: step for step in steps}
        detector = by_name["Acquire protected Git identity"]
        self.assertEqual(detector["id"], "protected-git")
        self.assertEqual(
            by_name["Resolve exact B3 proposal identities"]["if"],
            "steps.protected-git.outputs.b3-enabled == 'true' && github.event_name == 'pull_request'")
        self.assertEqual(
            by_name["Enforce exact DESIGN-B terminal admission"]["if"],
            "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP' && steps.protected-git.outputs.b3-enabled == 'true'")
        self.assertEqual(
            by_name["Enforce exact Model D maintenance admission"]["if"],
            "steps.protected-bootstrap.outputs.evaluation-context == 'SELF_PR_BOOTSTRAP' && steps.protected-git.outputs.b3-enabled != 'true'")
        exact_s2 = bootstrap._git_bytes(source, "show", f"{self.S2}:protected_policy_bootstrap.py")
        exact_s1 = bootstrap._git_bytes(
            source, "show", f"{bootstrap.B3_AUTHORITY_ORIGIN}:protected_policy_bootstrap.py")
        marker = b'B3_ENABLEMENT = "DESIGN_B_FINITE_V1"'
        self.assertEqual(exact_s2.count(marker), 1)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            policy = workspace / "policy"
            subprocess.run(["git", "clone", "--quiet", str(source), str(policy)],
                           check=True, capture_output=True)
            git(policy, "checkout", "--detach", self.S2)
            git(policy, "config", "core.autocrlf", "false")
            script = detector["run"].replace(
                "${{ github.workspace }}", workspace.as_posix())
            output = workspace / "GITHUB_OUTPUT"

            def execute(data: bytes, *, wrong_root: bool = False) -> tuple[int, str, str]:
                (policy / "protected_policy_bootstrap.py").write_bytes(data)
                output.unlink(missing_ok=True)
                command = script
                if wrong_root:
                    command = command.replace(
                        (workspace / "policy").as_posix(),
                        (workspace / "missing-policy").as_posix())
                completed = subprocess.run(
                    ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
                    env={**os.environ, "GITHUB_OUTPUT": str(output)},
                    capture_output=True, text=True)
                return (completed.returncode,
                        output.read_text(encoding="utf-8") if output.exists() else "",
                        completed.stderr + completed.stdout)

            cases = (
                ("exact-lf", exact_s2, "true"),
                ("exact-crlf", exact_s2.replace(b"\n", b"\r\n"), "true"),
                ("missing-marker", exact_s1, "false"),
                ("altered-marker", exact_s2.replace(marker, b'B3_ENABLEMENT = "OTHER"'), "false"),
            )
            for name, data, expected in cases:
                with self.subTest(name=name):
                    code, recorded, diagnostic = execute(data)
                    self.assertEqual(code, 0, diagnostic)
                    self.assertEqual(
                        recorded.splitlines(),
                        [f"protected-sha={self.S2}", f"b3-enabled={expected}"])
                    b3_route = expected == "true"
                    legacy_route = expected != "true"
                    self.assertNotEqual(b3_route, legacy_route)
                    self.assertEqual(b3_route, name.startswith("exact-"))
            for name, data in (
                ("duplicate-exact", exact_s2 + marker + b"\n"),
                ("duplicate-ambiguous", exact_s2 + b"B3_ENABLEMENT=OTHER\n"),
            ):
                with self.subTest(name=name):
                    code, recorded, diagnostic = execute(data)
                    self.assertNotEqual(code, 0)
                    self.assertIn("Ambiguous B3 enablement declaration", diagnostic)
                    self.assertNotIn("b3-enabled=", recorded)
            code, recorded, _ = execute(exact_s2, wrong_root=True)
            self.assertNotEqual(code, 0)
            self.assertNotIn("b3-enabled=", recorded)
            (workspace / "candidate").mkdir()
            (workspace / "candidate" / "protected_policy_bootstrap.py").write_bytes(exact_s2)
            code, recorded, diagnostic = execute(exact_s1)
            self.assertEqual(code, 0, diagnostic)
            self.assertIn("b3-enabled=false", recorded)

    def test_attribution_parser_accepts_exact_record_and_rejects_controls(self) -> None:
        root = Path(__file__).parent
        with mock.patch.object(bootstrap, "_git_bytes", return_value=self.GOOD):
            self.assertEqual(bootstrap._git_attribution(root, "a" * 40, "B3 P"),
                             ("Jos\u00e9", "jose@example.invalid",
                              "Committer", "c@example.invalid"))
        bad = {
            "short": b"a\0b\0c\n",
            "extra": b"a\0b\0c\0d\0e\n",
            "empty-author": b"\0b\0c\0d\n",
            "empty-author-email": b"a\0\0c\0d\n",
            "empty-committer": b"a\0b\0\0d\n",
            "empty-committer-email": b"a\0b\0c\0\n",
            "leading-delimiter": b"\0a\0b\0c\n",
            "trailing-delimiter": b"a\0b\0c\0\n",
            "no-newline": b"a\0b\0c\0d",
            "extra-newline": b"a\0b\0c\0d\n\n",
            "cr": b"a\rb\0c\0d\0e\n",
            "lf": b"a\nb\0c\0d\0e\n",
            "tab": b"a\tb\0c\0d\0e\n",
            "unicode-control": "a\u202eb\0c\0d\0e\n".encode(),
            "invalid-utf8": b"\xff\0b\0c\0d\n",
        }
        for name, output in bad.items():
            with self.subTest(name=name), \
                 mock.patch.object(bootstrap, "_git_bytes", return_value=output), \
                 self.assertRaisesRegex(bootstrap.BootstrapError, "attribution is malformed"):
                bootstrap._git_attribution(root, "a" * 40, "B3 P")

    def test_generic_git_identity_still_rejects_nul(self) -> None:
        with mock.patch.object(bootstrap.subprocess, "run", return_value=
                               subprocess.CompletedProcess([], 0, "a\0b", "")):
            with self.assertRaisesRegex(bootstrap.BootstrapError, "Malformed Git identity"):
                bootstrap._git(Path(__file__).parent, "rev-parse", "HEAD")

    def test_native_s2c_is_exactly_one_s2_anchored_layer(self) -> None:
        source = Path(__file__).parent.resolve()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "policy"
            subprocess.run(["git", "clone", "--quiet", str(source), str(repo)],
                           check=True, capture_output=True)
            git(repo, "checkout", "--detach", self.S2)
            git(repo, "remote", "set-url", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")
            git(repo, "config", "core.autocrlf", "false")
            git(repo, "config", "user.name", "S2C Test")
            git(repo, "config", "user.email", "s2c@example.invalid")
            for name in bootstrap.B3_CORRECTION_PATHS:
                (repo / name).write_bytes(subprocess.run(
                    ["git", "-C", str(source), "show", f"{bootstrap.B3_P_SELECTION_BASE}:{name}"],
                    check=True, capture_output=True).stdout)
            git(repo, "add", "--", *bootstrap.B3_CORRECTION_PATHS)
            git(repo, "commit", "-m", "C")
            proposal = git(repo, "rev-parse", "HEAD")
            tree = git(repo, "rev-parse", "HEAD^{tree}")

            def make(message: str, tree_sha: str, *parents: str) -> str:
                command = ["git", "-C", str(repo), "commit-tree", tree_sha]
                for parent in parents:
                    command.extend(("-p", parent))
                return subprocess.run(command, input=message + "\n", text=True,
                                      check=True, capture_output=True).stdout.strip()

            corrected = make("S2C", tree, self.S2, proposal)
            git(repo, "checkout", "--detach", corrected)
            git(repo, "update-ref", "refs/remotes/origin/main", corrected)
            bootstrap.validate_b3_corrected_authority(repo, corrected)
            with mock.patch.object(bootstrap, "_exact_modified_paths",
                                   return_value=("protected_policy_bootstrap.py",)):
                with self.assertRaisesRegex(bootstrap.BootstrapError, "three-file scope"):
                    bootstrap.validate_b3_corrected_authority(repo, corrected)
            original = bootstrap._git_bytes
            def mutated_source(root: Path, *arguments: str) -> bytes:
                value = original(root, *arguments)
                if arguments == ("show", f"{corrected}:protected_policy_bootstrap.py"):
                    return value.replace(
                        b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE_BOUND',
                        b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:CONSUMED')
                return value
            with mock.patch.object(bootstrap, "_git_bytes", side_effect=mutated_source):
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_b3_corrected_authority(repo, corrected)
            original_source = original(
                repo, "show", f"{corrected}:protected_policy_bootstrap.py")
            authority_mutations = {
                "binding": original_source.replace(
                    bootstrap.G2_BOUND_CANDIDATE_TREE.encode(), b"0" * 40),
                "g1-revival": original_source.replace(
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED',
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:ACTIVE_BOUND'),
                "g2-unbound": original_source.replace(
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE_BOUND',
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE_UNBOUND'),
                "future-p": original_source + b'\nFUTURE_P_SHA = "' + b"f" * 40 + b'"\n',
                "alternate-p": original_source + b'\nAUTHORIZED_PROVENANCE = "' + b"f" * 40 + b'"\n',
                "generation": original_source.replace(
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_2"',
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_3"'),
                "marker": original_source.replace(
                    b'B3_CORRECTION = "PPR_FWD_01_V1"', b''),
            }
            for name, source_mutation in authority_mutations.items():
                def changed_source(root: Path, *arguments: str) -> bytes:
                    if arguments == ("show", f"{corrected}:protected_policy_bootstrap.py"):
                        return source_mutation
                    return original(root, *arguments)
                with self.subTest(authority=name), \
                     mock.patch.object(bootstrap, "_git_bytes",
                                       side_effect=changed_source), \
                     self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_b3_corrected_authority(repo, corrected)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "protected main"):
                git(repo, "update-ref", "refs/remotes/origin/main", self.S2)
                bootstrap.validate_b3_corrected_authority(repo, corrected)
            git(repo, "update-ref", "refs/remotes/origin/main", corrected)
            wrong_first = make("wrong first", tree, bootstrap.B3_AUTHORITY_ORIGIN,
                               proposal)
            git(repo, "checkout", "--detach", wrong_first)
            git(repo, "update-ref", "refs/remotes/origin/main", wrong_first)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exact S2 first parent"):
                bootstrap.validate_b3_corrected_authority(repo, wrong_first)
            git(repo, "checkout", "--detach", corrected)
            git(repo, "update-ref", "refs/remotes/origin/main", corrected)
            wrong_child = make("not an S2 child", tree, bootstrap.B3_AUTHORITY_ORIGIN)
            wrong_proposal = make("wrong proposal", tree, self.S2, wrong_child)
            git(repo, "checkout", "--detach", wrong_proposal)
            git(repo, "update-ref", "refs/remotes/origin/main", wrong_proposal)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "direct S2 child"):
                bootstrap.validate_b3_corrected_authority(repo, wrong_proposal)
            git(repo, "checkout", "--detach", corrected)
            git(repo, "update-ref", "refs/remotes/origin/main", corrected)
            with mock.patch.object(bootstrap, "_git", wraps=bootstrap._git) as identity:
                def wrong_tree(root: Path, *arguments: str) -> str:
                    if arguments == ("rev-parse", f"{proposal}^{{tree}}"):
                        return "0" * 40
                    return identity.original(root, *arguments)
                identity.original = identity._mock_wraps
                identity.side_effect = wrong_tree
                with self.assertRaisesRegex(bootstrap.BootstrapError,
                                            "merge tree differs"):
                    bootstrap.validate_b3_corrected_authority(repo, corrected)
            replay = make("C2", tree, corrected)
            second = make("S2C2", tree, corrected, replay)
            git(repo, "checkout", "--detach", second)
            git(repo, "update-ref", "refs/remotes/origin/main", second)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exact S2 first parent"):
                bootstrap.validate_b3_corrected_authority(repo, second)
            arbitrary = make("arbitrary ACTIVE_BOUND", tree, corrected)
            git(repo, "checkout", "--detach", arbitrary)
            git(repo, "update-ref", "refs/remotes/origin/main", arbitrary)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exact S2 first parent"):
                bootstrap.validate_b3_corrected_authority(repo, arbitrary)


class S2PSelectionTests(unittest.TestCase):
    """The protected selector is one S2C successor, never E-supplied data."""

    S2C = "c7041b6802c9196c491d63977cdc6f81a3566b01"

    def test_native_one_use_and_closed_selection_schema(self) -> None:
        source = Path(__file__).parent.resolve()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "policy"
            subprocess.run(["git", "clone", "--quiet", str(source), str(repo)],
                           check=True, capture_output=True)
            git(repo, "config", "core.autocrlf", "false")
            git(repo, "checkout", "--detach", self.S2C)
            git(repo, "remote", "set-url", "origin",
                "https://github.com/KiloAlpha021/security-policy.git")
            git(repo, "config", "user.name", "S2P Test")
            git(repo, "config", "user.email", "s2p@example.invalid")
            for name in bootstrap.B3_P_SELECTION_PATHS:
                target = repo / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((source / name).read_bytes())
            git(repo, "add", "--", *bootstrap.B3_P_SELECTION_PATHS)
            git(repo, "commit", "-m", "SIMULATION_ONLY selector proposal")
            proposal = git(repo, "rev-parse", "HEAD")
            tree = git(repo, "rev-parse", "HEAD^{tree}")

            def make(label: str, tree_sha: str, *parents: str) -> str:
                command = ["git", "-C", str(repo), "commit-tree", tree_sha]
                for parent in parents:
                    command.extend(("-p", parent))
                return subprocess.run(command, input=label + "\n", text=True,
                                      check=True, capture_output=True).stdout.strip()

            selected = make("SIMULATION_ONLY S2P", tree, self.S2C, proposal)

            def protected_at(revision: str) -> None:
                git(repo, "checkout", "--detach", revision)
                git(repo, "update-ref", "refs/remotes/origin/main", revision)

            protected_at(selected)
            bootstrap.validate_b3_selected_authority(repo, selected)
            self.assertEqual(bootstrap.EXPECTED_P_SHA,
                             "f8f41127efe2c27cc7ba8f3132754b5c363636a1")
            with mock.patch.object(bootstrap, "_exact_modified_paths",
                                   return_value=("protected_policy_bootstrap.py",)), \
                 self.assertRaisesRegex(bootstrap.BootstrapError, "three-file scope"):
                bootstrap.validate_b3_selected_authority(repo, selected)
            with mock.patch.object(bootstrap, "_tree_entries",
                                   return_value={name: ("100755", "blob")
                                                 for name in bootstrap.B3_P_SELECTION_PATHS}), \
                 self.assertRaisesRegex(bootstrap.BootstrapError, "100644"):
                bootstrap.validate_b3_selected_authority(repo, selected)
            original = bootstrap._git_bytes
            actual = original(repo, "show", f"{selected}:protected_policy_bootstrap.py")
            mutations = {
                "missing": actual.replace(
                    b'EXPECTED_P_SHA = "f8f41127efe2c27cc7ba8f3132754b5c363636a1"\n', b""),
                "wrong": actual.replace(bootstrap.EXPECTED_P_SHA.encode(), b"9" * 40),
                "duplicate": actual + b'\nEXPECTED_P_SHA = "' +
                    bootstrap.EXPECTED_P_SHA.encode() + b'"\n',
                "alternate-name": actual + b'\nALTERNATE_P_SHA = "' + b"9" * 40 + b'"\n',
                "g1-revival": actual.replace(
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:CONSUMED',
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_1:ACTIVE_BOUND'),
                "g2-consumed": actual.replace(
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE_BOUND',
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:CONSUMED'),
                "g2-unbound": actual.replace(
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE_BOUND',
                    b'MODEL_D_ORCHESTRATION_V1_GENERATION_2:ACTIVE_UNBOUND'),
                "binding": actual.replace(
                    bootstrap.G2_BOUND_CANDIDATE_TREE.encode(), b"0" * 40),
            }
            for label, changed in mutations.items():
                def altered(root: Path, *args: str) -> bytes:
                    if args == ("show", f"{selected}:protected_policy_bootstrap.py"):
                        return changed
                    return original(root, *args)
                with self.subTest(label=label), \
                     mock.patch.object(bootstrap, "_git_bytes", side_effect=altered), \
                     self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_b3_selected_authority(repo, selected)
            wrong_first = make("wrong first", tree, bootstrap.B3_CORRECTION_BASE,
                               proposal)
            protected_at(wrong_first)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exact S2C first parent"):
                bootstrap.validate_b3_selected_authority(repo, wrong_first)
            wrong_proposal = make("wrong proposal", tree, self.S2C,
                                  bootstrap.B3_CORRECTION_BASE)
            protected_at(wrong_proposal)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "direct S2C child"):
                bootstrap.validate_b3_selected_authority(repo, wrong_proposal)
            second_child = make("replay", tree, selected)
            second = make("second S2P", tree, selected, second_child)
            protected_at(second)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exact S2C first parent"):
                bootstrap.validate_b3_selected_authority(repo, second)
            arbitrary = make("arbitrary ACTIVE_BOUND", tree, selected)
            protected_at(arbitrary)
            with self.assertRaisesRegex(bootstrap.BootstrapError, "exact S2C first parent"):
                bootstrap.validate_b3_selected_authority(repo, arbitrary)

    def test_supplied_p_cannot_override_protected_expected_p(self) -> None:
        alternate = "9" * 40
        with mock.patch.object(bootstrap, "validate_b3_selected_authority"), \
             mock.patch.object(bootstrap, "_validate_b1_candidate") as validate_p, \
             self.assertRaisesRegex(bootstrap.BootstrapError,
                                    "differs from protected expected P"):
            bootstrap.validate_b3_establishment(
                Path(__file__).parent.resolve(), self.S2C,
                Path(__file__).parent.resolve(), alternate,
                Path(__file__).parent.resolve(), "3" * 40)
        validate_p.assert_not_called()
        with self.assertRaisesRegex(bootstrap.BootstrapError,
                                    "differs from protected expected P"):
            bootstrap.validate_b3_terminal(
                Path(__file__).parent.resolve(), "4" * 40,
                self.S2C, alternate, "3" * 40)

    def test_workflow_selects_p_from_protected_code(self) -> None:
        workflow = yaml.safe_load(
            (Path(__file__).parent / ".github/workflows/security-workflows-policy.yml").read_text())
        steps = {step["name"]: step for step in
                 workflow["jobs"]["security-workflows-policy"]["steps"]}
        identity = steps["Resolve exact B3 proposal identities"]["run"]
        self.assertIn('policy/protected_policy_bootstrap.py" select-b3-p', identity)
        self.assertIn("$proposedP = $fields[2]", identity)
        self.assertIn("$proposedP -ne $pSha", identity)
        self.assertNotIn("$pSha = $fields[2]", identity)
        self.assertIn("steps.b3-identities.outputs.p-sha",
                      str(steps["Check out exact selected B1 provenance P"]))
        parser = bootstrap._parser()
        self.assertEqual(parser.parse_args([
            "select-b3-p", "--protected-sha", self.S2C,
            "--protected-root", "policy"]).operation, "select-b3-p")


if __name__ == "__main__":
    unittest.main()
