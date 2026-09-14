from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from verify_security_workflows import action_references, verify


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

    def test_policy_dependency_workflow_contract(self) -> None:
        root = Path(__file__).parent
        original = (root / ".github/workflows/security-workflows-policy.yml").read_text()

        def assert_contract(workflow_text: str) -> None:
            workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)
            self.assertIsInstance(workflow, dict)
            jobs = workflow["jobs"]
            self.assertIsInstance(jobs, dict)
            steps = jobs["security-workflows-policy"]["steps"]
            names = [step.get("name") for step in steps]
            expected_order = [
                "Check out exact candidate",
                "Check out independent root policy",
                "Resolve and verify evaluation context",
                "Normalize and verify committed policy bytes",
                "Set up CPython",
                "Assert exact CPython runtime",
                "Install isolated hash-locked policy environment",
                "Test independent root policy",
                "Install isolated hash-locked audit environment",
                "Audit independent root policy dependencies",
                "Apply independent security-workflows policy",
            ]
            self.assertEqual(names, expected_order)
            candidate_checkout, policy_checkout, context = steps[:3]
            self.assertEqual(candidate_checkout["with"]["repository"], "${{ github.repository }}")
            self.assertEqual(candidate_checkout["with"]["ref"], "${{ github.sha }}")
            self.assertEqual(candidate_checkout["with"]["path"], "candidate")
            self.assertEqual(policy_checkout["with"]["repository"],
                             "KiloAlpha021/security-policy")
            self.assertEqual(policy_checkout["with"]["ref"], "main")
            self.assertEqual(policy_checkout["with"]["path"], "policy")
            dispatch = context["run"]
            for fragment in (
                "$env:EVENT_NAME -eq 'pull_request'",
                "$env:EVENT_REPOSITORY -eq $selfRepository",
                "$env:BASE_REPOSITORY -eq $selfRepository",
                "$env:BASE_BRANCH -eq 'main'",
                "$evaluationContext = 'SELF_PR_BOOTSTRAP'",
                "$policySource = 'candidate'",
                "$env:EVENT_NAME -in @('pull_request', 'merge_group')",
                "$env:EVENT_REPOSITORY -eq $downstreamRepository",
                "$env:BASE_REPOSITORY -eq $downstreamRepository",
                "$evaluationContext = 'DOWNSTREAM_SECURITY_WORKFLOWS'",
                "$policySource = 'policy'",
                "throw 'Unsupported or ambiguous policy evaluation context'",
                "^[0-9a-f]{40}$",
                "Candidate and protected-policy roots must be separate",
                "Candidate checkout repository mismatch",
                "Protected-policy checkout repository mismatch",
                "Candidate checkout does not match event SHA",
                "Protected-policy checkout is not protected main",
                "git -C candidate diff --name-only $policyHead $candidateHead",
                "Security-policy self-PR exceeds the bounded five-file scope",
                '"EVALUATION_CONTEXT=$evaluationContext" >> $env:GITHUB_ENV',
                '"POLICY_SOURCE=$policySource" >> $env:GITHUB_ENV',
            ):
                self.assertIn(fragment, dispatch)
            self.assertEqual(dispatch.count("$env:BASE_BRANCH -eq 'main'"), 2)
            allowed_match = re.search(r"(?s)\$allowed\s*=\s*@\((.*?)\n\s*\)", dispatch)
            self.assertIsNotNone(allowed_match)
            assert allowed_match is not None
            self.assertEqual(
                re.findall(r"'([^']+)'", allowed_match.group(1)),
                [
                    ".github/workflows/security-workflows-policy.yml",
                    "requirements-audit.lock",
                    "requirements-policy.lock",
                    "test_verify_security_workflows.py",
                    "verify_security_workflows.py",
                ],
            )

            normalization = steps[3]["run"]
            for fragment in (
                "foreach ($root in @('candidate', 'policy'))",
                "git -C $root config core.autocrlf false",
                "git -C $root reset --hard HEAD",
                "foreach ($lock in @('requirements-policy.lock', 'requirements-audit.lock'))",
                'git -C $env:POLICY_SOURCE rev-parse "HEAD`:$lock"',
                "git -C $env:POLICY_SOURCE hash-object --no-filters $lock",
                "Policy lock bytes differ from committed Git bytes: $lock",
            ):
                self.assertIn(fragment, normalization)
            normalization_lines = [line.strip() for line in normalization.splitlines()
                                   if line.strip()]
            normalization_positions = {
                fragment: next(index for index, line in enumerate(normalization_lines)
                               if fragment in line)
                for fragment in (
                    "config core.autocrlf false",
                    "reset --hard HEAD",
                    'rev-parse "HEAD`:$lock"',
                    "hash-object --no-filters $lock",
                )
            }
            self.assertLess(normalization_positions["config core.autocrlf false"],
                            normalization_positions["reset --hard HEAD"])
            self.assertLess(normalization_positions["reset --hard HEAD"],
                            normalization_positions['rev-parse "HEAD`:$lock"'])
            self.assertLess(normalization_positions['rev-parse "HEAD`:$lock"'],
                            normalization_positions["hash-object --no-filters $lock"])
            for command in ("config core.autocrlf false", "reset --hard HEAD",
                            'rev-parse "HEAD`:$lock"', "hash-object --no-filters $lock"):
                command_index = next(index for index, line in enumerate(normalization_lines)
                                     if command in line)
                self.assertEqual(normalization_lines[command_index + 1],
                                 "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")

            setup = steps[4]
            self.assertEqual(setup["with"]["python-version"], "3.12.10")
            python_assertion = steps[5]["run"]
            self.assertIn("platform.python_version()", python_assertion)

            def assert_fatal_version_gate(run: str, variable: str, expected: str) -> None:
                mismatch = re.search(
                    rf"(?m)^\s*if\s*\(\${variable}\s+-ne\s+'{re.escape(expected)}'\)\s*"
                    r"\{\s*(?:throw\b|exit\s+[1-9][0-9]*\b)", run
                )
                self.assertIsNotNone(mismatch)

            assert_fatal_version_gate(python_assertion, "pythonVersion", "3.12.10")
            policy_install = steps[6]["run"]
            for fragment in (
                '$env:POLICY_SOURCE/requirements-policy.lock', "--require-hashes",
                "--only-binary=:all:", "$yamlVersion", "print(yaml.__version__)",
                "policy-env\\Scripts\\python.exe -m pip check",
            ):
                self.assertIn(fragment, policy_install)
            assert_fatal_version_gate(policy_install, "yamlVersion", "6.0.3")
            policy_test = steps[7]["run"]
            self.assertIn("-m unittest discover -s $env:POLICY_SOURCE", policy_test)
            self.assertIn("test_verify_security_workflows.py", policy_test)
            audit_install = steps[8]["run"]
            for fragment in (
                "python -m venv audit-env", '$env:POLICY_SOURCE/requirements-audit.lock',
                "--require-hashes", "--only-binary=:all:", "$auditVersion",
                "-m pip_audit --version", "audit-env\\Scripts\\python.exe -m pip check",
            ):
                self.assertIn(fragment, audit_install)
            assert_fatal_version_gate(audit_install, "auditVersion", "pip-audit 2.10.1")
            audit = steps[9]["run"]
            self.assertIn(
                '-m pip_audit --no-deps -r "$env:POLICY_SOURCE/requirements-policy.lock"',
                audit,
            )
            validator_step = steps[10]
            self.assertEqual(validator_step["if"],
                             "env.EVALUATION_CONTEXT == 'DOWNSTREAM_SECURITY_WORKFLOWS'")
            validator = validator_step["run"]
            self.assertIn("policy-env\\Scripts\\python.exe policy/verify_security_workflows.py",
                          validator)
            self.assertNotIn("candidate/verify_security_workflows.py --candidate", validator)
            self.assertNotIn("continue-on-error", workflow_text)

            for run, command in (
                (policy_install, "-m pip install"),
                (policy_test, "-m unittest"),
                (audit_install, "-m pip install"),
                (audit, "-m pip_audit"),
                (validator, "verify_security_workflows.py"),
            ):
                lines = [line.strip() for line in run.splitlines() if line.strip()]
                command_index = next(index for index, line in enumerate(lines)
                                     if command in line)
                self.assertEqual(lines[command_index + 1],
                                 "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")

        assert_contract(original)
        mutations = {
            "self_event_weakened": ("$env:EVENT_NAME -eq 'pull_request'", "$true"),
            "self_repository_weakened": ("$env:EVENT_REPOSITORY -eq $selfRepository", "$true"),
            "self_base_weakened": ("$env:BASE_REPOSITORY -eq $selfRepository", "$true"),
            "base_branch_weakened": ("$env:BASE_BRANCH -eq 'main'", "$true"),
            "downstream_repository_weakened":
                ("$env:EVENT_REPOSITORY -eq $downstreamRepository", "$true"),
            "downstream_base_weakened":
                ("$env:BASE_REPOSITORY -eq $downstreamRepository", "$true"),
            "fallthrough_success":
                ("throw 'Unsupported or ambiguous policy evaluation context'",
                 "$evaluationContext = 'SELF_PR_BOOTSTRAP'"),
            "sha_weakened": ("^[0-9a-f]{40}$", ".*"),
            "root_separation_removed":
                ("throw 'Candidate and protected-policy roots must be separate'",
                 "Write-Output 'roots overlap'"),
            "candidate_remote_removed":
                ("throw 'Candidate checkout repository mismatch'", "Write-Output 'ignored'"),
            "policy_remote_removed":
                ("throw 'Protected-policy checkout repository mismatch'", "Write-Output 'ignored'"),
            "candidate_head_removed":
                ("throw 'Candidate checkout does not match event SHA'", "Write-Output 'ignored'"),
            "protected_head_removed":
                ("throw 'Protected-policy checkout is not protected main'", "Write-Output 'ignored'"),
            "comparison_removed":
                ("git -C candidate diff --name-only $policyHead $candidateHead", "Write-Output ''"),
            "sixth_file_allowed":
                ("'verify_security_workflows.py'", "'verify_security_workflows.py',\n              'extra.txt'"),
            "candidate_lock_replaced":
                ('$env:POLICY_SOURCE/requirements-policy.lock', "policy/requirements-policy.lock"),
            "candidate_tests_replaced":
                ("-s $env:POLICY_SOURCE", "-s policy"),
            "candidate_audit_lock_replaced":
                ('$env:POLICY_SOURCE/requirements-audit.lock', "policy/requirements-audit.lock"),
            "downstream_validator_replaced":
                ("policy/verify_security_workflows.py", "candidate/verify_security_workflows.py"),
            "validator_condition_removed":
                ("if: env.EVALUATION_CONTEXT == 'DOWNSTREAM_SECURITY_WORKFLOWS'", "if: always()"),
            "hash_enforcement_removed": (" --require-hashes", ""),
            "binary_enforcement_removed": (" --only-binary=:all:", ""),
            "continue_on_error": ("    steps:\n", "    continue-on-error: true\n    steps:\n"),
            "normalization_removed":
                ("      - name: Normalize and verify committed policy bytes\n", "      - name: Missing normalization\n"),
            "candidate_only_normalization":
                ("foreach ($root in @('candidate', 'policy'))", "foreach ($root in @('candidate'))"),
            "protected_only_normalization":
                ("foreach ($root in @('candidate', 'policy'))", "foreach ($root in @('policy'))"),
            "hash_install_representation_split":
                ("git -C $env:POLICY_SOURCE hash-object --no-filters $lock",
                 "git -C policy hash-object --no-filters $lock"),
            "downstream_normalization_bypass":
                ("git -C $env:POLICY_SOURCE rev-parse", "git -C candidate rev-parse"),
            "normalization_failure_nonfatal":
                ("& git -C $root config core.autocrlf false\n"
                 "            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
                 "& git -C $root config core.autocrlf false\n"
                 "            if ($LASTEXITCODE -ne 0) { Write-Output 'ignored' }"),
        }
        for label, (old, new) in mutations.items():
            with self.subTest(label=label):
                mutated = original.replace(old, new, 1)
                self.assertNotEqual(mutated, original)
                with self.assertRaises((AssertionError, KeyError, StopIteration)):
                    assert_contract(mutated)
        workflow = yaml.load(original, Loader=yaml.BaseLoader)
        steps = workflow["jobs"]["security-workflows-policy"]["steps"]
        normalization_step = steps.pop(3)
        steps.insert(7, normalization_step)
        with self.subTest(label="normalization_after_install"), self.assertRaises(
                (AssertionError, KeyError, StopIteration)):
            assert_contract(yaml.safe_dump(workflow, sort_keys=False))

        workflow = yaml.load(original, Loader=yaml.BaseLoader)
        normalization = workflow["jobs"]["security-workflows-policy"]["steps"][3]["run"]
        normalization_lines = normalization.splitlines()
        reset_index = next(index for index, line in enumerate(normalization_lines)
                           if "reset --hard HEAD" in line)
        reset_block = normalization_lines[reset_index:reset_index + 2]
        del normalization_lines[reset_index:reset_index + 2]
        hash_index = next(index for index, line in enumerate(normalization_lines)
                          if "hash-object --no-filters" in line)
        normalization_lines[hash_index + 2:hash_index + 2] = reset_block
        workflow["jobs"]["security-workflows-policy"]["steps"][3]["run"] = (
            "\n".join(normalization_lines) + "\n"
        )
        with self.subTest(label="normalization_after_hash"), self.assertRaises(
                (AssertionError, KeyError, StopIteration)):
            assert_contract(yaml.safe_dump(workflow, sort_keys=False))
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


if __name__ == "__main__":
    unittest.main()
