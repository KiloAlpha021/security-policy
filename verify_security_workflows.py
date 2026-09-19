"""Independent policy for proposed KiloAlpha021/security-workflows revisions."""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

import yaml

TARGET = "KiloAlpha021/security-workflows"
POLICY = "KiloAlpha021/security-policy"
BASE_BRANCH = "main"
SHA = re.compile(r"[0-9a-f]{40}\Z")
REF = re.compile(r"[0-9a-f]{40}\Z")
SEGMENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\Z")
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


class RestrictedLoader(yaml.BaseLoader):
    def compose_node(self, parent: object, index: object) -> yaml.Node:
        if self.check_event(yaml.AliasEvent):
            raise ValueError("Workflow aliases are unsupported")
        event = self.peek_event()
        if event.anchor is not None or event.tag is not None:
            raise ValueError("Workflow anchors and explicit tags are unsupported")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        result: dict[str, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str) or key == "<<" or key in result:
                raise ValueError("Duplicate, merge, or invalid workflow key")
            result[key] = self.construct_object(value_node, deep=True)
        return result


def action_references(text: str) -> list[tuple[tuple[object, ...], str]]:
    try:
        workflow = yaml.load(text, Loader=RestrictedLoader)
    except yaml.YAMLError as exc:
        raise ValueError("Malformed workflow YAML") from exc
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        raise ValueError("Unsupported workflow structure")
    jobs = workflow["jobs"]
    for job in jobs.values():
        if not isinstance(job, dict):
            raise ValueError("Unsupported workflow job")
        if "steps" in job and (not isinstance(job["steps"], list) or
                               any(not isinstance(step, dict) for step in job["steps"])):
            raise ValueError("Unsupported workflow steps")

    found: list[tuple[tuple[object, ...], str]] = []

    def visit(value: object, path: tuple[object, ...]) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = (*path, key)
                if key == "uses":
                    job_reference = len(child_path) == 3 and child_path[0] == "jobs"
                    step_reference = (len(child_path) == 5 and child_path[0] == "jobs"
                                      and child_path[2] == "steps" and isinstance(child_path[3], int))
                    if not (job_reference or step_reference) or not isinstance(child, str):
                        raise ValueError(f"Unsupported workflow uses placement: {child_path!r}")
                    parts = child.split("@")
                    if len(parts) != 2 or REF.fullmatch(parts[1]) is None:
                        raise ValueError("Action reference is not a full commit SHA")
                    segments = parts[0].split("/")
                    if len(segments) < 2 or any(SEGMENT.fullmatch(part) is None or part in {".", ".."}
                                                 for part in segments):
                        raise ValueError("Unsupported action reference")
                    if OWNER.fullmatch(segments[0]) is None or not any(char.isascii() and char.isalnum()
                                                                          for char in segments[1]):
                        raise ValueError("Unsupported action owner or repository")
                    if job_reference and (len(segments) != 5 or segments[2:4] != [".github", "workflows"]
                                          or not segments[4].endswith((".yml", ".yaml"))):
                        raise ValueError("Unsupported reusable workflow reference")
                    found.append((child_path, child))
                visit(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*path, index))

    visit(workflow, ())
    if not found:
        raise ValueError("No action references found")
    return found


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
    action_references(text)
    workflow = yaml.load(text, Loader=RestrictedLoader)
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        raise ValueError("Unsupported workflow structure")
    if workflow.get("name") != "trusted-m1-evaluator" or not isinstance(workflow.get("on"), dict) \
            or set(workflow["on"]) != {"pull_request", "merge_group"} \
            or workflow.get("permissions") != {"contents": "read"}:
        raise ValueError("Trusted workflow authority declaration changed")
    jobs = workflow["jobs"]
    if set(jobs) != {"trusted-m1-evaluator"}:
        raise ValueError("Unexpected trusted workflow job")
    job = jobs["trusted-m1-evaluator"]
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        raise ValueError("Unsupported trusted workflow steps")
    steps = job["steps"]
    actions = [(index, step) for index, step in enumerate(steps) if "uses" in step]
    if len(actions) != 3 or [step["uses"].split("@")[0] for _, step in actions] != [
        "actions/checkout", "actions/checkout", "actions/setup-python"
    ]:
        raise ValueError("Unexpected or duplicate workflow action")
    candidate_checkout, trusted_checkout = actions[0][1], actions[1][1]
    if actions[0][0] != 0 or actions[1][0] != 1:
        raise ValueError("Checkout order changed")
    if candidate_checkout.get("with") != {
        "repository": "KiloAlpha021/automated-trading-bot",
        "ref": "${{ github.sha }}",
        "path": "candidate",
        "fetch-depth": "0",
    }:
        raise ValueError("Exact trading candidate checkout changed")
    if trusted_checkout.get("with") != {
        "repository": TARGET, "ref": "main", "path": "trusted"
    }:
        raise ValueError("Independent trusted checkout changed")
    if len(steps) < 4 or steps[3].get("name") != "Enforce separate candidate and trusted identities":
        raise ValueError("Trusted verifier step changed")
    verifier_step = steps[3]
    if not isinstance(verifier_step.get("run"), str):
        raise ValueError("Protected verifier invocation changed")
    if verifier_step.get("env") != {
        "EVENT_REPOSITORY": "${{ github.repository }}",
        "CANDIDATE_SHA": "${{ github.sha }}",
        "EVENT_NAME": "${{ github.event_name }}",
    } or verifier_step.get("run", "").strip().splitlines() != [
        "$ErrorActionPreference = 'Stop'",
        "python trusted/verify_candidate.py --candidate candidate --trusted trusted --event-repository $env:EVENT_REPOSITORY --candidate-sha $env:CANDIDATE_SHA --event-name $env:EVENT_NAME",
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
    ]:
        raise ValueError("Protected verifier invocation changed")
    for fragment, message in (
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
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ValueError("Malformed trusted verifier") from exc
    constants = {
        node.targets[0].id: node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    }
    if constants.get("CANDIDATE_REPOSITORY") != "KiloAlpha021/automated-trading-bot" or \
            constants.get("TRUSTED_REPOSITORY") != TARGET or \
            constants.get("TRUSTED_REF") != "refs/remotes/origin/main":
        raise ValueError("Trusted verifier target constants changed")
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "verify"]
    if len(functions) != 1:
        raise ValueError("Trusted verifier entry changed")
    body = functions[0].body
    required_guards = (
        'candidate = candidate.resolve(strict=True)',
        'trusted = trusted.resolve(strict=True)',
        'if candidate == trusted or candidate in trusted.parents or trusted in candidate.parents: raise ValueError("Candidate and trusted roots must be separate")',
        'if event_repository != CANDIDATE_REPOSITORY: raise ValueError("Wrong target repository")',
        'if event_name not in {"pull_request", "merge_group"}: raise ValueError("Unsupported required-workflow event")',
        'if not SHA.fullmatch(candidate_sha): raise ValueError("Invalid candidate SHA")',
        'if repository(candidate) != CANDIDATE_REPOSITORY: raise ValueError("Wrong candidate checkout")',
        'if git(candidate, "rev-parse", "HEAD") != candidate_sha: raise ValueError("Candidate checkout does not match event SHA")',
        'if git(candidate, "rev-parse", "--is-shallow-repository") != "false": raise ValueError("Required candidate history is unavailable")',
        'if repository(trusted) != TRUSTED_REPOSITORY: raise ValueError("Wrong trusted checkout")',
        'if git(trusted, "rev-parse", "HEAD") != git(trusted, "rev-parse", TRUSTED_REF): raise ValueError("Trusted checkout is not protected main")',
        'if actual_lock != expected_lock: raise ValueError("Candidate dependency lock differs from trusted lock")',
    )
    guard_shapes = [ast.dump(ast.parse(guard).body[0], include_attributes=False)
                    for guard in required_guards]
    observed = [ast.dump(node, include_attributes=False) for node in body]
    positions = [observed.index(shape) if shape in observed else -1 for shape in guard_shapes]
    if -1 in positions or positions != sorted(positions) or any(
        isinstance(node, (ast.Return, ast.Try)) for node in ast.walk(functions[0])
    ):
        raise ValueError("Trusted verifier event, origin, or HEAD guard changed")
    for fragment, message in (
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
        "test_wrong_target_repository_fails",
        "test_malformed_identity_fails",
    ):
        require(text, fragment, "Critical adversarial verifier test removed")
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        raise ValueError("Malformed adversarial verifier tests") from exc
    wrong_target = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                    and node.name == "test_wrong_target_repository_fails"]
    if len(wrong_target) != 1 or not any(
        isinstance(node, ast.With) and any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Attribute)
            and item.context_expr.func.attr in {"assertRaises", "assertRaisesRegex"}
            and any(isinstance(arg, ast.Name) and arg.id == "ValueError"
                    for arg in item.context_expr.args)
            for item in node.items
        ) and any(
            isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and call.func.attr == "check"
            and any(keyword.arg == "repository" and
                    isinstance(keyword.value, ast.Constant) and
                    keyword.value.value == TARGET
                    for keyword in call.keywords)
            for statement in node.body for call in ast.walk(statement)
        ) for node in wrong_target[0].body
    ):
        raise ValueError("Wrong trading target rejection test removed")


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
