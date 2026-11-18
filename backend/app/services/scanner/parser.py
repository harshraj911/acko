import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from app.services.versioning.ranges import normalize_package_name


@dataclass
class ParsedPackage:
    ecosystem: str
    name: str
    normalized_name: str
    version: str | None
    specifier: str | None
    instance_key: str
    package_path: str
    direct: bool
    dev_only: bool
    resolved: bool
    manifest_file: str
    parents: list[str] = field(default_factory=list)


def _npm_scan(root: Path) -> list[ParsedPackage]:
    package_file = root / "package.json"
    lock_file = root / "package-lock.json"
    manifest = json.loads(package_file.read_text(encoding="utf-8")) if package_file.exists() else {}
    if not lock_file.exists():
        return []
    lock = json.loads(lock_file.read_text(encoding="utf-8"))
    if lock.get("lockfileVersion") != 3:
        raise ValueError(f"Unsupported npm lockfile version: {lock.get('lockfileVersion')}")
    packages = lock.get("packages", {})
    root_entry = packages.get("", {})
    runtime_specs = {**root_entry.get("dependencies", {}), **manifest.get("dependencies", {})}
    dev_specs = {**root_entry.get("devDependencies", {}), **manifest.get("devDependencies", {})}
    direct_runtime = set(runtime_specs)
    direct_dev = set(dev_specs)
    direct_all = direct_runtime | direct_dev

    parsed: dict[str, ParsedPackage] = {}
    for path, info in packages.items():
        if not path or not path.startswith("node_modules/"):
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        if not info.get("version"):
            continue
        direct = path.count("node_modules/") == 1 and name in direct_all
        dev = bool(info.get("dev")) or (direct and name in direct_dev and name not in direct_runtime)
        parsed[path] = ParsedPackage(
            ecosystem="npm", name=name, normalized_name=normalize_package_name("npm", name),
            version=info["version"],
            specifier=runtime_specs.get(name) or dev_specs.get(name),
            instance_key=f"npm:{path}",
            package_path=path, direct=direct, dev_only=dev, resolved=True,
            manifest_file="package-lock.json",
        )

    def resolve(parent_path: str, package_name: str) -> str | None:
        parent_dir = parent_path if parent_path else ""
        while True:
            candidate = f"{parent_dir}/node_modules/{package_name}" if parent_dir else f"node_modules/{package_name}"
            if candidate in parsed:
                return candidate
            if not parent_dir:
                return None
            if "/node_modules/" in parent_dir:
                parent_dir = parent_dir.rsplit("/node_modules/", 1)[0]
            elif parent_dir.startswith("node_modules/"):
                parent_dir = ""
            else:
                parent_dir = ""

    edges: list[tuple[str, str]] = []
    for path, package_info in packages.items():
        if path not in parsed:
            continue
        dep_names = set(package_info.get("dependencies", {}))
        dep_names.update(package_info.get("optionalDependencies", {}))
        for dependency_name in dep_names:
            child = resolve(path, dependency_name)
            if child:
                edges.append((path, child))
                parsed[child].parents.append(path)

    # Include lockfile packages absent from the manifest's packages map only as lock entries;
    # directness still comes from the root manifest and transitive edges from lock metadata.
    for path, entry in parsed.items():
        if entry.direct:
            continue
        ancestors = entry.parents
        entry.dev_only = entry.dev_only or bool(ancestors) and all(parsed[parent].dev_only for parent in ancestors)
    return list(parsed.values())


def _read_requirement_line(line: str):
    clean = line.split("#", 1)[0].strip()
    if not clean or clean.startswith("-"):
        return None
    try:
        return Requirement(clean)
    except InvalidRequirement:
        return None


def _python_scan(root: Path) -> list[ParsedPackage]:
    lock_path = root / "requirements.lock"
    requirements_path = root / "requirements.txt"
    dev_path = root / "requirements-dev.txt"
    direct: dict[str, tuple[str, str, bool]] = {}
    for path, dev in ((requirements_path, False), (dev_path, True)):
        if not path.exists():
            continue
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            req = _read_requirement_line(raw_line)
            if req:
                key = normalize_package_name("PyPI", req.name)
                prior = direct.get(key)
                direct[key] = (
                    req.name,
                    str(req.specifier) if not prior or not prior[1] else prior[1],
                    dev if not prior else prior[2] and dev,
                )

    locked: dict[str, dict] = {}
    if lock_path.exists():
        lines = lock_path.read_text(encoding="utf-8").splitlines()
        current: dict | None = None
        in_via = False
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if not line[:1].isspace() and not stripped.startswith("#"):
                req = _read_requirement_line(stripped)
                if req and "==" in str(req.specifier):
                    version = next(iter(req.specifier)).version
                    key = normalize_package_name("PyPI", req.name)
                    current = locked.setdefault(key, {
                        "name": req.name, "version": version, "parents": [], "direct": False,
                    })
                    in_via = False
                else:
                    current = None
                    in_via = False
                continue
            if not current:
                continue
            if "# via" in stripped:
                via_text = stripped.split("# via", 1)[1].strip()
                in_via = True
            elif stripped.startswith("#") and in_via:
                via_text = stripped[1:].strip()
            else:
                continue
            if "-r requirements.txt" in via_text or via_text == "-r":
                current["direct"] = True
            for token in re.split(r"\s+", via_text):
                token = token.strip().lstrip("#").strip()
                if token.startswith("-r"):
                    if "requirements.txt" in token or via_text == "-r":
                        current["direct"] = True
                    continue
                if token == "requirements.txt":
                    current["direct"] = True
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)", token)
                if match:
                    current["parents"].append(normalize_package_name("PyPI", match.group(1)))

    output: dict[str, ParsedPackage] = {}
    for key, locked_entry in locked.items():
        direct_info = direct.get(key)
        is_direct = bool(direct_info) or bool(locked_entry["direct"])
        dev_only = bool(direct_info and direct_info[2] and key not in locked)
        output[key] = ParsedPackage(
            ecosystem="PyPI", name=locked_entry["name"], normalized_name=key,
            version=locked_entry["version"], specifier=direct_info[1] if direct_info else f"=={locked_entry['version']}",
            instance_key=f"pypi:runtime:{key}", package_path=locked_entry["name"],
            direct=is_direct, dev_only=dev_only, resolved=True,
            manifest_file="requirements.lock", parents=locked_entry["parents"],
        )

    # Requirements-dev is scanned independently so development packages stay visible
    # even when the production lockfile does not include them.
    for key, (name, specifier, dev_only) in direct.items():
        if not dev_only or key in output:
            continue
        pinned = re.fullmatch(r"==\s*([^,; ]+)", specifier)
        output[key] = ParsedPackage(
            ecosystem="PyPI", name=name, normalized_name=key,
            version=pinned.group(1) if pinned else None, specifier=specifier,
            instance_key=f"pypi:dev:{key}", package_path=name, direct=True,
            dev_only=True, resolved=bool(pinned), manifest_file="requirements-dev.txt",
        )

    # For a manifest without a lock, retain declarations but never invent resolved versions.
    if not lock_path.exists():
        for key, (name, specifier, dev_only) in direct.items():
            output[key] = ParsedPackage(
                ecosystem="PyPI", name=name, normalized_name=key, version=None,
                specifier=specifier, instance_key=f"pypi:{'dev' if dev_only else 'runtime'}:{key}",
                package_path=name, direct=True, dev_only=dev_only, resolved=False,
                manifest_file="requirements-dev.txt" if dev_only else "requirements.txt",
            )

    return list(output.values())


def scan_manifests(root: Path) -> list[ParsedPackage]:
    if (root / "package.json").exists() or (root / "package-lock.json").exists():
        return _npm_scan(root)
    return _python_scan(root)
