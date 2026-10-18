"""Static collection of settings from a project. Nothing is ever executed."""
import ast
import configparser
import json
import os
import re
from dataclasses import dataclass, field

SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "env", "node_modules", "site-packages", "tests"}
CONFIG_EXTS = {".ini", ".cfg", ".json", ".yml", ".yaml"}
MAX_FILE_BYTES = 2 * 1024 * 1024

LITERAL, ENV, DYNAMIC = "literal", "env", "dynamic"


@dataclass
class Setting:
    key: str
    value: object
    kind: str  # LITERAL | ENV | DYNAMIC
    file: str
    line: int


@dataclass
class Project:
    settings: list = field(default_factory=list)
    strings: set = field(default_factory=set)       # all string constants in .py files
    imports: set = field(default_factory=set)
    flask_files: list = field(default_factory=list)
    scanned_files: int = 0
    errors: list = field(default_factory=list)

    def get(self, key):
        """Last definition wins (mirrors how later assignments override earlier ones)."""
        found = [s for s in self.settings if s.key == key]
        return found[-1] if found else None


def _uses_env(node):
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv"):
            return True
        if isinstance(n, ast.Name) and n.id in ("getenv", "environ"):
            return True
    return False


def _value(node):
    if _uses_env(node):
        return ENV, None
    try:
        return LITERAL, ast.literal_eval(node)
    except Exception:
        return DYNAMIC, None


class _Visitor(ast.NodeVisitor):
    def __init__(self, project, rel):
        self.p, self.rel = project, rel

    def add(self, key, node, line):
        kind, val = _value(node)
        self.p.settings.append(Setting(key.upper(), val, kind, self.rel, line))

    def visit_Import(self, node):
        for a in node.names:
            self.p.imports.add(a.name.split(".")[0])

    def visit_ImportFrom(self, node):
        if node.module:
            self.p.imports.add(node.module.split(".")[0])

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self.p.strings.add(node.value.lower())

    def visit_Assign(self, node):
        for t in node.targets:
            self._target(t, node.value, node.lineno)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._target(node.target, node.value, node.lineno)
        self.generic_visit(node)

    def _target(self, t, value, line):
        if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) \
                and isinstance(t.slice.value, str) and "config" in ast.unparse(t.value).lower():
            self.add(t.slice.value, value, line)
        elif isinstance(t, ast.Attribute) and t.attr in ("secret_key", "debug"):
            self.add(t.attr, value, line)
        elif isinstance(t, ast.Name) and t.id.isupper():
            self.add(t.id, value, line)

    def visit_Call(self, node):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in ("update", "from_mapping") and "config" in ast.unparse(func).lower():
            for kw in node.keywords:
                if kw.arg:
                    self.add(kw.arg, kw.value, node.lineno)
            for arg in node.args:
                if isinstance(arg, ast.Dict):
                    for k, v in zip(arg.keys, arg.values):
                        if isinstance(k, ast.Constant) and isinstance(k.value, str):
                            self.add(k.value, v, node.lineno)
        elif name == "run":
            for kw in node.keywords:
                if kw.arg == "debug":
                    self.add("DEBUG", kw.value, node.lineno)
        elif name == "Flask":
            self.p.flask_files.append(self.rel)
        self.generic_visit(node)


def _coerce(v):
    if isinstance(v, str):
        low = v.strip().lower()
        if low in ("true", "yes", "on", "1"):
            return True
        if low in ("false", "no", "off", "0"):
            return False
        return v.strip().strip("'\"")
    return v


def _add_flat(project, rel, pairs):
    for i, (k, v) in enumerate(pairs, 1):
        kind = ENV if isinstance(v, str) and re.search(r"\$\{?\w+", v) else LITERAL
        project.settings.append(Setting(str(k).upper(), _coerce(v), kind, rel, i))


def _flatten_json(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten_json(v, k)
    elif not isinstance(obj, list):
        yield prefix, obj


def _parse_config_file(project, path, rel):
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path).lower()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    if ext == ".json":
        _add_flat(project, rel, _flatten_json(json.loads(text)))
    elif ext in (".ini", ".cfg"):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_string(text)
        _add_flat(project, rel, [(k, v) for s in cp.sections() for k, v in cp.items(s)]
                  + list(cp.defaults().items()))
    else:  # .env style, yaml (flat "key: value"), dotenv
        pairs = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(?:export\s+)?([\w.\-]+)\s*[=:]\s*(.*)$", line)
            if m and m.group(2) != "":
                pairs.append((m.group(1), m.group(2)))
        _add_flat(project, rel, pairs)


def collect(root):
    project = Project()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            ext = os.path.splitext(fn)[1].lower()
            is_env = fn.lower().startswith(".env") or ext == ".env"
            if os.path.islink(path) or os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            try:
                if ext == ".py":
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        tree = ast.parse(f.read(), filename=rel)
                    _Visitor(project, rel).visit(tree)
                elif ext in CONFIG_EXTS or is_env:
                    _parse_config_file(project, path, rel)
                else:
                    continue
                project.scanned_files += 1
            except Exception as e:  # unparsable file: report, keep going
                project.errors.append(f"{rel}: {type(e).__name__}: {e}")
    return project
