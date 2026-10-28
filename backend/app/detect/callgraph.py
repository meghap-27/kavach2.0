"""Parse a Flask project into functions, calls, import aliases and routes (L2)."""
import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

ROUTE_METHODS = {"route", "get", "post", "put", "delete", "patch"}
ROUTE_PARAM = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>")
AUTH_DECORATORS = {"login_required", "auth_required", "requires_auth", "jwt_required"}


@dataclass
class Function:
    qualname: str  # "module:func"
    module: str
    name: str
    file: str
    node: ast.FunctionDef
    params: list[str]
    route: str | None = None
    route_params: list[str] = field(default_factory=list)
    has_auth: bool = False


@dataclass
class Project:
    root: Path
    modules: dict[str, ast.Module] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)  # module -> relative file
    aliases: dict[str, dict[str, str]] = field(default_factory=dict)  # module -> local -> dotted
    functions: dict[str, Function] = field(default_factory=dict)
    unresolved: list[tuple[str, int, str]] = field(default_factory=list)  # (file, line, text)

    def resolve(self, module: str, func: ast.expr) -> str | None:
        """Return the qualname of a project function called by `func`, or None."""
        dotted = dotted_name(func, self.aliases.get(module, {}))
        if not dotted:
            return None
        if "." not in dotted and f"{module}:{dotted}" in self.functions:
            return f"{module}:{dotted}"
        mod, _, name = dotted.rpartition(".")
        target = self.match_module(mod)
        if target and f"{target}:{name}" in self.functions:
            return f"{target}:{name}"
        return None

    def match_module(self, dotted: str) -> str | None:
        if dotted in self.modules:
            return dotted
        hits = [m for m in self.modules if m.endswith("." + dotted)]
        return hits[0] if len(hits) == 1 else None


def dotted_name(expr: ast.expr, aliases: dict[str, str]) -> str | None:
    if isinstance(expr, ast.Name):
        return aliases.get(expr.id, expr.id)
    if isinstance(expr, ast.Attribute):
        base = dotted_name(expr.value, aliases)
        return f"{base}.{expr.attr}" if base else None
    return None


def module_name(rel: Path) -> str:
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) or "__init__"


def collect_aliases(tree: ast.Module, module: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    package = module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = ".".join(filter(None, [package, base]))
            for a in node.names:
                aliases[a.asname or a.name] = f"{base}.{a.name}" if base else a.name
    return aliases


def route_info(fn: ast.FunctionDef) -> tuple[str | None, bool]:
    route, auth = None, False
    for dec in fn.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if name in AUTH_DECORATORS:
            auth = True
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and name in ROUTE_METHODS:
            if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                route = dec.args[0].value
    return route, auth


def _add_functions(project: Project, module: str, rel: str, tree: ast.Module) -> None:
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route, auth = route_info(node)
        params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
        fn = Function(f"{module}:{node.name}", module, node.name, rel, node, params,
                      route, ROUTE_PARAM.findall(route) if route else [], auth)
        project.functions[fn.qualname] = fn


def _record_dynamic(project: Project, module: str, rel: str, tree: ast.Module) -> None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Call):
            inner = node.func.func
            if isinstance(inner, ast.Name) and inner.id == "getattr":
                project.unresolved.append((rel, node.lineno, ast.unparse(node)[:80]))


def build_project(root: str | Path, files: list[Path] | None = None) -> Project:
    root = Path(root)
    project = Project(root)
    for py in files or sorted(root.rglob("*.py")):
        rel = py.relative_to(root)
        try:
            tree = ast.parse(py.read_text(errors="replace"), filename=str(rel))
        except SyntaxError:
            continue
        module = module_name(rel)
        project.modules[module] = tree
        project.files[module] = rel.as_posix()
        project.aliases[module] = collect_aliases(tree, module)
        _add_functions(project, module, rel.as_posix(), tree)
        _record_dynamic(project, module, rel.as_posix(), tree)
    return project


def callers_of(project: Project) -> dict[str, set[str]]:
    """Reverse call graph: callee qualname -> caller qualnames."""
    rev: dict[str, set[str]] = {q: set() for q in project.functions}
    for fn in project.functions.values():
        for node in ast.walk(fn.node):
            if isinstance(node, ast.Call):
                callee = project.resolve(fn.module, node.func)
                if callee:
                    rev[callee].add(fn.qualname)
    return rev
