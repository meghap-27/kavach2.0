"""Intra-procedural taint analysis with hooks for callee summaries (L2).

Taint is a set of (label, cwe) pairs. A label is "src:<what>" for user input or
"param:<name>" for a parameter of the function under analysis (used to build the
summaries that wrappers.py composes across the call graph). A sanitizer removes only
the CWEs it actually protects against.
"""
import ast
from dataclasses import dataclass, field

from .callgraph import Function, Project, dotted_name

CWES = ("CWE-78", "CWE-89", "CWE-22")
EMPTY: frozenset = frozenset()
MAX_PATH = 8

SOURCE_ATTRS = {"args", "form", "values", "json", "cookies", "headers", "files", "data"}
SOURCE_CALLS = {"get_json", "get_data"}

SANITIZERS = {
    "shlex.quote": {"CWE-78"}, "pipes.quote": {"CWE-78"},
    "werkzeug.utils.secure_filename": {"CWE-22"}, "secure_filename": {"CWE-22"},
    "os.path.basename": {"CWE-22"},
    "int": set(CWES), "float": set(CWES), "bool": set(CWES), "len": set(CWES),
}

# sink name -> (cwe, indices of dangerous positional args, needs shell=True)
SINKS = {
    "os.system": ("CWE-78", (0,), False), "os.popen": ("CWE-78", (0,), False),
    "subprocess.getoutput": ("CWE-78", (0,), False),
    "subprocess.getstatusoutput": ("CWE-78", (0,), False),
    "subprocess.run": ("CWE-78", (0,), True), "subprocess.call": ("CWE-78", (0,), True),
    "subprocess.check_output": ("CWE-78", (0,), True),
    "subprocess.check_call": ("CWE-78", (0,), True), "subprocess.Popen": ("CWE-78", (0,), True),
    "open": ("CWE-22", (0,), False), "io.open": ("CWE-22", (0,), False),
    "flask.send_file": ("CWE-22", (0,), False), "send_file": ("CWE-22", (0,), False),
    "os.remove": ("CWE-22", (0,), False), "os.unlink": ("CWE-22", (0,), False),
    "os.rmdir": ("CWE-22", (0,), False), "shutil.rmtree": ("CWE-22", (0,), False),
    "shutil.copy": ("CWE-22", (0, 1), False), "shutil.copy2": ("CWE-22", (0, 1), False),
    "shutil.copyfile": ("CWE-22", (0, 1), False), "shutil.move": ("CWE-22", (0, 1), False),
}
SQL_METHODS = {"execute", "executescript", "executemany"}


@dataclass(frozen=True)
class SinkHit:
    """A parameter of some function reaches a sink unsanitized."""
    param: str
    cwe: str
    sink: str
    file: str
    line: int
    path: tuple[str, ...]


@dataclass(frozen=True)
class RawHit:
    """User input reaches a sink."""
    source: str
    cwe: str
    sink: str
    file: str
    line: int
    path: tuple[str, ...]
    function: str


@dataclass(eq=True)
class Summary:
    ret: dict[str, frozenset] = field(default_factory=dict)  # param -> CWEs reaching return
    sinks: frozenset = EMPTY  # SinkHit set


def taint_all(label: str) -> frozenset:
    return frozenset((label, c) for c in CWES)


def union(*sets) -> frozenset:
    out: set = set()
    for s in sets:
        out |= s
    return frozenset(out)


def strip(taint: frozenset, cwes: set[str]) -> frozenset:
    return frozenset(p for p in taint if p[1] not in cwes)


def sink_spec(name: str, func: ast.expr) -> tuple[str, str, tuple, bool] | None:
    if name in SINKS:
        cwe, idx, shell = SINKS[name]
        return cwe, name.removeprefix("flask."), idx, shell
    if isinstance(func, ast.Attribute) and func.attr in SQL_METHODS:
        return "CWE-89", f"cursor.{func.attr}", (0,), False
    return None


def shell_true(call: ast.Call) -> bool:
    return any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
               for k in call.keywords)


class FunctionAnalyzer:
    def __init__(self, project: Project, fn: Function, summaries: dict[str, Summary]):
        self.project, self.fn, self.summaries = project, fn, summaries
        self.aliases = project.aliases.get(fn.module, {})
        self.env: dict[str, frozenset] = {}
        self.hits: set[RawHit] = set()
        self.sinks: set[SinkHit] = set()
        self.ret: dict[str, set[str]] = {}
        for p in fn.params:
            label = f"src:route param <{p}>" if p in fn.route_params else f"param:{p}"
            self.env[p] = taint_all(label)

    def run(self) -> "FunctionAnalyzer":
        self.block(self.fn.node.body)
        return self

    def summary(self) -> Summary:
        return Summary({p: frozenset(c) for p, c in self.ret.items()}, frozenset(self.sinks))

    # ---- statements -------------------------------------------------------
    def block(self, stmts: list[ast.stmt]) -> None:
        for s in stmts:
            self.stmt(s)

    def stmt(self, s: ast.stmt) -> None:
        if isinstance(s, ast.Assign):
            t = self.expr(s.value)
            for tgt in s.targets:
                self.assign(tgt, t)
        elif isinstance(s, ast.AugAssign):
            self.assign(s.target, union(self.expr(s.value), self.expr(s.target)))
        elif isinstance(s, ast.AnnAssign) and s.value is not None:
            self.assign(s.target, self.expr(s.value))
        elif isinstance(s, ast.Return):
            self.record_return(self.expr(s.value))
        elif isinstance(s, ast.If):
            self.expr(s.test)
            self.branches([s.body, s.orelse])
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            self.assign(s.target, self.expr(s.iter))
            self.loop(s.body, s.orelse)
        elif isinstance(s, ast.While):
            self.expr(s.test)
            self.loop(s.body, s.orelse)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                t = self.expr(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, t)
            self.block(s.body)
        elif isinstance(s, ast.Try):
            self.block(s.body)
            self.branches([h.body for h in s.handlers] + [s.orelse])
            self.block(s.finalbody)
        elif not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for child in ast.iter_child_nodes(s):
                if isinstance(child, ast.expr):
                    self.expr(child)

    def branches(self, bodies: list[list[ast.stmt]]) -> None:
        start, results = dict(self.env), []
        for body in bodies:
            self.env = dict(start)
            self.block(body)
            results.append(self.env)
        self.env = {k: union(*(r.get(k, EMPTY) for r in results)) for k in set().union(*results)}

    def loop(self, body: list[ast.stmt], orelse: list[ast.stmt]) -> None:
        for _ in range(2):  # second pass lets loop-carried taint settle
            self.branches([body, []])
        self.block(orelse)

    def assign(self, target: ast.expr, t: frozenset) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = t
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt, t)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name):
                self.env[base.id] = union(self.env.get(base.id, EMPTY), t)

    def record_return(self, t: frozenset) -> None:
        for label, cwe in t:
            if label.startswith("param:"):
                self.ret.setdefault(label[6:], set()).add(cwe)

    # ---- expressions ------------------------------------------------------
    def is_request(self, e: ast.expr) -> bool:
        return dotted_name(e, self.aliases) in ("flask.request", "request")

    def expr(self, e: ast.expr | None) -> frozenset:
        if e is None or isinstance(e, (ast.Constant, ast.Lambda)):
            return EMPTY
        if isinstance(e, ast.Call):
            return self.call(e)
        if isinstance(e, ast.Attribute):
            if self.is_request(e.value) and e.attr in SOURCE_ATTRS:
                return taint_all(f"src:request.{e.attr}")
            return self.expr(e.value)
        if isinstance(e, ast.Name):
            return self.env.get(e.id, EMPTY)
        if isinstance(e, ast.Subscript):
            self.expr(e.slice)
            return self.expr(e.value)
        if isinstance(e, ast.NamedExpr):
            t = self.expr(e.value)
            self.assign(e.target, t)
            return t
        parts = [self.expr(c) for c in ast.iter_child_nodes(e) if isinstance(c, ast.expr)]
        if isinstance(e, ast.comprehension):
            return union(*parts)
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            parts += [self.expr(g.iter) for g in e.generators]
        return EMPTY if isinstance(e, ast.Compare) else union(*parts)

    def call(self, e: ast.Call) -> frozenset:
        name = dotted_name(e.func, self.aliases) or ""
        recv = self.expr(e.func.value) if isinstance(e.func, ast.Attribute) else EMPTY
        args = [self.expr(a) for a in e.args]
        kwargs = {k.arg: self.expr(k.value) for k in e.keywords}
        if isinstance(e.func, ast.Attribute) and e.func.attr in SOURCE_CALLS and self.is_request(e.func.value):
            return taint_all(f"src:request.{e.func.attr}()")
        self.check_sink(e, name, args)
        callee = self.project.resolve(self.fn.module, e.func)
        if callee:
            return self.apply_summary(callee, args, kwargs)
        merged = union(recv, *args, *kwargs.values())
        return strip(merged, SANITIZERS.get(name, set()))

    def check_sink(self, e: ast.Call, name: str, args: list[frozenset]) -> None:
        spec = sink_spec(name, e.func)
        if not spec:
            return
        cwe, sink, idx, needs_shell = spec
        if needs_shell and not shell_true(e):
            return
        tainted = union(*(args[i] for i in idx if i < len(args)))
        for label, c in tainted:
            if c == cwe:
                self.emit(label, cwe, sink, self.fn.file, e.lineno, (f"{self.fn.name}()", sink))

    def emit(self, label: str, cwe: str, sink: str, file: str, line: int, path: tuple) -> None:
        if len(path) > MAX_PATH:
            return
        if label.startswith("src:"):
            self.hits.add(RawHit(label[4:], cwe, sink, file, line, path, self.fn.qualname))
        else:
            self.sinks.add(SinkHit(label[6:], cwe, sink, file, line, path))

    def apply_summary(self, callee: str, args: list[frozenset], kwargs: dict) -> frozenset:
        summ = self.summaries.get(callee, Summary())
        params = self.project.functions[callee].params
        bound = {p: args[i] for i, p in enumerate(params) if i < len(args)}
        bound.update({k: v for k, v in kwargs.items() if k in params})
        for hit in summ.sinks:
            for label, c in bound.get(hit.param, EMPTY):
                if c == hit.cwe:
                    self.emit(label, c, hit.sink, hit.file, hit.line, (f"{self.fn.name}()",) + hit.path)
        out: set = set()
        for p, cwes in summ.ret.items():
            out |= {pair for pair in bound.get(p, EMPTY) if pair[1] in cwes}
        return frozenset(out)
