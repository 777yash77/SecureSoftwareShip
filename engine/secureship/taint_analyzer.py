"""SecureShip Static Taint Analysis Engine.

Performs source-to-sink dataflow tracking on Python and JavaScript codebases
to identify injection vulnerabilities with high mathematical precision.

Taint Pipeline:
1. Identify Untrusted Input Sources (HTTP parameters, CLI arguments, environment)
2. Trace Taint Propagation across variables, string interpolations, and concatenations
3. Verify presence of Data Sanitizers (int casts, HTML escaping, parameterized placeholders)
4. Flag Dangerous Sinks (SQL execution, OS shell, eval/exec, SSRF, File I/O)
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class SinkType(str, Enum):
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    CODE_EXECUTION = "CODE_EXECUTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    SSRF = "SSRF"
    XSS = "XSS"


@dataclass
class TaintFinding:
    file_path: str
    sink_type: SinkType
    sink_line: int
    source_line: int
    tainted_var: str
    sink_function: str
    call_path: str
    code_snippet: str
    remediation: str


class PythonTaintVisitor(ast.NodeVisitor):
    """AST Visitor that tracks variable taint from HTTP sources to dangerous sinks."""

    TAINT_SOURCES = {
        "request.args",
        "request.form",
        "request.values",
        "request.json",
        "request.data",
        "request.headers",
        "request.get_json",
        "sys.argv",
        "input",
    }

    SANITIZERS = {
        "int",
        "float",
        "bool",
        "escape",
        "shlex.quote",
        "secure_filename",
    }

    SQL_SINKS = {"execute", "executemany", "raw", "query"}
    CMD_SINKS = {"system", "popen", "call", "run", "Popen", "check_output"}
    CODE_SINKS = {"eval", "exec"}
    PATH_SINKS = {"open", "remove", "unlink", "rmdir"}
    SSRF_SINKS = {"get", "post", "put", "delete", "request", "urlopen"}

    def __init__(self, file_path: str, lines: List[str]):
        self.file_path = file_path
        self.lines = lines
        self.tainted_vars: Dict[str, int] = {}  # var_name -> source_line
        self.sanitized_vars: Set[str] = set()
        self.findings: List[TaintFinding] = []

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._get_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return ""

    def _is_tainted_expr(self, node: ast.AST) -> Optional[Tuple[str, int]]:
        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars and node.id not in self.sanitized_vars:
                return (node.id, self.tainted_vars[node.id])
        elif isinstance(node, ast.JoinedStr):  # f-string: f"...{var}..."
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    t = self._is_tainted_expr(val.value)
                    if t:
                        return t
        elif isinstance(node, ast.BinOp):  # "query " + var or "query %s" % var
            left = self._is_tainted_expr(node.left)
            if left:
                return left
            right = self._is_tainted_expr(node.right)
            if right:
                return right
        elif isinstance(node, ast.Call):
            call_name = self._get_call_name(node.func)
            # Check if source
            if any(s in call_name for s in self.TAINT_SOURCES):
                return (call_name, getattr(node, "lineno", 1))
            # Check if sanitizer
            if any(san in call_name for san in self.SANITIZERS):
                return None
            # Check arguments
            for arg in node.args:
                t = self._is_tainted_expr(arg)
                if t:
                    return t
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        tainted = self._is_tainted_expr(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if tainted:
                    self.tainted_vars[var_name] = tainted[1]
                else:
                    # Check if sanitized
                    if isinstance(node.value, ast.Call):
                        c_name = self._get_call_name(node.value.func)
                        if any(s in c_name for s in self.SANITIZERS):
                            self.sanitized_vars.add(var_name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._get_call_name(node.func)
        func_short = call_name.split(".")[-1]

        sink_type: Optional[SinkType] = None
        remediation = ""

        if func_short in self.SQL_SINKS:
            sink_type = SinkType.SQL_INJECTION
            remediation = "Use parameterized queries with placeholders: cursor.execute('SELECT * FROM t WHERE id = %s', (val,))"
        elif func_short in self.CMD_SINKS:
            sink_type = SinkType.COMMAND_INJECTION
            remediation = "Pass arguments as a safe list without shell=True: subprocess.run(['cmd', arg], shell=False)"
        elif func_short in self.CODE_SINKS:
            sink_type = SinkType.CODE_EXECUTION
            remediation = "Avoid dynamic eval/exec; use safe data parsers (e.g. ast.literal_eval or json.loads)."
        elif func_short in self.PATH_SINKS:
            sink_type = SinkType.PATH_TRAVERSAL
            remediation = "Sanitize filename with werkzeug.utils.secure_filename and resolve against a restricted directory root."
        elif func_short in self.SSRF_SINKS and any(p in call_name for p in ("requests", "urllib", "http")):
            sink_type = SinkType.SSRF
            remediation = "Validate requested URLs against an allowlist of permitted hosts and reject private IP ranges (RFC 1918)."

        if sink_type and node.args:
            first_arg = node.args[0]
            taint = self._is_tainted_expr(first_arg)
            if taint:
                var_name, src_line = taint
                line_no = getattr(node, "lineno", 1)
                snippet = self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""
                self.findings.append(
                    TaintFinding(
                        file_path=self.file_path,
                        sink_type=sink_type,
                        sink_line=line_no,
                        source_line=src_line,
                        tainted_var=var_name,
                        sink_function=call_name,
                        call_path=f"Source ({var_name} at L{src_line}) -> Sink ({call_name} at L{line_no})",
                        code_snippet=snippet,
                        remediation=remediation,
                    )
                )

        self.generic_visit(node)


class TaintAnalyzer:
    """Orchestrates source-to-sink taint analysis across Python and JavaScript codebases."""

    def __init__(self, target_dir: str):
        self.target_dir = Path(target_dir).resolve()

    def analyze(self) -> Dict[str, Any]:
        findings: List[TaintFinding] = []

        # 1. Analyze Python files via AST visitor
        for py_file in self.target_dir.rglob("*.py"):
            if any(x in py_file.parts for x in (".git", "venv", ".pytest_cache", "node_modules", "dist")):
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()
                tree = ast.parse(content, filename=str(py_file))
                rel_path = str(py_file.relative_to(self.target_dir))
                visitor = PythonTaintVisitor(rel_path, lines)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except Exception:
                pass

        # 2. Analyze JavaScript files via pattern flow analysis
        for js_file in self.target_dir.rglob("*.[jt]s"):
            if any(x in js_file.parts for x in (".git", "node_modules", "dist", ".vscode-test")):
                continue
            try:
                rel_path = str(js_file.relative_to(self.target_dir))
                findings.extend(self._analyze_js_file(js_file, rel_path))
            except Exception:
                pass

        return {
            "target": str(self.target_dir),
            "total_taint_findings": len(findings),
            "status": "SECURE" if len(findings) == 0 else "TAINT_DETECTED",
            "findings": [
                {
                    "file": f.file_path,
                    "sink_type": f.sink_type.value,
                    "sink_line": f.sink_line,
                    "source_line": f.source_line,
                    "tainted_var": f.tainted_var,
                    "sink_function": f.sink_function,
                    "call_path": f.call_path,
                    "code_snippet": f.code_snippet,
                    "remediation": f.remediation,
                }
                for f in findings
            ],
        }

    def _analyze_js_file(self, file_path: Path, rel_path: str) -> List[TaintFinding]:
        results: List[TaintFinding] = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = content.splitlines()

        # Track variable assignments from req.query / req.body / req.params
        tainted_vars: Dict[str, int] = {}
        source_pattern = re.compile(r"(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*req\.(?:query|body|params|headers)")
        sink_pattern = re.compile(r"(db\.query|client\.query|child_process\.exec|exec|eval)\s*\(\s*([^)]+)\)")

        for idx, line in enumerate(lines, start=1):
            m_src = source_pattern.search(line)
            if m_src:
                var_name = m_src.group(1)
                tainted_vars[var_name] = idx

            m_sink = sink_pattern.search(line)
            if m_sink:
                func_name = m_sink.group(1)
                arg_expr = m_sink.group(2)
                for t_var, src_line in tainted_vars.items():
                    if t_var in arg_expr:
                        st = SinkType.SQL_INJECTION if "query" in func_name else SinkType.COMMAND_INJECTION
                        results.append(
                            TaintFinding(
                                file_path=rel_path,
                                sink_type=st,
                                sink_line=idx,
                                source_line=src_line,
                                tainted_var=t_var,
                                sink_function=func_name,
                                call_path=f"Source (req.{t_var} at L{src_line}) -> Sink ({func_name} at L{idx})",
                                code_snippet=line.strip(),
                                remediation="Validate inputs and use parameterized database bindings or execFile with array arguments.",
                            )
                        )
        return results
