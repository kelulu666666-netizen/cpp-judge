#!/usr/bin/env python3
"""C++ 在线判题后端（类似洛谷「爱测试」）。

- 用 g++ 编译用户提交的 C++ 代码
- 在受限沙箱中运行（超时、内存、文件大小、进程数、降权、断网）
- 返回编译错误 / 运行错误 / 超时 / 内存超限 / 答案正确等状态
"""
import os
import re
import ctypes
import time
import json
import hmac
import hashlib
import secrets
import sqlite3
import uuid
import socket
import threading
import signal
import shutil
import tempfile
import subprocess
import resource
import requests
from pathlib import Path
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI()

# 访问密码：打开页面需输入；同时作为接口调用凭证（header: x-password）
ACCESS_PASSWORD = os.environ.get("JUDGE_PASSWORD", "102938")
# 管理后台密码：用于 /admin 后台登录（可通过环境变量 ADMIN_PASSWORD 覆盖，默认 fcz666）。
# 注意：密码以「加盐哈希」形式保存在内存中，不保留明文，登录时用恒定时间比较防时序攻击。
_PLAIN_ADMIN = os.environ.get("ADMIN_PASSWORD", "fcz666")
_ADMIN_SALT = secrets.token_bytes(16)
ADMIN_PASSWORD_HASH = hashlib.pbkdf2_hmac(
    "sha256", _PLAIN_ADMIN.encode("utf-8"), _ADMIN_SALT, 150000)
# 用完后丢弃明文引用，降低泄露风险
del _PLAIN_ADMIN
# 参观密码：仅可「查看」后台，不能进行任何写操作（禁用/删除/清理等）。
# 用于演示或只读巡查；可通过环境变量 TOUR_PASSWORD 修改。
TOUR_PASSWORD = os.environ.get("TOUR_PASSWORD", "666")
# 设备/登录记录数据库
DB_PATH = os.environ.get("JUDGE_DB", str(Path(__file__).with_name("judge.db")))

# ---- 判题参数 ----
TIME_LIMIT = 2.0          # 单组用例墙钟时间（秒）
CPU_LIMIT = 3             # 单进程 CPU 时间（秒）
MEM_LIMIT = 256           # 内存上限（MB，用于判定 MLE）
AS_LIMIT = 1024           # 地址空间硬上限（MB，防止内存耗尽型 DoS）
FSIZE_LIMIT = 16 * 1024 * 1024   # 可写文件大小上限（字节）
NOFILE_LIMIT = 64
NPROC_LIMIT = 64
COMPILE_TIME_LIMIT = 20   # 编译超时（秒）
MAX_CODE = 200 * 1024     # 代码大小上限
MAX_INPUT = 1024 * 1024   # 输入大小上限

NOBODY_UID = 65534

# ---- 大模型（LLM）配置：OpenAI 兼容接口，用于判题出错时生成中文解释 ----
# API Key 通过环境变量 LLM_API_KEY 提供（不写死在代码里）。
# 默认按 DeepSeek 配置；如需其它兼容端点，改 LLM_BASE_URL / LLM_MODEL 即可。
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.deepseek.com").rstrip("/")
LLM_MODEL = os.environ.get("LLM_MODEL", "deepseek-chat")
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "15"))
NOBODY_GID = 65534


_CLONE_NEWNET = 0x40000000  # Linux: 新建网络命名空间（断网）


def _unshare_net():
    """在子进程中创建独立网络命名空间，使程序无法访问网络。"""
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.unshare(_CLONE_NEWNET)
    except Exception:
        pass


def apply_limits():
    """在子进程中：设资源限制 -> 新会话 -> 断网 -> 降权（preexec_fn 调用）。"""
    for rlim, val in (
        (resource.RLIMIT_CPU, (CPU_LIMIT, CPU_LIMIT + 1)),
        (resource.RLIMIT_AS, (AS_LIMIT * 1024 * 1024, AS_LIMIT * 1024 * 1024)),
        (resource.RLIMIT_FSIZE, (FSIZE_LIMIT, FSIZE_LIMIT)),
        (resource.RLIMIT_NOFILE, (NOFILE_LIMIT, NOFILE_LIMIT)),
        (resource.RLIMIT_NPROC, (NPROC_LIMIT, NPROC_LIMIT)),
    ):
        try:
            resource.setrlimit(rlim, val)
        except Exception:
            pass
    try:
        os.setsid()  # 新会话，便于整体 kill 进程组（防死循环变孤儿）
    except Exception:
        pass
    _unshare_net()  # 断网（必须在降权前，以 root 执行）
    # 降权到 nobody，避免以 root 运行用户代码
    if os.getuid() == 0:
        try:
            os.setgid(NOBODY_GID)
            os.setuid(NOBODY_UID)
        except Exception:
            pass


def compile_cpp(workdir: str):
    """编译 main.cpp -> main，返回 (ok, error_text)。"""
    src = os.path.join(workdir, "main.cpp")
    binp = os.path.join(workdir, "main")
    cmd = ["g++", "-std=c++17", "-O2", "-Wall", "-o", binp, src]
    try:
        p = subprocess.run(cmd, cwd=workdir, capture_output=True,
                           text=True, timeout=COMPILE_TIME_LIMIT)
    except subprocess.TimeoutExpired:
        return False, "编译超时（代码可能过于复杂或触发模板展开死循环）。"
    if p.returncode != 0:
        return False, (p.stderr or p.stdout or "编译失败（无错误信息）。").strip()
    try:
        os.chmod(binp, 0o755)
    except Exception:
        pass
    return True, ""


def analyze_compile_errors(stderr: str):
    """解析 g++ 报错，提取行号并生成中文解释。

    返回 (error_lines: set[int], hints: list[(line, text)])
    """
    err_re = re.compile(r'main\.cpp:(\d+):(\d+):\s*(?:error|warning):\s*(.*)')
    error_lines = set()
    hints = []
    seen = set()
    for m in err_re.finditer(stderr or ""):
        line = int(m.group(1))
        msg = m.group(3).strip()
        error_lines.add(line)
        if msg in seen:
            continue
        seen.add(msg)
        hints.append((line, explain_gcc(msg)))
    return error_lines, hints


def explain_gcc(msg: str):
    """把单条 g++ 报错翻译成中文修改建议。"""
    m = msg
    # 兼容 ASCII 引号 ' 与 g++ 弯引号 ‘ ’（U+2018/U+2019）
    nm = re.search(r"['‘]([^'’]+)['’]\s+was not declared", m)
    if nm and nm.group(1) in ('cout', 'cin', 'endl', 'string', 'vector',
                               'map', 'set', 'pair', 'sort', 'stack', 'queue'):
        return (f"使用了标准库里的 '{nm.group(1)}'，但未引入命名空间。"
                f"请在代码开头加 `using namespace std;`，或写成 `std::{nm.group(1)}`。")
    if 'was not declared in this scope' in m:
        name = nm.group(1) if nm else '该标识符'
        return (f"'{name}' 未声明：可能拼写错误、未 #include 对应头文件，"
                f"或变量定义在使用的下方（C++ 需先定义后使用）。")
    if "expected ';' before" in m:
        return "前面某行缺少分号 `;`，请在报错位置上一行末尾补上 `;`。"
    if "expected '}'" in m or "expected ')'" in m or "expected ']'" in m:
        return ("括号不匹配：大括号 `{}`、圆括号 `()` 或方括号 `[]` 少写了右半边，"
                "请检查配对（尤其注意中文括号 `（）`).")
    if 'missing terminating' in m:
        return "字符串或字符的引号没有闭合（少了一个 `'` 或 `\"`）。"
    if 'stray' in m:
        return ("代码里混入了非法字符（如中文引号 `“”`、全角空格或不可见字符），"
                "请改用英文半角符号。")
    if 'no matching function' in m:
        return "函数调用参数不匹配：参数类型或个数与函数定义不一致。"
    if 'request for member' in m:
        return "成员访问方式错误：指针应用 `->`，对象用 `.`；或二者用反了。"
    if 'cannot convert' in m:
        return "类型不匹配：赋值/传参时左右两边类型不一致，可能需要强制转换或修改类型。"
    if 'redefinition' in m:
        return "重复定义：同一个变量或函数被定义了两次，请删除多余的定义。"
    if 'expected primary-expression' in m:
        return "语法错误：这里缺了一个表达式（可能是运算符、括号或分号位置不对）。"
    if 'too many arguments' in m:
        return "函数调用参数过多，请核对函数定义。"
    if 'too few arguments' in m:
        return "函数调用参数过少，请核对函数定义。"
    return f"编译错误：{m}"


def explain_ce(hints):
    if not hints:
        return "编译未通过，请查看上方的编译器错误信息。"
    lines = "、".join(f"第{ln}行" for ln in sorted({ln for ln, _ in hints}))
    head = f"编译未通过，问题出现在 {lines}：\n"
    body = "\n".join(f"· 第{ln}行：{h}" for ln, h in hints)
    return head + body


def explain_status(status: str, stderr: str = ""):
    """为非编译类状态生成中文解释。"""
    if status == "RE":
        if "Segmentation fault" in stderr:
            return ("运行时错误（段错误）：常见原因——空指针解引用、数组/vector 越界访问、"
                    "栈溢出（递归太深或在函数内开了过大的数组）。请检查下标是否越界、指针是否为空。")
        if "floating point" in stderr:
            return "运行时错误（浮点异常）：极可能是除以零，请检查分母是否可能为 0。"
        if "bad_alloc" in stderr:
            return ("运行时错误（内存分配失败）：可能开了过大的数组导致内存不足，"
                    "请减小规模或改用动态分配并判断是否分配成功。")
        if "Aborted" in stderr:
            return "运行时错误（Aborted）：可能是 assert 失败、主动调用了 abort()，或内存分配失败。"
        return "运行时错误：程序异常崩溃退出。常见原因包括数组越界、空指针、除以零等，请结合上方信息定位。"
    if status == "TLE":
        return ("超时（TLE）：程序在 2 秒内没有结束。可能原因——(1) 死循环，"
                "如 `while` 条件永远为真、循环变量没有更新；(2) 算法太慢、时间复杂度过高。"
                "请检查循环退出条件，或优化算法（如用 O(n) 代替 O(n²)）。")
    if status == "MLE":
        return ("内存超限（MLE）：程序使用的内存超过了 256MB 上限。"
                "请检查是否开了过大的数组/vector，或递归层数过深导致栈溢出。")
    if status == "WA":
        return ("答案错误（WA）：你的输出与期望不一致。请检查——(1) 算法逻辑是否正确；"
                "(2) 输出格式：是否多了/少了空格或换行；(3) 边界情况：n=0、负数、数据最大值；"
                "(4) 浮点精度（必要时用 `printf(\"%.xf\")` 或 `long double`）。")
    return ""


# ---- 大模型解释（判题出错时自动调用，并统计 Token 消耗） ----
def call_llm(system: str, user: str):
    """调用 OpenAI 兼容接口，返回 (回复文本, usage 字典)。
       未配置 LLM_API_KEY 或调用失败时返回 (None, None)，不影响判题。"""
    if not LLM_API_KEY:
        return None, None
    try:
        resp = requests.post(
            f"{LLM_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {LLM_API_KEY}",
                     "Content-Type": "application/json"},
            json={"model": LLM_MODEL, "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}],
                "temperature": 0.3, "max_tokens": 400},
            timeout=LLM_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        usage = data.get("usage", {}) or {}
        text = data["choices"][0]["message"]["content"]
        return text.strip(), {
            "prompt_tokens": int(usage.get("prompt_tokens", 0)),
            "completion_tokens": int(usage.get("completion_tokens", 0)),
            "total_tokens": int(usage.get("total_tokens", 0)),
        }
    except Exception:
        return None, None


def ai_explain_error(status: str, stderr: str, base_hint: str):
    """判题出错时生成更友好的中文解释，并把 Token 计入数据库。
       无 Key / 失败则回退到规则版 hint（返回 None）。"""
    system = ("你是 C++ 编程竞赛的辅导老师，用简洁中文帮初学者定位错误。"
              "结合编译器/运行器的报错与现有提示，给出最可能的原因和一条"
              "可操作的修改建议。不要写完整代码，不超过 4 句话。")
    user = (f"判题状态：{status}\n"
            f"运行器/编译器报错：\n{(stderr or '')[:1500]}\n"
            f"现有提示：{base_hint}\n"
            f"请给出中文解释与修改建议。")
    text, usage = call_llm(system, user)
    if text and usage:
        add_token_usage(usage.get("prompt_tokens", 0),
                        usage.get("completion_tokens", 0))
    return text



def descendants(pid: int):
    """递归收集进程树中的所有 pid（用于统计内存）。"""
    pids = [pid]
    try:
        with open(f"/proc/{pid}/task/{pid}/children") as f:
            for tok in f.read().split():
                pids.extend(descendants(int(tok)))
    except Exception:
        pass
    return pids


def run_binary(workdir: str, stdin_text: str):
    """运行已编译的 main，返回结构化结果（含峰值内存）。"""
    cmd = f'timeout -s KILL {TIME_LIMIT} ./main'
    t0 = time.perf_counter()
    try:
        p = subprocess.Popen(
            cmd, shell=True, cwd=workdir,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=apply_limits,
        )
    except Exception as e:
        return {"status": "RE", "stdout": "", "stderr": str(e),
                "time": 0, "memory": None}

    peak = [0]
    stop = [False]

    def monitor():
        while not stop[0] and p.poll() is None:
            for pid in descendants(p.pid):
                try:
                    with open(f"/proc/{pid}/status") as f:
                        for line in f:
                            if line.startswith("VmHWM:"):
                                kb = int(line.split()[1])
                                if kb > peak[0]:
                                    peak[0] = kb
                except Exception:
                    pass
            time.sleep(0.015)

    mt = threading.Thread(target=monitor, daemon=True)
    mt.start()
    try:
        out, err = p.communicate(input=stdin_text.encode("utf-8"),
                                 timeout=TIME_LIMIT + 3)
    except subprocess.TimeoutExpired:
        # 杀掉整个进程组，避免子进程（如死循环）变孤儿继续占用 CPU
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception:
            p.kill()
        try:
            out, err = p.communicate(timeout=2)
        except Exception:
            out, err = b"", b""
        stop[0] = True
        mt.join(timeout=1)
        wall = time.perf_counter() - t0
        return {"status": "TLE",
                "stdout": (out or b"").decode("utf-8", "ignore"),
                "stderr": ((err or b"").decode("utf-8", "ignore") +
                           f"\n[运行超时：超过 {TIME_LIMIT} 秒]").strip(),
                "time": round(wall, 3),
                "memory": (peak[0] / 1024 if peak[0] else None),
                "hint": explain_status("TLE")}

    stop[0] = True
    mt.join(timeout=1)
    wall = time.perf_counter() - t0
    maxrss = peak[0] / 1024 if peak[0] else None
    stdout = out.decode("utf-8", "ignore") if out else ""
    stderr = err.decode("utf-8", "ignore") if err else ""

    if p.returncode == 124 or (wall >= TIME_LIMIT and p.returncode != 0):
        return {"status": "TLE", "stdout": stdout,
                "stderr": stderr or f"[运行超时：超过 {TIME_LIMIT} 秒]",
                "time": TIME_LIMIT, "memory": maxrss,
                "hint": explain_status("TLE")}
    if p.returncode != 0:
        sig = f"（信号 {-p.returncode}）" if p.returncode < 0 else ""
        status = "RE"
        if maxrss is not None and maxrss >= MEM_LIMIT * 0.95:
            status = "MLE"
        return {"status": status, "stdout": stdout,
                "stderr": (stderr + f"\n[进程退出码 {p.returncode}{sig}]").strip(),
                "time": round(wall, 3), "memory": maxrss,
                "hint": explain_status(status, stderr)}
    if maxrss is not None and maxrss > MEM_LIMIT:
        return {"status": "MLE", "stdout": stdout, "stderr": stderr,
                "time": round(wall, 3), "memory": maxrss,
                "hint": explain_status("MLE")}
    return {"status": "AC", "stdout": stdout, "stderr": stderr,
            "time": round(wall, 3), "memory": maxrss, "hint": ""}


def judge_once(code: str, stdin: str):
    """编译一次并运行一组输入，返回结果；编译失败直接返回 CE。"""
    if len(code.encode("utf-8", "ignore")) > MAX_CODE:
        return {"status": "CE", "stdout": "", "stderr": "代码过长（超过大小限制）。",
                "time": 0, "memory": None}
    if len(stdin.encode("utf-8", "ignore")) > MAX_INPUT:
        return {"status": "RE", "stdout": "", "stderr": "输入过长（超过大小限制）。",
                "time": 0, "memory": None}
    workdir = tempfile.mkdtemp(prefix="judge_")
    src = os.path.join(workdir, "main.cpp")
    try:
        with open(src, "w", encoding="utf-8") as f:
            f.write(code)
        os.chmod(workdir, 0o777)  # 允许降权后的子进程写入临时文件
        ok, err = compile_cpp(workdir)
        if not ok:
            error_lines, hints = analyze_compile_errors(err)
            return {"status": "CE", "stdout": "", "stderr": err,
                    "time": 0, "memory": None,
                    "error_lines": sorted(error_lines),
                    "hint": explain_ce(hints)}
        return run_binary(workdir, stdin)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def judge_many(code: str, cases):
    """仅编译一次，对多组用例分别运行并比对期望输出。"""
    if len(code.encode("utf-8", "ignore")) > MAX_CODE:
        return [{"status": "CE", "stdout": "", "stderr": "代码过长（超过大小限制）。",
                 "time": 0, "memory": None, "passed": False, "expected": c.get("expected", "")}
                for c in cases]
    workdir = tempfile.mkdtemp(prefix="judge_")
    src = os.path.join(workdir, "main.cpp")
    try:
        with open(src, "w", encoding="utf-8") as f:
            f.write(code)
        os.chmod(workdir, 0o777)
        ok, err = compile_cpp(workdir)
        if not ok:
            error_lines, hints = analyze_compile_errors(err)
            return [{"status": "CE", "stdout": "", "stderr": err, "time": 0,
                     "memory": None, "passed": False, "expected": c.get("expected", ""),
                     "error_lines": sorted(error_lines), "hint": explain_ce(hints)}
                    for c in cases]
        results = []
        for c in cases:
            stdin = c.get("input", "")
            if len(stdin.encode("utf-8", "ignore")) > MAX_INPUT:
                results.append({"status": "RE", "stdout": "", "stderr": "输入过长。",
                                "time": 0, "memory": None, "passed": False,
                                "expected": c.get("expected", "")})
                continue
            r = run_binary(workdir, stdin)
            exp = (c.get("expected", "") or "").rstrip()
            got = (r.get("stdout", "") or "").rstrip()
            if r["status"] == "AC":
                r["passed"] = (exp == got)
                if r["passed"]:
                    r["hint"] = ""
                else:
                    r["status"] = "WA"
                    r["hint"] = explain_status("WA")
            else:
                r["passed"] = False
                r.setdefault("hint", "")
            r["expected"] = c.get("expected", "")
            results.append(r)
        return results
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# ---- 请求模型 ----
class RunReq(BaseModel):
    code: str
    stdin: str = ""


class Case(BaseModel):
    input: str = ""
    expected: str = ""


class JudgeReq(BaseModel):
    code: str
    cases: list[Case] = []


@app.get("/", response_class=HTMLResponse)
def index():
    html_path = Path(__file__).with_name("index.html")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.post("/api/run")
def api_run(req: RunReq, request: Request,
            x_password: str = Header(None), x_device_id: str = Header(None)):
    if x_password != ACCESS_PASSWORD:
        raise HTTPException(status_code=401, detail="密码错误")
    if is_banned(x_device_id, get_client_ip(request)):
        raise HTTPException(status_code=403, detail="该设备已被禁用，请联系管理员")
    r = judge_once(req.code, req.stdin)
    if r.get("status") not in ("AC", None):
        ai = ai_explain_error(r.get("status", ""), r.get("stderr", ""),
                               r.get("hint", ""))
        if ai:
            r["ai_hint"] = ai
    return r


@app.post("/api/judge")
def api_judge(req: JudgeReq, request: Request,
              x_password: str = Header(None), x_device_id: str = Header(None)):
    if x_password != ACCESS_PASSWORD:
        raise HTTPException(status_code=401, detail="密码错误")
    if is_banned(x_device_id, get_client_ip(request)):
        raise HTTPException(status_code=403, detail="该设备已被禁用，请联系管理员")
    cases = [{"input": c.input, "expected": c.expected} for c in req.cases]
    results = judge_many(req.code, cases)
    passed = sum(1 for r in results if r.get("passed"))
    # 出错时自动用 LLM 生成一次中文解释（取首个出错用例），Token 计入统计
    first_err = next((r for r in results
                      if r.get("status") not in ("AC", None)), None)
    if first_err:
        ai = ai_explain_error(first_err.get("status", ""),
                              first_err.get("stderr", ""),
                              first_err.get("hint", ""))
        if ai:
            first_err["ai_hint"] = ai
    return {"results": results, "summary": {"total": len(results), "passed": passed}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


# ============================================================
# 设备管理 + 后台：设备/登录记录、禁用、内存统计
# ============================================================
_db_lock = threading.Lock()


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _db_lock:
        c = _conn()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            ua TEXT, screen TEXT, lang TEXT, platform TEXT, tz TEXT,
            ip TEXT, label TEXT DEFAULT '',
            banned INTEGER NOT NULL DEFAULT 0,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT,
            ts TEXT NOT NULL,
            action TEXT,
            status TEXT,
            ip TEXT
        );
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """)
        c.commit()
        c.close()


def get_meta(key, default="0"):
    with _db_lock:
        c = _conn()
        row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        c.close()
    return row[0] if row else default


def set_meta(key, value):
    with _db_lock:
        c = _conn()
        c.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                  "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                  (key, str(value)))
        c.commit()
        c.close()


def add_token_usage(prompt_tokens: int, completion_tokens: int):
    """累计 LLM Token 消耗（总消耗 + 当日消耗，持久化到 meta 表）。"""
    total = prompt_tokens + completion_tokens
    if total <= 0:
        return
    today = _now()[:10]
    new_total = int(get_meta("token_total", "0")) + total
    set_meta("token_total", new_total)
    if get_meta("token_today_date", "") != today:
        set_meta("token_today_date", today)
        set_meta("token_today", 0)
    new_today = int(get_meta("token_today", "0")) + total
    set_meta("token_today", new_today)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_client_ip(request: Request):
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def register_device(device_id, ua, screen, lang, platform, tz, ip):
    now = _now()
    with _db_lock:
        c = _conn()
        exists = c.execute(
            "SELECT 1 FROM devices WHERE device_id=?", (device_id,)).fetchone()
        if exists:
            c.execute(
                "UPDATE devices SET last_seen=?, ip=?, ua=?, screen=?, lang=?, "
                "platform=?, tz=? WHERE device_id=?",
                (now, ip, ua, screen, lang, platform, tz, device_id))
        else:
            c.execute(
                "INSERT INTO devices(device_id,ua,screen,lang,platform,tz,ip,"
                "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?)",
                (device_id, ua, screen, lang, platform, tz, ip, now, now))
        c.execute(
            "INSERT INTO logs(device_id,ts,action,status,ip) VALUES(?,?,?,?,?)",
            (device_id, now, "login", "ok", ip))
        c.commit()
        c.close()


def is_banned(device_id, ip):
    with _db_lock:
        c = _conn()
        b = 0
        if device_id:
            r = c.execute("SELECT banned FROM devices WHERE device_id=?",
                          (device_id,)).fetchone()
            if r:
                b = r[0]
        ip_banned = c.execute(
            "SELECT 1 FROM devices WHERE banned=1 AND ip=?", (ip,)).fetchone() \
            is not None
        c.close()
    return bool(b) or ip_banned


def list_devices():
    with _db_lock:
        c = _conn()
        rows = c.execute(
            "SELECT device_id,ua,screen,lang,platform,tz,ip,label,banned,"
            "first_seen,last_seen FROM devices ORDER BY last_seen DESC").fetchall()
        c.close()
    keys = ["device_id", "ua", "screen", "lang", "platform", "tz", "ip",
            "label", "banned", "first_seen", "last_seen"]
    return [dict(zip(keys, r)) for r in rows]


def list_logs(limit=200):
    with _db_lock:
        c = _conn()
        rows = c.execute(
            "SELECT id,device_id,ts,action,status,ip FROM logs "
            "ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        c.close()
    keys = ["id", "device_id", "ts", "action", "status", "ip"]
    return [dict(zip(keys, r)) for r in rows]


def set_ban(device_id, banned):
    with _db_lock:
        c = _conn()
        c.execute("UPDATE devices SET banned=? WHERE device_id=?",
                  (1 if banned else 0, device_id))
        c.commit()
        c.close()


def delete_device(device_id):
    with _db_lock:
        c = _conn()
        c.execute("DELETE FROM devices WHERE device_id=?", (device_id,))
        c.execute("DELETE FROM logs WHERE device_id=?", (device_id,))
        c.commit()
        c.close()


def delete_log(log_id):
    with _db_lock:
        c = _conn()
        c.execute("DELETE FROM logs WHERE id=?", (log_id,))
        c.commit()
        c.close()


def _read_int(path):
    """读取 cgroup / proc 文件里的整数（字节），失败返回 None。"""
    try:
        with open(path) as f:
            v = f.read().strip()
        if v in ("", "max"):   # cgroup v2 未设上限时 memory.max 为 "max"
            return None
        return int(v)
    except Exception:
        return None


def get_memory():
    """返回容器/服务器自身的内存占用（优先 cgroup，避免读到宿主机总量）。"""
    # 1) cgroup v2（容器场景，最准确）
    limit = _read_int("/sys/fs/cgroup/memory.max")
    current = _read_int("/sys/fs/cgroup/memory.current")
    # 2) cgroup v1 回退
    if limit is None:
        limit = _read_int("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    if current is None:
        current = _read_int("/sys/fs/cgroup/memory/memory.usage_in_bytes")

    if limit and current is not None:
        used = current
        avail = max(limit - current, 0)
        percent = round(used / limit * 100, 1) if limit else 0
        return {"total_mb": limit // (1024 * 1024),
                "used_mb": used // (1024 * 1024),
                "avail_mb": avail // (1024 * 1024),
                "percent": percent}

    # 3) 兜底：读 /proc/meminfo（物理机场景）
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0].endswith(":"):
                    try:
                        info[parts[0][:-1]] = int(parts[1])
                    except Exception:
                        pass
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
        used = total - avail
        percent = round(used / total * 100, 1) if total else 0
        return {"total_mb": total // 1024, "used_mb": used // 1024,
                "avail_mb": avail // 1024, "percent": percent}
    except Exception:
        return {"total_mb": 0, "used_mb": 0, "avail_mb": 0, "percent": 0}


def get_top_procs(n=6):
    """扫描 /proc 取内存占用最高的若干进程（RSS，单位 MB）。"""
    rows = []
    try:
        page = os.sysconf("SC_PAGE_SIZE")
    except Exception:
        page = 4096
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/statm") as f:
                    parts = f.read().split()
                rss_kb = int(parts[1]) * page // 1024 if len(parts) > 1 else 0
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip() or "?"
            except Exception:
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    cmd = f.read().replace(b"\x00", b" ").strip().decode("utf-8", "ignore")
                cmd = cmd or comm
            except Exception:
                cmd = comm
            rows.append((rss_kb, cmd[:60]))
    except Exception:
        return []
    rows.sort(reverse=True)
    return [{"rss_mb": r // 1024, "cmd": c} for r, c in rows[:n]]


def clean_memory():
    """针对性清理：删除残留编译目录、回收过期日志、压实数据库空闲空间。
       只动「本服务留下的、可安全删除的」残留物，不做无意义的全局 drop_caches。
       返回每项清理的具体内容、释放大小与前后占用对比。"""
    import gc
    import glob

    def du_mb(path):
        try:
            total = 0
            for root, _, files in os.walk(path):
                for f in files:
                    try:
                        total += os.path.getsize(os.path.join(root, f))
                    except Exception:
                        pass
            return total / (1024 * 1024)
        except Exception:
            return 0.0

    before = get_memory()
    items = []          # 被清理的具体项（针对性，前端逐条展示）
    freed_mb = 0.0

    # 1) 残留编译临时目录：judge_*，超过 10 分钟视为残留，
    #    避免误删正在评测中的任务目录。
    tmp = tempfile.gettempdir()
    now = time.time()
    for d in glob.glob(os.path.join(tmp, "judge_*")):
        try:
            age = now - os.path.getmtime(d)
        except Exception:
            age = 1e9
        if age < 600:
            continue
        size = du_mb(d)
        shutil.rmtree(d, ignore_errors=True)
        if not os.path.exists(d):
            items.append({"name": os.path.basename(d), "freed_mb": round(size, 1)})
            freed_mb += size

    # 2) 过期日志（保留最近 30 天），并 VACUUM 回收被删除行占用的数据库空间。
    old_logs = 0
    try:
        with _db_lock:
            c = _conn()
            cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).strftime(
                "%Y-%m-%d")
            old_logs = c.execute(
                "SELECT COUNT(*) FROM logs WHERE ts < ?", (cutoff,)).fetchone()[0]
            if old_logs:
                c.execute("DELETE FROM logs WHERE ts < ?", (cutoff,))
                try:
                    c.execute("VACUUM")
                except Exception:
                    c.commit()
                else:
                    c.commit()
            c.close()
    except Exception:
        pass
    if old_logs:
        items.append({"name": "过期日志(>30天)", "count": old_logs, "freed_mb": 0.0})

    # 3) Python 垃圾回收：释放进程内未引用对象（含循环引用）。
    #    注意：gc 不会把 RSS 还给系统，但能清理悬挂引用，配合上面删文件才有效。
    gc.collect()

    after = get_memory()
    return {
        "before": before,
        "after": after,
        "freed_mb": round(freed_mb, 1),
        "items": items,
        "tmp_dirs_removed": sum(1 for i in items if i["name"].startswith("judge_")),
        "logs_removed": old_logs,
    }


def get_stats():
    mem = get_memory()
    today = _now()[:10]
    with _db_lock:
        c = _conn()
        total = c.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        banned = c.execute(
            "SELECT COUNT(*) FROM devices WHERE banned=1").fetchone()[0]
        logins_today = c.execute(
            "SELECT COUNT(*) FROM logs WHERE action='login' AND ts LIKE ?",
            (today + "%",)).fetchone()[0]
        total_logins = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        c.close()
    # Token 消耗：总消耗 + 当日消耗（跨天自动归零当日计数）
    tok_today = int(get_meta("token_today", "0")) \
        if get_meta("token_today_date", "") == today else 0
    tok_total = int(get_meta("token_total", "0"))
    return {"memory": mem, "top": get_top_procs(), "devices": total, "banned": banned,
            "logins_today": logins_today, "total_logins": total_logins,
            "token_total": tok_total, "token_today": tok_today}


_admin_tokens = {}   # token -> (过期时间戳, 角色: 'admin' | 'tour')
_admin_lock = threading.Lock()


def require_admin(x_admin_token: str = Header(None)) -> str:
    """校验管理员令牌，返回角色 'admin' 或 'tour'；无效/过期则 401。"""
    if not x_admin_token:
        raise HTTPException(status_code=401, detail="管理员未登录")
    with _admin_lock:
        item = _admin_tokens.get(x_admin_token)
    if not item or item[0] < time.time():
        raise HTTPException(status_code=401, detail="管理员未登录或已过期")
    return item[1]


def require_admin_write(x_admin_token: str = Header(None)):
    """写操作专用：必须是 admin 角色；参观(tour)模式返回 403。"""
    role = require_admin(x_admin_token)
    if role != "admin":
        raise HTTPException(status_code=403,
                            detail="参观模式仅可查看，不能进行任何操作")


# ---- 请求模型 ----
class DeviceRegisterReq(BaseModel):
    device_id: str
    ua: str = ""
    screen: str = ""
    lang: str = ""
    platform: str = ""
    tz: str = ""


class AdminLogin(BaseModel):
    password: str


class DeviceBan(BaseModel):
    device_id: str
    banned: bool


class DeviceDelete(BaseModel):
    device_id: str


class LogDelete(BaseModel):
    log_id: int


init_db()


@app.post("/api/device/register")
def api_register(req: DeviceRegisterReq, request: Request,
                 x_password: str = Header(None)):
    if x_password != ACCESS_PASSWORD:
        raise HTTPException(status_code=401, detail="密码错误")
    ip = get_client_ip(request)
    if is_banned(req.device_id, ip):
        raise HTTPException(status_code=403, detail="该设备已被禁用，请联系管理员")
    register_device(req.device_id, req.ua, req.screen, req.lang,
                    req.platform, req.tz, ip)
    return {"ok": True}


def check_admin_password(pw: str) -> bool:
    """以恒定时间比较提交密码的哈希与管理员哈希，避免时序攻击。"""
    cand = hashlib.pbkdf2_hmac("sha256", pw.strip().encode("utf-8"), _ADMIN_SALT, 150000)
    return hmac.compare_digest(cand, ADMIN_PASSWORD_HASH)


@app.post("/admin/login")
def admin_login(req: AdminLogin):
    # 先试管理员密码（哈希校验），再试参观密码（明文恒定时间比较）
    if check_admin_password(req.password):
        role = "admin"
    elif hmac.compare_digest(req.password.strip().encode("utf-8"),
                              TOUR_PASSWORD.strip().encode("utf-8")):
        role = "tour"
    else:
        raise HTTPException(status_code=401, detail="密码错误")
    token = uuid.uuid4().hex
    with _admin_lock:
        _admin_tokens[token] = (time.time() + 3600 * 12, role)
    return {"token": token, "role": role}


@app.get("/api/admin/stats")
def admin_stats(x_admin_token: str = Header(None)):
    role = require_admin(x_admin_token)
    d = get_stats()
    d["role"] = role
    return d


@app.post("/api/admin/memory/clean")
def admin_clean_mem(x_admin_token: str = Header(None)):
    require_admin_write(x_admin_token)
    return clean_memory()


@app.get("/api/admin/devices")
def admin_devices(x_admin_token: str = Header(None)):
    require_admin(x_admin_token)
    return {"devices": list_devices(), "logs": list_logs()}


@app.post("/api/admin/device/ban")
def admin_ban(req: DeviceBan, x_admin_token: str = Header(None)):
    require_admin_write(x_admin_token)
    set_ban(req.device_id, req.banned)
    return {"ok": True}


@app.post("/api/admin/device/delete")
def admin_del_device(req: DeviceDelete, x_admin_token: str = Header(None)):
    require_admin_write(x_admin_token)
    delete_device(req.device_id)
    return {"ok": True}


@app.post("/api/admin/log/delete")
def admin_del_log(req: LogDelete, x_admin_token: str = Header(None)):
    require_admin_write(x_admin_token)
    delete_log(req.log_id)
    return {"ok": True}


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    html_path = Path(__file__).with_name("admin.html")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))
