# ⚡ C++ 在线判题（Online Judge）

一个**手机浏览器直接打开就能用**的 C++ 在线判题工具，类似洛谷「爱测试」：粘贴代码、填输入、一键运行，自动判断编译错误 / 运行错误 / 超时 / 内存超限 / 答案对错，并用中文告诉你错在哪、怎么改，出错行还会高亮。

> 作者 / 版权：© Asuna(fcz)

---

## ✨ 功能特性

- **手机端优先**：视口适配、16px 字体防聚焦缩放、大按钮、深色界面，iPhone Safari 体验良好。
- **两种模式**
  - **运行模式**：代码 + 标准输入 → 运行，显示输出与编译/运行信息。
  - **测试用例模式**：多组「输入 + 期望输出」逐组评测，汇总「通过 X / Y 组」。
- **六种判定状态**（均经自测）：`AC 通过` / `CE 编译错误` / `RE 运行错误` / `TLE 超时` / `MLE 内存超限` / `WA 答案错误`，并报告耗时与峰值内存。
- **中文错误提示**：编译错误指出第几行并给修改建议（如「加 `using namespace std`」、缺分号、中文引号混用等）；运行错误区分段错误/浮点异常/分配失败；超时/内存/答案错误各自给排查方向。
- **出错行高亮**：编译错误对应的行以红色背景标出，一眼定位。
- **访问密码**：打开需输入密码（默认 `102938`），接口侧同样校验，他人拿不到链接也跑不了。
- **设备管理后台**（`/admin`）：
  - 记录进入网站的设备（UA / 分辨率 / 语言 / 平台 / 时区 / IP / 访问时间）。
  - 可**禁用 / 解禁 / 删除设备**，禁用后该设备再运行会被拦截（`403`）。
  - 可逐条**删除登录记录**。
  - 显示**服务器内存占用**（优先读 cgroup，避免读到宿主机总量）、Top 进程具体占用，并支持**一键清理内存**。

---

## 🗂 项目结构

```
.
├── app.py            # FastAPI 判题后端（g++ 编译 + 沙箱运行 + 后台 API）
├── index.html         # 主站前端（纯前端，无外部依赖）
├── admin.html         # 管理后台页面（移动端适配）
├── requirements.txt   # Python 依赖
├── run.sh             # 启动脚本
├── Dockerfile         # 可选：加固部署
├── LICENSE            # MIT
└── .gitignore
```

---

## 🚀 本地运行

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动（默认 8000 端口）
bash run.sh
# 或： uvicorn app:app --host 0.0.0.0 --port 8000

# 3. 浏览器打开
#    主站：     http://localhost:8000/
#    管理后台： http://localhost:8000/admin
```

打开主站输入访问密码 `102938`；后台登录密码 `admin888`。

---

## ⚙️ 环境变量（可选）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `JUDGE_PASSWORD` | `102938` | 访问密码（主站 + 接口凭证） |
| `ADMIN_PASSWORD` | `admin888` | 管理后台登录密码 |
| `JUDGE_DB` | `./judge.db` | 设备/登录记录数据库路径（SQLite） |
| `PORT` | — | 若设置则监听该端口（部署脚本注入） |

示例：

```bash
JUDGE_PASSWORD=你的密码 ADMIN_PASSWORD=你的后台密码 uvicorn app:app --host 0.0.0.0 --port 8000
```

---

## 🔒 沙箱与安全

每次运行用户提交的 C++ 都会做隔离（详见 `app.py`）：

- 降权到 `nobody` 运行，非 root；
- **断网**：子进程内 `unshare(CLONE_NEWNET)` 新建网络命名空间；
- **超时**：单组 2s 墙钟，整体 `kill` 进程组（防死循环变孤儿）；
- **资源限制**：CPU 3s、内存 256MB（判定 MLE）/ 地址空间 1GB 硬上限、文件大小、打开文件数、进程数；
- 代码/输入大小上限，防滥用。

### 上线前建议加固

当前实现适合「自己/小范围使用」。对外公开前建议：

1. **改掉默认密码**，并给 `/admin` 与判题接口加更严格的鉴权 / 限流；
2. 用 **Docker**（`Dockerfile` 已提供）进一步限制逃逸：`--cap-drop=ALL --read-only --memory=...`；
3. 加 **seccomp** 系统调用过滤，仅允许必要 syscall；
4. 不用即下线，避免链接被陌生人滥用算力。

---

## 🐳 Docker 部署（加固）

```bash
docker build -t cpp-judge .
docker run -d --name cpp-judge \
  -p 8000:8000 \
  --cap-drop=ALL --security-opt=no-new-privileges --read-only \
  -e JUDGE_PASSWORD=你的密码 -e ADMIN_PASSWORD=你的后台密码 \
  cpp-judge
```

---

## 📌 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/run` | 运行单组（密码 `x-password`） |
| POST | `/api/judge` | 多组测试用例（密码 `x-password`） |
| POST | `/api/device/register` | 设备解锁上报（密码 `x-password`） |
| POST | `/admin/login` | 后台登录 |
| GET | `/api/admin/stats` | 概览 + 内存 + Top 进程（token） |
| GET | `/api/admin/devices` | 设备列表 + 登录记录（token） |
| POST | `/api/admin/device/ban` | 禁用/解禁设备（token） |
| POST | `/api/admin/device/delete` | 删除设备（token） |
| POST | `/api/admin/log/delete` | 删除登录记录（token） |
| POST | `/api/admin/memory/clean` | 清理内存（token） |
| GET | `/admin` | 后台页面 |

---

## 📄 许可证

[MIT](LICENSE) © Asuna(fcz)
