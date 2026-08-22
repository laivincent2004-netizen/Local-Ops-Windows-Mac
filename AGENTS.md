# 总控台 (Console)

本地服务监控与快速启动控制台。同一套前端、配置、HTTP API 和业务逻辑支持 macOS 与 Windows：

- macOS 源码运行时仅需 Python 3.12 标准库和系统 `ps/lsof/osascript`；推荐双击 `总控台.app`，`start.command` 保留为终端调试入口。
- Windows 目标是 Windows 10 22H2 / Windows 11 x64，使用 PyInstaller `onedir + windowed` 和 Inno Setup per-user 安装包，终端用户不需安装 Python。系统托盘宿主托管 HTTP 线程并用默认浏览器打开界面。
- Windows 原生运行时依赖 `psutil/pywin32/pystray/Pillow`，只在 Windows 懒加载；前端始终为无框架、无 CDN、无构建的原生 ES Modules。
- Windows 可管理原生 CMD/Windows PowerShell 与 WSL2 x86_64 发行版。不支持 WSL1、Windows/WSL ARM64、内嵌 WebView 或 macOS 数据自动导入。

## 结构

- `server.py` — 平台中立的 HTTP/API、配置、应用、诊断、日志与项目识别业务；Windows 依赖必须条件导入。
- `console_platform/{base,common,macos,windows,wsl,wsl_host,windows_security}.py` — 平台适配层：运行目录、当前用户身份、端口/进程快照、Shell、路径、Windows DACL 和 WSL host/helper 协调。
- `supervisor.py` / `supervisor_client.py` / `supervisor_windows.py` — Windows 持久化、版本化 supervisor，命名 Job Object，只当前 SID 可用的命名管道，HMAC 请求/响应和原子运行元数据。
- `desktop/windows_host.py` — Windows 托盘宿主，当前用户 Mutex + ACL 命名管道单实例激活，HTTP 启动/停止/重启，退出确认和默认浏览器。停止托盘/HTTP 不结束受管应用。
- `wsl_helper/` — Rust 实现的静态 `x86_64-unknown-linux-musl` helper，直接读 `/proc`，执行验证安装、端口/进程扫描、session 启停与 pidfd 完整身份控制。协议见 `wsl_helper/PROTOCOL.md`。
- `packaging/windows/` — PyInstaller 托盘 `onedir/windowed` spec、独立 supervisor `onefile` spec、Inno Setup 按用户安装器、构建脚本和未签名内测说明。
- `static/index.html` / `static/app.js` / `static/js/{core,i18n,launchpad,services,overlays,ports,widgets}.js` / `static/icons.js` — 原生前端。`core.js` 承载 API/状态/主题/运行环境归一化，`i18n.js` 承载中英文字典、持久化语言偏好和安全插值；模块间用 `window.__poll` 共享轮询入口。
- 布局 v2：左侧 `.rail` 导航轨 + 顶栏 + 内容/右侧信息栏双列网格；≤1280px 侧栏下沉，≤900px 导航轨隐藏。结构样式集中在 `static/base.css` 末尾“布局 v2”段。
- `static/themes/` — 当前仅内置 `ops`。`{id}.css + {id}.json` 注册机制保留；产品无主题选择器，深/浅/跟随系统仍保留。
- `static/fonts/GeistMono-Variable.woff2` 是 vendored 数据/代码字体；中文和正文使用系统字体栈。`static/icons/*.svg` 为 vendored Lucide 源文件，`tools/gen_icons.py` 生成 `static/icons.js`，勿手改生成文件。
- `static/assets/` — `console-app-icon.png` 为主图，`brand-mark.png` 为顶栏标识；favicon/Apple Touch Icon/macOS `AppIcon.icns` 由 `tools/gen_brand_assets.py` 生成。
- `data/` — 旧版项目内数据，仅 macOS 在新目标不存在时首次复制迁移，保留不删；Windows 不扫描或导入。
- `.github/workflows/ci.yml` 为 macOS 项目/发行检查；`.github/workflows/windows-release.yml` 分别在 Linux 构建/验证静态 helper，在 Windows 运行测试并生成未签名安装包。

## 运行与目录

- macOS：`python3 server.py` 绑定 `127.0.0.1`，从 9600–9609 选择端口并打开浏览器。默认数据为 `~/Library/Application Support/总控台`，日志为 `~/Library/Logs/总控台`，目录/文件权限为 0700/0600。
- Windows 安装版：`总控台.exe` 托盘宿主嵌入同一 HTTP 服务，安装在 `%LOCALAPPDATA%\Programs\总控台`，数据、图标、日志、运行元数据和版本化 supervisor 在 `%LOCALAPPDATA%\总控台\`。相关 DACL 仅允许当前 SID 和 SYSTEM。安装版不将继承的 `CONSOLE_DATA_DIR/CONSOLE_LOG_DIR` 应用到任意路径。
- 源码运行可用 `CONSOLE_DATA_DIR` / `CONSOLE_LOG_DIR` 显式覆盖；值必须是非空绝对路径、专用子目录且非符号链接，不得是磁盘根、用户主目录或项目根。
- `/favicon.ico` 返回统一品牌图标。`GET /api/health` 是不执行进程/端口扫描的轻量检查，返回 `status/version/schemaVersion/degraded/issues/config`。

## API 契约（全部 JSON；icon 上传为原始字节）

### `GET /api/platform`

返回平台、架构、可用 Shell、是否打包运行以及 WSL 能力，且不为监控而启动已停止的 WSL 发行版：

```json
{
  "os": "windows", "arch": "amd64",
  "shells": ["auto", "cmd", "powershell"], "packaged": true,
  "wslAvailable": true,
  "wslDistros": [{"name": "Ubuntu", "version": 2, "state": "running", "running": true, "available": true, "default": true}]
}
```

WSL1 项保留在清单中，`available=false` 并返回升级提示。macOS 为 `native + posix`，无 WSL 列表。

### `GET /api/state` — 前端唯一轮询接口

```json
{
  "services": [{
    "key": "python:8000", "instanceKey": "ik1.<opaque>.<hmac>",
    "pid": 54252, "name": "python", "port": 8000,
    "cwd": "C:\\work\\demo", "project": "demo", "cmd": "py -3 app.py",
    "execution": {"environment": "native", "shell": "auto", "distro": null},
    "cpu": 0.3, "mem": 1.2, "uptimeSec": 7980,
    "group": "mine", "pinned": false, "hidden": false, "promoted": false,
    "origin": {"label": "Windows Terminal", "icon": "terminal"}
  }],
  "apps": [{
    "id": "a1b2c3d4", "name": "我的博客", "command": "npm run dev",
    "cwd": "C:\\work\\blog", "port": 3000, "kind": "service",
    "execution": {"environment": "native", "shell": "auto", "distro": null},
    "attached": false, "running": true, "pid": 1234,
    "instanceKey": "ik1.<opaque>.<hmac>", "uptimeSec": 120,
    "listening": true, "portOccupied": false, "ports": [3000],
    "lastExit": null, "health": {"status": "ok", "blocking": false, "issues": []}
  }],
  "watchedKeywords": ["ffmpeg"], "consolePort": 9600, "consolePid": 123,
  "version": "1.0.0", "schemaVersion": 2,
  "degraded": false, "degradedReasons": []
}
```

- `execution` 为 `native + posix` (macOS)、`native + auto|cmd|powershell` (Windows) 或 `wsl + posix + distro` (Windows/WSL2)。WSL 服务同时返回 `distro`。
- `instanceKey` 是服务实例的有签名不透明身份，包含环境、发行版、boot/create-time、PID、端口、所有者与 cwd/命令哈希等身份。前端 DOM 对账、认领和 Windows/WSL 破坏性操作均用它；不得解析或伪造。
- `key` 继续保持稳定的隐藏/置顶键；不得将 `key`、端口或裸 PID 当作进程杀死权限。
- `lastExit` 为 `succeeded` (0) / `canceled` (130) / `failed` (其他自然退出) / `stopped` (总控台中止)。旧数据可只有 `code/at`，API 兼容推导但不改写磁盘。
- `health` 为只读检查，返回 `ok|error|unknown`、`blocking` 与 issues。明确缺失 cwd/脚本/运行时会阻止启动；复杂动态 Shell 命令为 unknown 且不执行。
- `kind` 为 `service` 或 `task`；task 强制 `port=null`。`running` 只表示通过当前平台完整身份校验的受控运行时，不表示“端口上有任意监听者”。
- `attached` 表示用户明确认领的外部服务。认领与重新关联必须验证完整平台身份，不得仅按端口。
- `listening` 是受控运行时是否监听配置端口；`portOccupied` 是否被其他进程占用。多张停止卡片可保存相同开发端口；`portConflict/portConflictApps` 仅为旧前端兼容字段。
- 服务监控排除总控台自身和其他用户。单个 WSL 发行版扫描故障只写入局部 `degradedReasons`，不阻塞 Windows 原生扫描。
- `origin` 沿 PPID 链（≤12 层）识别 AI 助手、编辑器、终端、包管理器、总控台和 WSL 发行版；只用于展示，不影响启停授权。

### 服务操作

- `POST /api/kill`：macOS/legacy 为 `{pid, force?}`；Windows/WSL 必须为 `{instanceKey, force?}`。Windows 外部进程的普通停止不能证明可安全时返回 `requiresForce`；WSL 普通停止发 SIGTERM，只有第二次明确 `force=true` 才发 SIGKILL。
- `POST /api/services/flag` `{key, flag: "hidden"|"pinned"|"promoted", value: bool}`。
- `POST /api/watch` `{keyword, action: "add"|"remove"}`。

### 启动台应用

- `POST /api/apps` 接受 `name/command/cwd?/port?/emoji?/glyph?/kind?/execution?`。Windows/WSL 从监控创建必须携带 `attachInstanceKey` (兼容别名 `instanceKey`)，旧 `attachPid` 在 Windows 被拒绝；macOS 仍保留 `attachPid` 兼容。后端必须先验证身份再原子创建和认领，失败不得留下半成品卡片。
- `POST /api/pick` `{what: "dir"|"script", execution?, language?:"zh"|"en"}` 使用当前平台原生对话框，标题和文件类型随界面语言切换；WSL 路径需输入 Linux/UNC 路径。取消返回 `{ok:false,canceled:true}` 而非错误，旧客户端未传语言时默认中文。
- `POST /api/project/detect` `{cwd, execution?}` 只读项目根中不超过 2MB 的已知文件，不执行项目代码、不安装依赖、不递归扫描。按环境生成 macOS POSIX、Windows `py -3`/PowerShell/CMD 或 WSL POSIX 候选。
- `POST /api/apps/reorder` `{ids:[...]}` 使用稳定排序，服务/任务两区独立拖拽。
- `PUT /api/apps/{id}` 是部分更新；运行中修改 command/cwd/port/kind/execution 需要先停止。API 保留 `stopBeforeUpdate:true` 原子停止更新能力，但前端默认流程是保留草稿、单独停止、再普通保存。
- `DELETE /api/apps/{id}` 先安全停止再删除卡片、图标和日志。
- `POST /api/apps/{id}/start|restart` 启动前复查配置健康与实际端口占用。重启预检失败不先停止仍正常的旧服务。task 启动立即返回，快速成功不得误报为启动失败。
- `POST /api/apps/{id}/stop` 读取 `{force?:bool}`。普通停止超时必须保留运行身份并返回 `requiresForce:true`；前端只能在二次明确确认后重试 `force:true`。
- `POST /api/apps/{id}/diagnose` 合并健康检查、依赖/模块缺失、npm script、端口、权限、pip 和退出码本地规则，不调外部 AI。
- `POST /api/apps/{id}/attach`：Windows/WSL 为 `{instanceKey}`，macOS 为 `{pid}`。只允许当前用户、配置端口真实监听、cwd/命令身份匹配且未被其他卡片认领的 service。
- `POST/DELETE /api/apps/{id}/icon`、`POST /api/apps/{id}/favicon` 和 `GET /api/apps/{id}/logs?tail=300` 保留。上传 icon 优先级高于 glyph/favicon/首字；favicon 解析首页 icon 并回退 `/favicon.ico`；日志从文件尾有界读取。WSL favicon 只能访问刚发现的发行版主机+端口，禁止代理和跨端点重定向。

### 总控台自身

- `POST /api/console/restart` / `stop` 只控制 HTTP 服务，不停止已启动应用。macOS 使用独立 helper 重启；Windows 托盘宿主在进程内重启 HTTP 线程并优先复用原端口。
- `POST /api/ui/theme` `{theme}` 验证已注册主题后原子写入配置；目前唯一产品主题为 `ops`。
- 静态文件映射到 `static/`，`/icons/*` 映射用户图标目录；`realpath/commonpath` 必须防止路径穿越和符号链接逃逸。

## 后端实现要点

### 通用安全与状态

- 配置读写有线程锁，临时文件 + `os.replace` 原子落盘，`.bak` 保留修改前的上一份良好版本。主/备配置都不可读时进入只读保护，不用空配置覆盖。
- 保留回环绑定、Host/Origin/Cookie 令牌校验、CSP、请求大小限制、路径穿越防护和当前用户边界。
- 所有破坏性进程操作都必须完整校验身份。任何平台都不得按配置端口杀进程；Windows/WSL 不得退化为裸 PID。
- 任务取消协议：自然 exit 0=成功，130=脚本内用户取消，其他=失败；总控台按钮中止=`stopped`。不从日志文字猜状态。
- 单日志超过 10MB 时 copy-truncate，保留 3 份轮转备份；API 从文件尾分块读取，不将整份日志载入内存。
- HTTP keep-alive 连接上，每个 POST 必须完整读取或丢弃 body。新增不读 JSON/raw body 的 POST 路由必须调 `discard_body()`，否则残留 `{}` 会污染同一连接的下一个 method。`/stop` 已读取 `{force}`，不得改回盲目丢弃。
- 项目识别仅读根目录已知文件，显式 CLI 端口优先于框架默认值。

### macOS

- 端口扫描使用 `lsof -iTCP -sTCP:LISTEN -P -n`，按 `(pid,port)` 去重 IPv4/IPv6；进程详情用批量 `ps`，cwd 用 `lsof -d cwd`，只保留当前 UID。`etime` 解析 `[[dd-]hh:]mm:ss`。
- 分组优先级保持：用户 promoted → 开发进程关键词 → `.app/Contents`/system/containers 背景 → 默认 mine。开发关键词只匹配 name，不匹配 args。
- 关注进程用全局 `ps` 快照，args 小写包含关键词，排除自身及 `ps/lsof`。
- 每次启动生成 `runToken`，常驻外层 shell 持有标记并等待内层命令/后台作业。新运行时使用 PGID + UID + token；升级前无 token 运行时仅在 PID+端口+UID+真实 cwd 全部匹配时兼容。
- 停止只对验证后的进程组发 SIGTERM；应用可共享配置端口，只在真实启动时遇到监听占用才阻止。
- Finder/LSUIElement 不读 shell 配置；子应用 PATH 必须补入 `~/.local/bin`、Volta/Bun/pnpm、NVM/fnm、Homebrew 和系统 bin。

### Windows 原生

- `psutil` 提供 TCP 监听、PID/PPID、CPU/内存、cwd、创建时间和命令行。当前用户的安全身份是 SID，兼容数值 `uid` 不得用于破坏性授权。
- 受管应用由独立、版本化 supervisor 启动。打包运行时先对随包 supervisor 执行 SHA-256 证明，再原子复制到私有数据目录。正在运行的旧版 supervisor 保留；运行时退出后，退出监视器扫描元数据并移除未引用版本，后续 supervisor 启动时也会再扫描兜底。
- supervisor 使用隐藏控制台、新进程组和可重新打开的命名 Job Object；禁止 `KILL_ON_JOB_CLOSE`，所以托盘/HTTP/更新器退出不会结束应用。
- 命名管道 DACL 只允许当前 SID 和 SYSTEM，拒绝远程客户端。每个 status/stop/force-stop 都校验 owner SID、supervisor PID 创建时间、run ID、token HMAC、nonce/时间和已签名响应；元数据原子写入私有 `runtime/`。
- 普通停止用可丢弃的 signal helper 附加到子进程控制台并发 `CTRL_BREAK_EVENT`，等待约 5 秒。超时返回 `requiresForce` 并保留身份；只有明确强制操作才 `TerminateJobObject`。
- `auto` 将普通命令交给 `cmd.exe /d /s /c`，以 `.ps1` 开头的命令交给 Windows PowerShell；用户可选 `cmd`/`powershell`。禁止自动加 `-ExecutionPolicy Bypass`。
- 外部进程认领/结束立即复查 SID、PID 创建时间、端口、cwd 和命令哈希。无法证明安全的普通结束返回 `requiresForce`，不退化为按端口或裸 PID。

### WSL2

- 用 `wsl.exe --list --verbose` 列出安装的发行版，再单独获取 running 集合以避免依赖本地化 STATE 文字。监控只并行扫描已运行 WSL2，每个发行版独立超时/降级；只有用户明确启动卡片才可激活已停止发行版。
- 随包 helper 必须是静态 ELF64 x86-64，Windows 打包前重新核验 SHA-256/ELF header；helper `install` 路径必须属于当前 Linux UID，禁止符号链接，以 0700 原子安装并二次哈希。
- helper 直接读 `/proc`，不依赖发行版 Python/`ps`/`lsof`。扫描仅返回 helper 当前 UID，进程身份包含 boot ID、PID/PPID/PGID/SID、UID、start ticks、cwd hash 和 raw cmdline hash。
- 命令用发行版默认用户的 `/bin/sh -lc`，helper 创建独立 setsid/process group session。token 通过私有 pipe/stdin 传入，持久 argv/元数据不存明文，只存 SHA-256。Unix socket 必须是当前 UID + 0600，每次控制校验 `SO_PEERCRED`、token hash、boot ID、start ticks 和 PGID。
- session 普通停止对完整身份进程组发 SIGTERM；超时保留运行身份并要求强制确认；只有 force-stop 发 SIGKILL。外部 WSL 进程使用 pidfd 并重读 UID/boot/start/cwd/cmd 所有字段后发信号，防止 PID 重用。
- Windows supervisor 保存 WSL 日志和结果；总控台重启后同时验证 Windows 元数据、发行版 boot ID、Linux session/token。发行版停止/重启使旧 boot 身份失效，不得误认领新进程。
- 路径支持 Linux 绝对路径、`\\wsl.localhost\<distro>\...` 与 `/mnt/<drive>`/Windows drive 映射；发行版名必须经严格验证，禁止控制字符/参数注入。
- WSL 端点优先 Windows localhost 转发，不可用时使用 helper 从 `/proc` 获取的当前发行版地址。favicon 禁用代理并拒绝跨 host/port 重定向。

## 配置 schema v2

```json
{
  "schemaVersion": 2,
  "apps": [{
    "id": "8位hex", "name": "", "command": "", "cwd": null,
    "port": null, "kind": "service", "glyph": null, "icon": null,
    "favicon": null,
    "execution": {"environment": "native", "shell": "auto", "distro": null},
    "lastPid": null, "lastPgid": null, "runToken": null,
    "instanceKey": null, "processIdentity": null,
    "attached": false, "lastExit": null, "createdAt": 0
  }],
  "hidden": ["name:port"], "pinned": ["name:port"], "promoted": ["name:port"],
  "watchedKeywords": [], "uiTheme": "ops"
}
```

- macOS v1→v2 迁移为 `native + posix`，显式、幂等。Windows 新建配置默认 `native + auto`，不导入 Mac 配置。
- 合法组合只有 macOS `native+posix`、Windows `native+auto|cmd|powershell`、WSL `wsl+posix+非空 distro`。native 不得携带 distro，WSL 不得使用 Windows Shell。
- 高于当前支持版本的 schema 必须失败并保护原文件，不得静默降级。

## 前端要求

- 中英双语 UI，默认中文；顶栏 `EN | 中` 控件只在本地切换并将偏好保存为 `localStorage console-language`，不得为切换语言额外请求 API。单页启动台/服务监控双视图每 2s 轮询 `/api/state`；启动时先获取 `/api/platform`，Windows 显示环境/Shell/WSL 发行版，macOS 隐藏这些控件。用户名称、命令、路径和日志不得翻译，只有前端文案与明确列入安全白名单的后端固定标签可翻译。
- 选择工作区后按 `execution` 调用项目识别，候选完成前不得保存；保留“选择脚本”和手动输入。WSL 路径支持 Linux/UNC/drive 映射。
- 运行中编辑时立即显示“停止服务/中止任务”，停止不得关闭面板或清空草稿；普通停止返回 `requiresForce` 时显示二次强制确认，不得自动强杀。
- task 运行中显示实时耗时与“中止”，结束显示成功/取消/失败/中止、距今时间与耗时；失败突出日志，首次载入旧历史不重复通知。
- 停止卡片的阻断健康问题需显示第一项原因、禁用启动并开放诊断；运行中的停止/中止不得被健康问题禁用。
- 新端口发现仅在当前页面会话连续轮询期间提醒新 mine 实例；首次载入、断线/后台/降级/重启恢复静默建基线。
- Windows/WSL “加入启动台”必须传 `attachInstanceKey`，macOS 可传 `attachPid`；创建/认领失败不留卡片，成功后直接显示运行中。
- 服务 DOM 按 `instanceKey` 原地对账，禁止整列表重绘闪烁；fetch 失败显示断连横幅。
- 深/浅色跟随系统 + 手动切换（`localStorage console-theme`），单一 Ops 指挥台主题，系统中文字体栈 + Geist Mono，顶栏品牌图为 `static/assets/brand-mark.png`，UI 零 emoji。
- 保留入场 stagger、hover、模态/抽屉、按键回弹，并完整支持 `prefers-reduced-motion`、高对比度、键盘焦点与窄屏。
- 结束进程、强制停止、删除应用等危险操作必须明确确认。

## Windows 打包与测试

- `requirements-windows.txt` 必须使用精确版本。Windows 构建必须在 Python 3.12 x64 的干净 venv 中安装锁定依赖，不可从 macOS 交叉构建。
- Linux CI 用 Rust 1.88.0 + `x86_64-unknown-linux-musl` 运行 `cargo test --locked`、生成 helper，并用 ELF/readelf 证明无 PT_INTERP/共享库依赖，输出 `.sha256`。
- Windows CI 先运行 `python -m unittest discover -s tests -p "test_*.py" -v` 和 `node --test tests/js/i18n.test.mjs tests/js/ports.test.mjs`，再下载已验证 helper 运行：

  ```powershell
  .\packaging\windows\build.ps1 `
    -WslHelper .\dist\wsl-helper-x86_64 `
    -WslHelperSha256 .\dist\wsl-helper-x86_64.sha256
  ```

- 构建必须生成 `总控台.exe` onedir、`_internal/supervisors/console-supervisor-<version>.exe{,.sha256}`、`_internal/wsl/wsl-helper-x86_64{,.sha256}`、Inno Setup per-user installer、`release-manifest.json`、`SHA256SUMS.txt`、SPDX 2.3 SBOM、完整 Python 依赖清单和 `UNSIGNED_BUILD_NOTICE.txt`。
- Inno Setup 默认 `%LOCALAPPDATA%\Programs\总控台`、`PrivilegesRequired=lowest`、x64 only、最低 build 19045；登录启动默认不勾选。覆盖升级/卸载只请求托盘/HTTP 退出，已运行应用和 `%LOCALAPPDATA%\总控台` 用户数据保留。
- 首版是未签名内测包，必须绑定 SmartScreen 提示与 SHA-256 核验说明。稳定公开发布前需在构建脚本预留点加 Authenticode 签名/验签，然后重新生成 manifest 和 SHA-256。
- WSL2 端到端需在具备虚拟化的 Windows 10/11 x64 测试机完成，覆盖 Ubuntu、Debian、无 glibc 最小发行版、NAT/mirrored 网络、发行版停止/重启/删除、helper 损坏/升级、PID 重用、跨用户、伪造 token 和 socket 权限。
- 现有 macOS `make check` / `make release-check` / `.app` 和发行流程不得回退；Windows 平台分支不得弱化 macOS POSIX 安全测试。
