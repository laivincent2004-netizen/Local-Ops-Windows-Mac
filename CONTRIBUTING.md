# 参与贡献

[English version](#english-version)

感谢你帮助改进总控台。项目仍处于 Preview / Alpha 阶段，优先接受范围清晰、可验证且不扩大安全边界的改动。

## 开始之前

1. 先搜索已有 Issue 和 Pull Request，避免重复工作。
2. 较大的功能、配置 schema 变化、进程管理策略或 UI 主题调整，请先开 Issue 说明动机、用户场景和兼容性影响。
3. 安全漏洞不要公开讨论，按 [`SECURITY.md`](SECURITY.md) 私下报告。
4. 不要提交本机 `data/`、`%LOCALAPPDATA%\总控台`、Application Support、Library Logs、WSL 用户目录的 helper/session/log 数据、个人路径、完整命令、SID、`instanceKey`、token、用户图标或未脱敏截图。

## 开发环境

### macOS

- macOS 12 或更高版本；
- Python 3.12；后端运行时仅使用标准库；
- Node.js，用于 JavaScript 语法/单元检查。

重新生成品牌/图标资源或运行对应工具时安装开发依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

### Windows x64

- Windows 10 22H2 或 Windows 11 x64；Windows ARM64 不在支持/打包范围；
- 源码开发使用 Python 3.12 x64 和 Node.js；Windows 发行构建固定为 CPython 3.12.10 x64（3.12 系列最后一个提供官方 Windows 二进制安装器的完整维护版本）；
- 源码运行、进程监控、托盘和打包依赖由 `requirements-windows.txt` 精确锁定。“Windows 安装版无需用户安装 Python”不等于“Windows 源码开发零依赖”。

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-windows.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
node --test tests/js/i18n.test.mjs tests/js/ports.test.mjs
```

Windows 安装包必须在 Windows x64 上构建，还需要 Inno Setup 6.7.3 与 Linux CI 产出的静态 x86_64 musl WSL helper/对应 SHA-256；不支持从 macOS 交叉生成 Windows 产物。打包命令与产物契约见 `README.md` 和 `packaging/windows/build.ps1`。

WSL2 端到端测试需要具备虚拟化的 Windows 10/11 x64 测试机；单元/协议测试不能代替真实 Ubuntu/Debian/无 glibc 发行版、NAT/mirrored 网络和发行版重启验收。

## 修改原则

- macOS 后端运行路径保持 Python 标准库实现；Windows 专属依赖只在 Windows 懒加载并锁定版本；前端保持原生 ES Modules、无 CDN、无构建。
- 不得削弱回环绑定、Host/Origin/控制令牌、macOS UID/进程组/token、Windows SID/PID 创建时间/Job/命名管道 DACL/HMAC，或 WSL boot ID/UID/start ticks/session token/0600 socket 等安全校验。
- 不得按端口直接结束未知进程；Windows/WSL 破坏性操作必须使用有签名 `instanceKey` 并立即重新校验完整身份，不得退化为裸 PID。
- 普通停止超时时必须保留运行身份并返回 `requiresForce`；只有用户明确二次确认才可强制结束已验证 Windows Job 或 WSL session。
- 配置变更必须有明确 `schemaVersion`、幂等迁移和升级测试。
- DOM 服务列表应按 `instanceKey` 原地更新，稳定隐藏/置顶仍使用 `key`，避免轮询造成整表闪烁。
- 危险操作必须有明确确认。
- 修改 `static/icons/*.svg` 后运行 `make generate-icons`，不要手改 `static/icons.js`。

## 素材与许可

新增或替换字体、Logo、App Icon、favicon、插画、照片、纹理、声音等素材时，Pull Request 必须同时：

1. 更新 [`ASSET_PROVENANCE.md`](ASSET_PROVENANCE.md)；
2. 记录来源、作者/生成方式、版本、修改过程、许可、SHA-256 和凭证位置；
3. 需要时更新 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 并随包加入许可原文；
4. 确认素材状态不是 `BLOCKED` 或 `TO_REPLACE`。

只有“网上可下载”“AI 生成”或“免费使用”的说明不足以证明可随开源项目再分发。

## 检查

提交前运行：

```bash
make check
```

涉及发行范围、许可证、静态资源或打包逻辑时，再运行：

```bash
make release-check
```

Pull Request 应说明：

- 改了什么、为什么；
- 用户可见影响和风险；
- 执行过的检查及结果；
- 必要的手工验收步骤；
- 是否影响配置、数据、进程生命周期、素材许可或发布范围。

## 变更记录

- 用户可感知的功能、修复、安全或兼容性变化必须写入
  [`CHANGELOG.md`](CHANGELOG.md) 的 `Unreleased`。
- 使用 `Added`、`Changed`、`Fixed`、`Removed` 或 `Security`
  描述用户结果，不记录实现步骤。
- 纯缓存清理、过期本地构建产物和不影响行为的内部重构不必写入；
  Pull Request 中应说明为什么不适用。
- 发布时将 `Unreleased` 中的内容移动到对应版本和发布日期，并重新保留空的
  `Unreleased` 章节。

## Commit 与 Pull Request

- 使用简洁、可追溯的 commit；不要使用占位邮箱或伪造作者身份。
- 一个 Pull Request 尽量只解决一个主题。
- 不重写他人的历史，不夹带无关格式化或生成文件。
- 如果 UI 有变化，提供不含个人路径和真实服务信息的脱敏截图。
- 贡献即表示你有权提交该内容，并同意项目按根目录 `LICENSE` 及对应素材许可分发。

所有参与者都应遵守 [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)。

---

<a id="english-version"></a>

# Contributing

[中文版](#参与贡献)

Thank you for helping improve Local Ops Console. The project is still in the Preview / Alpha stage. Priority is given to changes that have a clearly defined scope, can be verified, and do not expand the security boundary.

## Before You Begin

1. Search existing Issues and Pull Requests first to avoid duplicate work.
2. For larger features, configuration schema changes, process-management policy changes, or UI theme changes, open an Issue first and describe the motivation, user scenarios, and compatibility impact.
3. Do not discuss security vulnerabilities publicly. Report them privately according to [`SECURITY.md`](SECURITY.md).
4. Do not commit local `data/`, `%LOCALAPPDATA%\总控台`, Application Support, Library Logs, helper/session/log data from a WSL user directory, personal paths, full commands, SIDs, `instanceKey` values, tokens, user icons, or screenshots that have not been redacted.

## Development Environment

### macOS

- macOS 12 or later;
- Python 3.12; the backend uses only the standard library at runtime;
- Node.js, for JavaScript syntax and unit checks.

Install the development dependencies when regenerating brand/icon assets or running the corresponding tools:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

### Windows x64

- Windows 10 22H2 or Windows 11 x64; Windows ARM64 is outside the supported and packaging scope;
- Source development requires Python 3.12 x64 and Node.js. Windows release builds are fixed to CPython 3.12.10 x64, the final 3.12 full-maintenance release with official Windows binary installers;
- Dependencies for source execution, process monitoring, the system-tray host, and packaging are pinned exactly in `requirements-windows.txt`. The fact that users do not need to install Python for the Windows application does not mean that Windows source development has no dependencies.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-windows.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
node --test tests/js/i18n.test.mjs tests/js/ports.test.mjs
```

The Windows installer must be built on Windows x64. It also requires Inno Setup 6.7.3 and the static x86_64-musl WSL helper produced by Linux CI, together with its corresponding SHA-256 file. Cross-building Windows artifacts from macOS is not supported. See `README.md` and `packaging/windows/build.ps1` for the packaging commands and artifact contract.

WSL2 end-to-end testing requires a virtualized Windows 10/11 x64 test machine. Unit and protocol tests are not substitutes for acceptance testing with real Ubuntu, Debian, and non-glibc distributions, NAT and mirrored networking, and distribution restarts.

## Change Principles

- Keep the macOS backend runtime path implemented with the Python standard library. Windows-specific dependencies must be lazily loaded only on Windows and pinned to exact versions. Keep the frontend as native ES Modules with no CDN and no build step.
- Do not weaken loopback binding, Host/Origin/control-token checks, macOS UID/process-group/token checks, Windows SID/PID creation-time/Job/named-pipe DACL/HMAC checks, or WSL boot ID/UID/start ticks/session token/0600 socket checks.
- Never terminate an unknown process solely by port. Destructive Windows and WSL operations must use a signed `instanceKey` and immediately revalidate the complete identity; they must never fall back to a bare PID.
- If a normal stop times out, preserve the runtime identity and return `requiresForce`. Force termination of a verified Windows Job or WSL session is allowed only after explicit secondary confirmation from the user.
- Configuration changes must include an explicit `schemaVersion`, an idempotent migration, and upgrade tests.
- Update the DOM service list in place by `instanceKey`; continue to use `key` for stable hidden/pinned state and avoid redrawing the entire table during polling.
- Dangerous operations must require explicit confirmation.
- After modifying `static/icons/*.svg`, run `make generate-icons`. Do not edit `static/icons.js` manually.

## Assets and Licensing

When adding or replacing fonts, logos, app icons, favicons, illustrations, photographs, textures, sounds, or other assets, the Pull Request must also:

1. Update [`ASSET_PROVENANCE.md`](ASSET_PROVENANCE.md);
2. Record the source, author or generation method, version, modification process, license, SHA-256, and location of supporting evidence;
3. Update [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) when necessary and include the full license text in the distribution;
4. Confirm that the asset status is neither `BLOCKED` nor `TO_REPLACE`.

Statements such as “downloadable from the internet,” “AI-generated,” or “free to use” are not sufficient proof that an asset may be redistributed with an open-source project.

## Checks

Run the following before submitting:

```bash
make check
```

If the change affects the release scope, licensing, static assets, or packaging logic, also run:

```bash
make release-check
```

A Pull Request should explain:

- What changed and why;
- User-visible effects and risks;
- Which checks were run and their results;
- Any required manual acceptance steps;
- Whether the change affects configuration, data, process lifecycles, asset licensing, or the release scope.

## Changelog

- User-visible features, fixes, security changes, and compatibility changes must be added to the `Unreleased` section of [`CHANGELOG.md`](CHANGELOG.md).
- Use `Added`, `Changed`, `Fixed`, `Removed`, or `Security` to describe user outcomes rather than implementation steps.
- Pure cache cleanup, removal of stale local build artifacts, and internal refactoring that does not affect behavior do not require a changelog entry; explain in the Pull Request why the changelog does not apply.
- At release time, move the contents of `Unreleased` to the corresponding version and release date, then retain a new empty `Unreleased` section.

## Commits and Pull Requests

- Use concise, traceable commits. Do not use placeholder email addresses or falsify authorship.
- Keep each Pull Request focused on a single topic whenever possible.
- Do not rewrite another contributor's history or include unrelated formatting changes or generated files.
- If the UI changes, provide redacted screenshots that contain no personal paths or real service information.
- By contributing, you confirm that you have the right to submit the content and agree that the project may distribute it under the root `LICENSE` and any applicable asset licenses.

All participants are expected to follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
