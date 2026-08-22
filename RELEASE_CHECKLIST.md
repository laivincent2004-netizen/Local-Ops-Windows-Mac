# 总控台发布核对表

每一个候选版本都复制一份本文档并逐项签字；完成后的副本归档到
`docs/releases/<version>-checklist.md` 或对应的 GitHub Release，根目录模板保持未勾选。
自动检查通过不等于完成人工验收。

## 1. 发布身份

- [ ] 发布版本：`VERSION` = `____________`
- [ ] 候选 commit：`____________`
- [ ] 发布范围已明确：个人备份 / 内部交付 / 公开发布 / 商业分发
- [ ] `CHANGELOG.md` 已将本次变更从 Unreleased 移入对应版本和日期。
- [ ] `VERSION`、macOS `Info.plist`、Windows Inno/PyInstaller `release-manifest.json`、发行包名、标签和发行说明的版本一致；supervisor 实现版本与版本化文件名一致，helper 包版本与 manifest/SBOM 一致，双方协议常量保持兼容。
- [ ] 根目录 MIT License 的版权主体与发布说明一致，发行负责人已确认其适用于本次项目自有代码和文档。
- [ ] commit 作者、提交者和签名均为真实可追溯身份，不含 `your-email@example.com` 等占位信息。
- [ ] 如果公开仓库名称、产品名或 Bundle ID 有变化，已在首个公开 Tag 前冻结并完成一致性核对。

## 2. 源码与自动检查

- [ ] Git 工作区干净，没有未审查的改动。
- [ ] `make release-check` 通过，完整输出已归档。
- [ ] 测试数量大于 0，失败与错误均为 0。
- [ ] Python、JavaScript、Bash、plist 和主题 JSON 语法检查通过。
- [ ] `static/icons.js` 与 `static/icons/*.svg` 同步。
- [ ] 所有引用的静态字体、图像、主题和模块都存在。
- [ ] `SECURITY.md`、`CONTRIBUTING.md`、`CODE_OF_CONDUCT.md` 和 `ASSET_PROVENANCE.md` 已通过复核并进入发行范围。
- [ ] GitHub Bug/Feature Issue 表单与 Pull Request 模板仍符合当前安全、隐私和素材门禁。
- [ ] 已人工复核从上一版本到当前 commit 的完整 diff。
- [ ] macOS CI 的 `make check`/release 可重现性检查通过，现有 macOS 测试未因 Windows 分支被跳过或弱化。
- [ ] Windows 10/11 x64 CI 安装 `requirements-windows.txt` 的精确版本后，全部 Python 和 JavaScript 测试通过；未打包源码模式与 PyInstaller 产物都有冒烟证据。
- [ ] Linux CI 用锁定 Rust 1.88.0 对 `x86_64-unknown-linux-musl` 运行 `cargo test --locked`，helper 为无 PT_INTERP/共享库依赖的静态 ELF64 x86-64，且 `.sha256` 在 Windows 打包前重新验证。

## 3. 安全与进程生命周期

- [ ] HTTP 服务仅绑定 `127.0.0.1`，不会因配置或启动方式变为局域网可访问。
- [ ] 写接口的 Host、Origin/获取站点来源与控制令牌防护已用自动测试覆盖。
- [ ] 错误 Host、跨站 Origin、缺失/错误令牌和非预期 Content-Type 不能触发任何写操作。
- [ ] 普通停止、忽略 SIGTERM、快速自然退出、启动失败和重启均已验收。
- [ ] 两个并发启动/停止/删除请求不会创建孤儿进程或覆盖新 token。
- [ ] 两个总控台实例不能同时写同一配置，或已证明跨进程锁/合并策略正确。
- [ ] 不会按端口误杀外部进程；macOS kill 验证当前 UID/受控身份，Windows/WSL 破坏性操作必须使用有效 `instanceKey` 并重新验证完整平台身份，不接受裸 PID。
- [ ] 配置、日志和运行目录使用最小化权限：macOS 为 0700/0600，Windows DACL 只允许当前 SID 和 SYSTEM，不对其他本机用户可读。
- [ ] `/api/health` 不执行 `ps/lsof`，并与 `/api/state` 一致返回当前 `VERSION`、`schemaVersion` 和降级原因。
- [ ] 缺失的工作目录、脚本或运行时会在启动前阻止运行；服务重启预检失败时旧进程保持运行。
- [ ] 任务 exit 0 / 130 / 其他非零 / 总控台中止分别显示成功 / 取消 / 失败 / 中止。
- [ ] 新端口发现首次载入与重连恢复保持静默，后续新端口可加入启动台、忽略隐藏或暂时关闭。
- [ ] 公开仓库已启用 GitHub Private Vulnerability Reporting，`SECURITY.md` 中的报告流程可实际使用。
- [ ] Issue/PR 模板会提醒用户脱敏，且普通公开 Issue 不承载可直接利用的安全细节。
- [ ] `GET /api/platform` 不启动已停止 WSL 发行版，正确返回 OS/架构/Shell/打包状态与 WSL1/WSL2 可用状态；恶意发行版名不能形成参数注入。

## 4. 数据、升级和回退

- [ ] 空配置首次启动能自动创建必要目录和文件。
- [ ] 在 Application Support/Library Logs 目标不存在时，旧项目 `data/` 的配置、图标和日志只复制一次，旧文件保留不删除。
- [ ] 已存在的新目标不被旧 `data/` 覆盖；显式设置 `CONSOLE_DATA_DIR` / `CONSOLE_LOG_DIR` 时对应自动迁移不发生。
- [ ] 从上一发布版本的真实备份升级成功，应用、图标、标记和主题未丢失；macOS 目录/文件仍为 0700/0600，Windows 运行数据仍是当前 SID + SYSTEM 私有 DACL。
- [ ] 损坏主配置能从备份恢复，且错误对用户可见。
- [ ] `config.json.bak` 是修改前的上一份良好配置；主配置与备份同时损坏时不会被空配置覆盖。
- [ ] 配置 schema 变更有明确版本、幂等迁移和 N-1 升级测试。
- [ ] 升级失败后能用已归档的旧程序和备份回退。
- [ ] 停止/卸载总控台时，已明确告知用户哪些子服务仍在运行。
- [ ] `schemaVersion=1` 的 macOS 备份幂等升级到 v2 `native+posix`；Windows 从 `%LOCALAPPDATA%\总控台` 创建全新 v2 配置，不扫描、导入或覆盖 macOS/项目内旧 `data/`。
- [ ] Windows 覆盖升级和卸载只停止托盘/HTTP 宿主，原生与 WSL2 受管应用继续运行，`%LOCALAPPDATA%\总控台` 数据和被引用的旧版 supervisor 保留；应用退出后监视器移除已无元数据引用的版本，后续 supervisor 启动也能兜底清理。

## 5. UI 与浏览器验收

- [ ] Ops 指挥台浅色/深色：360、600、900、1024、1280 和宽屏通过。
- [ ] 中间宽度下顶栏、导航块、总览和卡片不异常放大、裁切或重叠。
- [ ] 启动台和服务监控中的主操作在窄屏仍可见、可键盘达到。
- [ ] 添加、编辑、运行中停止、删除、拖拽、命令面板、日志和诊断的完整流程通过。
- [ ] 模态框/抽屉具备焦点限定和返回，Tab/Shift+Tab/Escape/方向键行为正确。
- [ ] 命令面板的 combobox/listbox/option 状态能被辅助技术理解。
- [ ] 断网、HTTP 500、慢请求和乱序响应不会让轮询永久停止或用旧日志覆盖当前应用。
- [ ] 用户向上滚动阅读日志时，自动刷新不会强制拉回底部。
- [ ] `prefers-reduced-motion` 与高对比度/键盘焦点验收通过。

## 6. macOS 安装包

- [ ] 在未安装开发工具、不存在旧 `data/` 的目标 macOS 版本上完成全新安装。
- [ ] 如果交付声称“独立 App”，发行包已捆绑 Python 和所有必要文件，单独复制 `.app` 也能运行。
- [ ] 如果仍是“完整项目目录”交付，README 和安装界面已明确说明 Python 3.12 和目录关系。
- [ ] 缺少或版本不符的 Python 会显示可理解、可操作的错误，不会静默退出。
- [ ] App 具有正确的 bundle id、版本、build 号、最低系统版本和图标。
- [ ] 对外分发包已使用 Developer ID 签名、提交公证并完成 Gatekeeper 验证。

## 7. Windows x64 安装、托盘与原生运行

- [ ] 分别在干净 Windows 10 22H2 (19045) x64 和 Windows 11 x64 上完成安装；无管理员权限、未安装 Python、未安装 WSL 的机器也能启动 Windows 原生功能，WSL 部分清晰降级。
- [ ] 安装器拒绝 ARM64/非 x64 目标，默认安装到 `%LOCALAPPDATA%\Programs\总控台`，`PrivilegesRequired=lowest`，登录启动选项默认不勾选且可正确安装/移除。
- [ ] 未签名内测包在安装前显示 `UNSIGNED_BUILD_NOTICE.txt`，发行说明包含 SmartScreen 风险与“先核对 SHA-256，再考虑仍要运行”指引；不声称已签名或已公证。
- [ ] 托盘菜单的打开、启动、停止、重启 HTTP 和退出全部通过；退出明确告知应用继续运行，当前 SID Mutex + 激活管道保证二次启动只唤醒已有实例。
- [ ] 托盘/HTTP 停止和重启不结束已运行应用；重启后能用持久元数据和完整身份重新识别它们。命名 Job 未启用 `KILL_ON_JOB_CLOSE`，旧 supervisor 可在安装目录被覆盖后继续服务。
- [ ] CMD、Windows PowerShell、Node、Python、Go、Rust 和 Docker Compose 的项目识别/启动通过，覆盖 Unicode、空格、驱动器号和长路径；`auto` 不会自动加 PowerShell `ExecutionPolicy Bypass`。
- [ ] 原生 service/task 的启动、快速退出、日志、成功/失败/取消/中止、重启、端口占用、认领、来源溯源和 favicon 全部通过。
- [ ] supervisor 命名管道只允许当前 SID/SYSTEM 且拒绝远程连接；伪造 token/HMAC/nonce、其他 SID、PID 重用、创建时间/cwd/命令变化和相同端口的无关进程均不能获得控制权。
- [ ] 普通停止实际发送 `CTRL_BREAK_EVENT` 并等待；子进程忽略时仅返回 `requiresForce`、保留运行身份且不自动 `TerminateJobObject`，用户二次确认后才强制结束已验证 Job。
- [ ] Windows 数据目录、配置、日志、运行元数据、supervisor 副本和控制通道都通过当前 SID + SYSTEM 私有 DACL 审计；打包运行时无法收紧权限必须失败关闭。

## 8. WSL2 功能与安全

- [ ] WSL1 在 `/api/platform` 和界面中显示为不可用并给出 `wsl --set-version <distro> 2`；监控只扫描已运行 WSL2，不启动已停止发行版。
- [ ] Ubuntu、Debian 和一个无 glibc 的最小 x86_64 WSL2 发行版通过；未安装 Python、`ps`、`lsof`、`sha256sum` 仍可完成 helper 安装/扫描/启停。
- [ ] helper 首次安装和版本升级使用随包 SHA-256，拒绝损坏二进制、哈希不匹配、符号链接、非当前 UID 目录和不安全权限，安装结果为 0700 且重读哈希一致。
- [ ] 多个运行中发行版并行扫描且分别超时；单个 helper/发行版故障只标记局部 degraded，Windows 原生和其他 WSL 扫描继续。
- [ ] Linux 路径、`\\wsl.localhost\<distro>\...`、Windows drive 与 `/mnt/<drive>` 双向映射通过 Unicode/空格案例；恶意发行版名、换行/NUL/参数注入被拒绝。
- [ ] service/task 在 WSL 默认用户 + `/bin/sh -lc` 下的启动、日志、成功/失败/取消/中止、端口、认领和来源标签通过；Windows 托盘/HTTP 重启后仍可验证 session 并恢复状态。
- [ ] Unix socket 属于当前 UID 且模式精确为 0600，伪造 token、错误 `SO_PEERCRED`、boot ID/start ticks/PGID 不匹配、他人 UID 和 PID 重用均不能发信号。持久 argv/元数据中无明文 token。
- [ ] 外部 WSL 进程控制必须完整匹配 boot ID、UID、PID、start ticks、cwd hash 和 raw cmdline hash，通过 pidfd 发信号；绝不按端口或裸 PID 杀进程。
- [ ] 普通停止只发 SIGTERM，超时仅返回 `requiresForce` 并保留 session；用户二次确认后才对已验证 session 发 SIGKILL。
- [ ] 发行版停止、重启、删除、boot ID 更换与 helper 损坏时不会误认领新进程，运行/最终状态或局部降级提示准确。
- [ ] Windows 11 NAT 与 mirrored 网络都通过；优先 localhost 转发，不可用时仅使用当前发行版发现地址。favicon 请求禁用代理并拒绝跨 host/port 重定向。

## 9. 许可、隐私与发行包内容

- [ ] `THIRD_PARTY_NOTICES.md` 中每一项的来源、版本、版权和许可与实际文件相符。
- [ ] `ASSET_PROVENANCE.md` 已覆盖发行范围内的全部字体、Logo、favicon、App Icon、插画和生成纹理，当前文件 SHA-256 与台账一致。
- [ ] 发行范围内不存在状态为 `BLOCKED` 或 `TO_REPLACE` 的素材；`REVIEW_REQUIRED` 项已有本次发布负责人的书面结论。
- [ ] 发行包只包含台账中已登记的字体；系统字体栈不以字体文件形式捆绑。
- [ ] Logo、favicon 与 App Icon 来自同一获准发布的品牌主源，原始设计、导出过程、小尺寸验收和授权范围均已归档。
- [ ] AI 生成插画已记录生成操作人、平台/模型、生成日期、原始输出、修改过程、适用条款和再分发依据；无法补齐者已替换。
- [ ] 发行包不包含旧 `data/`、任何用户 `%LOCALAPPDATA%`/Application Support/Library Logs/WSL home 数据、`tmp/`、`__pycache__/`、`.DS_Store`、本地虚拟环境或覆盖率文件。
- [ ] 发行包不包含个人绝对路径、shell 命令、PID、run token、日志或用户图标。
- [ ] README、Issue/PR 模板、示例 JSON、截图和录屏中的用户名、主目录和真实服务信息均已脱敏。
- [ ] 用 macOS 最终解压产物和 Windows 最终安装产物（而不是开发工作区）完成了各自验收。

## 10. 交付与回滚凭证

- [ ] 生成发行包 SHA-256：`________________________________________`
- [ ] 发行包字节数：`____________`
- [ ] Windows `SHA256SUMS.txt` 中每一项都重新计算一致；`release-manifest.json` 中 onedir 文件哈希一致，version/supervisor/helper/architecture/unsigned 字段与候选产物一致。
- [ ] Windows 发行附带 SPDX 2.3 SBOM、完整 Python 依赖清单和未签名内测说明；未把预留的 Authenticode 步骤误报为已完成。
- [ ] 最终解压/安装/启动/停止验收记录已归档。
- [ ] 上一版本产物、校验值和兼容数据备份仍可用。
- [ ] 已创建并验证版本 Tag，Tag 指向与发行包一致的 commit。
- [ ] 发行说明包含：主要变更、破坏性变更、升级步骤、已知问题、回退步骤和校验值。

## 签字

- 开发验收：`____________`  日期：`____________`
- 安全验收：`____________`  日期：`____________`
- 设计/UI 验收：`____________`  日期：`____________`
- 发布批准：`____________`  日期：`____________`
