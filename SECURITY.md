# 安全政策

[English version](#english-version)

总控台会以当前 macOS/Windows 用户或选定 WSL2 发行版默认用户的权限执行用户保存的 shell 命令，并提供启动、停止和结束本地进程的接口。请把命令执行、身份校验、写接口授权、路径处理、配置完整性、Windows supervisor/命名管道、WSL helper/session 和敏感信息泄露问题视为高影响安全问题。

## 支持范围

项目仍处于 Preview / Alpha 阶段。安全修复优先面向默认分支和最新发布版本；旧版本是否继续支持会在对应发行说明中注明。尚未发布的本地开发提交不承诺兼容修复。

## 私下报告漏洞

请优先使用 GitHub 仓库 **Security → Report a vulnerability** 提交私密报告。公开仓库建立后，维护者必须先启用 GitHub Private Vulnerability Reporting，再对外发布版本。

如果私密报告入口暂不可用，请不要在公开 Issue、讨论区或 Pull Request 中披露漏洞细节。请通过仓库所有者 GitHub 个人资料中已经验证的联系方式，只发送“不含漏洞细节、请求建立私密通道”的简短消息；在私密通道确认前不要附带复现代码、日志、配置或路径。

一份有用的私密报告应包含：

- 受影响版本或 commit；
- 运行环境：macOS 与 Python 版本，或 Windows 10/11 build、x64 架构、是否为 PyInstaller 安装版；
- 受影响卡片的 `execution.environment`/Shell；如果是 WSL，请提供已脱敏的发行版名、WSL1/WSL2、helper 版本和发行版是否在运行；
- 影响范围和攻击前提；
- 最小化复现步骤；
- 预期行为与实际行为；
- 已完成脱敏的相关日志或请求；
- 你认为安全的修复方向（可选）。

## 必须脱敏的内容

不要提交下列原始数据：

- `~/Library/Application Support/总控台/config.json{,.bak}`；
- `~/Library/Logs/总控台/` 中的日志；
- `%LOCALAPPDATA%\总控台\` 中的配置、日志、`runtime/`、`supervisors/` 和用户图标；
- WSL 用户目录中 `.local/share/local-ops/` 下的 helper、session 元数据、Unix socket 路径和日志；
- 完整 shell 命令、个人工作目录、用户名和主目录路径；
- PID、Windows SID、进程创建时间、`instanceKey`、run/session token、token hash、命名管道或 Unix socket 名、boot ID、访问令牌、密钥或环境变量；
- 用户上传图标或其他不具备公开授权的文件。

请使用 `/Users/example/project`、`C:\Users\example\project`、`/home/example/project`、`SID_REDACTED`、`TOKEN_REDACTED` 等明确占位符，并在提交前复核截图和录屏。

## 项目安全边界

- HTTP 服务只应绑定 `127.0.0.1`，不应直接或间接暴露到局域网或公网。
- 本项目不是多用户权限系统，也不是远程管理面板。
- 只有受信任的本地用户才能添加和执行命令。
- 本地回环绑定不能替代 Host、Origin、控制令牌和受控进程完整身份校验。macOS 使用 UID/进程组/token；Windows 使用当前 SID、PID 创建时间、cwd/命令身份和端口；WSL 使用发行版 boot ID、UID、start ticks、cwd/命令哈希和 session/token。
- Windows 数据与 supervisor/托盘命名管道 DACL 应只允许当前 SID 和 SYSTEM，并拒绝远程命名管道客户端。无法证明 SID/创建时间时必须失败关闭。
- WSL helper/session 必须限于当前 Linux UID，Unix socket 权限为 0600 并验证 `SO_PEERCRED`、token hash、boot ID、start ticks/PGID。普通停止只发 SIGTERM，只有用户明确确认的强制操作才发 SIGKILL。
- 任何平台都不得仅凭相同端口或裸 PID 结束进程。Windows/WSL 破坏性 API 必须使用并重新验证有效 `instanceKey`。

修复准备公开前，维护者会尽量与报告者协调披露时间。请勿在修复可用前公开可直接利用的细节。

---

<a id="english-version"></a>

# Security Policy

[中文版](#安全政策)

Local Ops Console executes shell commands saved by the user with the privileges of the current macOS or Windows user, or the default user of a selected WSL2 distribution. It also provides interfaces for starting, stopping, and terminating local processes. Issues involving command execution, identity verification, authorization for write endpoints, path handling, configuration integrity, Windows supervisors or named pipes, WSL helpers or sessions, or the disclosure of sensitive information should be treated as high-impact security issues.

## Supported Versions

This project remains in Preview / Alpha. Security fixes prioritize the default branch and the latest released version. Continued support for older versions will be documented in the corresponding release notes. No compatibility fixes are promised for unpublished local development commits.

## Reporting a Vulnerability Privately

Please use **Security → Report a vulnerability** in the GitHub repository as the preferred channel for submitting a private report. Once the public repository has been established, maintainers must enable GitHub Private Vulnerability Reporting before publishing a release.

If private vulnerability reporting is temporarily unavailable, do not disclose vulnerability details in a public Issue, Discussion, or Pull Request. Use a verified contact method listed on the repository owner's GitHub profile to send only a brief message that contains no vulnerability details and requests the establishment of a private channel. Do not attach reproduction code, logs, configuration data, or paths until the private channel has been confirmed.

A useful private report should include:

- The affected version or commit;
- The environment: the macOS and Python versions, or the Windows 10/11 build, x64 architecture, and whether it is a version packaged with PyInstaller;
- The affected card's `execution.environment` and Shell; for WSL, include a sanitized distribution name, whether it is WSL1 or WSL2, the helper version, and whether the distribution was running;
- The scope of impact and prerequisites for exploitation;
- Minimal reproduction steps;
- The expected behavior and actual behavior;
- Relevant logs or requests after sanitization;
- A remediation approach that you believe is safe, if available.

## Information That Must Be Redacted

Do not submit any of the following in raw form:

- `~/Library/Application Support/总控台/config.json{,.bak}`;
- Logs under `~/Library/Logs/总控台/`;
- Configuration data, logs, `runtime/`, `supervisors/`, or user icons under `%LOCALAPPDATA%\总控台\`;
- Helpers, session metadata, Unix socket paths, or logs under `.local/share/local-ops/` in a WSL user's home directory;
- Complete shell commands, personal working directories, usernames, or home-directory paths;
- PIDs, Windows SIDs, process creation times, `instanceKey` values, run or session tokens, token hashes, named-pipe or Unix-socket names, boot IDs, access tokens, keys, or environment variables;
- User-uploaded icons or other files that you are not authorized to publish.

Use explicit placeholders such as `/Users/example/project`, `C:\Users\example\project`, `/home/example/project`, `SID_REDACTED`, and `TOKEN_REDACTED`. Review screenshots and screen recordings carefully before submitting them.

## Project Security Boundary

- The HTTP service should bind only to `127.0.0.1` and should not be exposed, directly or indirectly, to a local network or the public Internet.
- This project is not a multi-user access-control system or a remote administration panel.
- Only trusted local users may add and execute commands.
- Loopback binding does not replace validation of the Host, Origin, control token, and complete identity of a managed process. macOS uses the UID, process group, and token; Windows uses the current SID, PID creation time, working-directory and command identity, and port; WSL uses the distribution boot ID, UID, start ticks, working-directory and command hashes, and the session identity and token.
- The DACLs for Windows data and the supervisor and tray named pipes should allow only the current SID and SYSTEM; the named pipes should reject remote clients. If the SID or creation time cannot be proven, the operation must fail closed.
- WSL helpers and sessions must be restricted to the current Linux UID. Unix socket permissions must be `0600`, and `SO_PEERCRED`, the token hash, boot ID, start ticks, and PGID must be verified. A normal stop sends only SIGTERM; SIGKILL may be sent only for a force operation that the user has explicitly confirmed.
- No platform may terminate a process solely because it uses the same port or based on a bare PID. Destructive Windows and WSL APIs must use and revalidate a valid `instanceKey`.

Before a fix is made public, maintainers will make reasonable efforts to coordinate disclosure timing with the reporter. Do not publicly disclose directly exploitable details before a fix is available.
