# Windsurf Login (Windsurf 账户管理)

一款功能强大的 VS Code 扩展，专为 Windsurf 用户设计，提供多账户管理、用量监控及环境配置重置等一站式解决方案。

## 🚀 主要功能

### 1. 账户管理
*   **多模式登录**: 支持通过 `Email/Password` 常规登录，或直接使用 `AccessToken` (sk-ws-xxx) 进行登录。
*   **批量添加**: 支持一键批量导入多个账户，提升效率。
*   **凭证自动刷新**: 内置 Auth 服务对接，自动检测 Token 过期并使用 Refresh Token 进行无感刷新。

### 2. 用量监控 (Usage Center)
*   **实时配额查询**: 深度解析 Windsurf 后端 Protobuf 协议，精准展示 `User Prompt Credits` 剩余用量。
*   **计划检测**: 自动识别 Free、Trial 或其他订阅方案。


### 3. 环境与安全
*   **本地 Token 读写**: 
    *   **深度解密**: 能够提取并解密 Windsurf 本地存储 (`state.vscdb`) 中的 Session 信息。
    *   **安全注入**: 支持将凭证加密后写回本地数据库，实现“强制登录”或账户持久化。
*   **机器 ID 重置**: 内置 `Machine ID Resetter`，支持一键重置 `machineid`。
    *   自动备份旧 ID。
    *   覆盖多处标识文件（`machineid`, `machineid.json`, `globalStorage`）。

## 🛠️ 核心逻辑说明

*   **安全加密**: 基于 Windows **DPAPI** (Data Protection API) 技术，通过 PowerShell 脚本与 Node.js `crypto` 模块协同工作，确保本地凭证解密与重写的安全性。
*   **数据库交互**: 集成 `sql.js` 引擎，非侵入式地读写 Windsurf 内部 SQLite 数据库状态。
*   **协议解析**: 手写轻量级 Protobuf 解析器，直接与 Windsurf 后端 API 通讯获取最新的账户配额状态。

## 📖 使用指南

1.  **侧边栏入口**: 安装后，在 VS Code 活动栏点击 **Windsurf Login** 图标。
2.  **添加账户**:
    *   输入账号密码进行登录。
    *   或者在底部的 Token 区域，输入 `sk-ws-` 开头的 AccessToken 并为其命名。
3.  **切换账户**: 点击列表中账户后的“切换”按钮。如果是 AccessToken 账户，系统会提示您重启 Windsurf 以使更改生效。
4.  **重置机器码**: 如遇到环境限制，点击侧边栏顶部的“重置机器码”按钮，重置后请务必重启编辑器。
5.  **查看详细日志**: 所有后台操作（解密、请求、写入）均可在 VS Code 输出面板的 `Windsurf Login` 通道中查看详情。

## 📂 项目结构

```text
src/
├── extension.ts          # 插件入口
├── loginViewProvider.ts  # Webview 界面逻辑与账户调度
├── localTokenReader.ts   # 本地 vscdb 数据库读取与解密 (DPAPI)
├── localTokenWriter.ts   # 本地数据库写入与凭证加密
├── machineIdResetter.ts  # 机器标识符重置工具
└── windsurfInjector.ts   # 核心命令注入与后端 API 通讯
```

## 🧑‍💻 关于作者

*   **作者**: kumaomao
*   **版本**: 1.0.1
*   **技术栈**: TypeScript, VS Code Extension API, sql.js, Windows DPAPI.

---

Made with ❤️ by kumaomao
