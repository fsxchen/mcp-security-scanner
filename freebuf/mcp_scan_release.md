# [工具发布] 你的 AI Agent 正在裸奔？mcp-scan 一键探测 Moltbot/ClawdBot 高危暴露与 MCP 漏洞

> **摘要**：随着 Anthropic 推出的 MCP (Model Context Protocol) 协议日益流行，自托管 AI Agent（如 Moltbot/ClawdBot）的数量呈爆发式增长。然而，"Insecure by Default" 的设计导致大量 Agent 的管理面板和 API Gateway 直接暴露在公网。本文将介绍一款开源安全工具 `mcp-security-scanner`，它不仅能对 MCP 协议进行 Fuzzing 测试，更能通过 mDNS 协议精准定位内网泄露的 AI 资产。

## 0x01 背景：AI Agent 的“裸奔”危机

最近，一个名为 **Moltbot** (前身 ClawdBot) 的开源项目在 GitHub 上爆火。它允许用户在本地部署一个能够控制浏览器、读写文件、操作 Shell 的全能 AI 助理。

然而，安全研究发现，Moltbot 存在致命的设计缺陷：
1.  **默认监听 0.0.0.0**：Web 面板直接绑定在所有网卡上。
2.  **Localhost 信任滥用**：如果在反向代理后配置不当，它会误认为请求来自本地从而**绕过身份验证**。
3.  **敏感信息明文存储**：OpenAI/Anthropic API Key、Telegram Token 等直接明文存盘。

一旦暴露在公网，攻击者无需密码即可接管 Web 控制台，窃取所有对话记录，甚至利用其 `exec` 能力实现 **RCE (远程代码执行)**。

为了应对这一威胁，我开发了 **mcp-security-scanner**。

## 0x02 工具介绍：mcp-security-scanner

`mcp-security-scanner` 是一个模块化的 Python 安全评估工具，专为 MCP 生态设计。它包含两个核心模块：

*   **Infrastructure Scanner (`moltbot` 模式)**：针对 AI Agent 基础设施的扫描，支持 TCP 指纹识别和 UDP mDNS 隐蔽探测。
*   **Protocol Auditor (`check` 模式)**：针对 MCP Server 代码的静态审计与动态 Fuzzing（支持 RCE/LFI/SSRF 验证及 TPA 投毒检测）。

**项目地址**：https://github.com/your-repo/mcp-security-scanner
**安装方式**：
```bash
git clone https://github.com/your-repo/mcp-security-scanner.git
cd mcp-security-scanner
pip install .
```

## 0x03 核心功能：Moltbot 暴露面测绘

这是该工具最亮眼的功能。不同于传统的端口扫描，`mcp-scan` 结合了 mDNS (Multicast DNS) 协议来确认目标。

Moltbot 在启动时，会通过 Bonjour/mDNS 广播自己的服务（`_clawdbot-gw._tcp`）。虽然这本该局限于局域网，但许多云服务器配置错误，导致 UDP 5353 端口对外开放，泄露了内网服务信息。

### 实战演示

假设我们在资产测绘中发现了一个可疑 IP `47.104.xxx.xxx`，直接使用工具进行扫描：

```bash
mcp-scan moltbot 47.104.xxx.xxx
```

**扫描结果分析：**

```text
[*] Starting Moltbot/ClawdBot Scan for: 47.104.xxx.xxx
[*] Probing http://47.104.xxx.xxx:8080...
[*] Probing http://47.104.xxx.xxx:18789...
[*] Probing 47.104.xxx.xxx:5353 via Unicast mDNS...

  [!] 🚨 LEAK DETECTED: Found ClawdBot/Moltbot via mDNS on 47.104.xxx.xxx:5353!
  [!] 🚨 FOUND MOLTBOT INSTANCE ON PORT 18789!
  [!] 💀 POTENTIAL AUTH BYPASS: Direct access to dashboard allowed.

============================================================
🔍 Moltbot/ClawdBot Scan Report
============================================================

🔴 [HIGH] mDNS Information Leak
   URL: udp://47.104.xxx.xxx:5353
   Details: Target leaking internal network info:
   Service Instance: _clawdbot-gw._tcp.local

☠️ [CRITICAL] Exposed Web Interface
   URL: http://47.104.xxx.xxx:18789
   Details: Web interface is accessible. Check for authentication bypass.
```

可以看到，工具成功利用了两个维度的特征：
1.  **UDP 5353 (mDNS)**: 捕获到了 `_clawdbot-gw._tcp.local` 的服务指纹，直接实锤了目标身份。
2.  **TCP 18789**: 发现 Gateway 端口直接开放，且存在 **Auth Bypass** 风险。

## 0x04 进阶功能：MCP 协议 Fuzzing 与 TPA 检测

除了扫描暴露的实例，`mcp-scan` 还能对 MCP Server 的源代码进行深度审计。

对于开发者来说，最担心的是工具被 LLM 错误调用导致被黑（如 Prompt Injection）。本工具引入了 **Tool Poisoning Attack (TPA)** 检测机制。

```bash
# 开启 Fuzzing 模式扫描 MCP Server
mcp-scan check --fuzz python my_server.py
```

它能检测出：
*   **TPA 攻击**: 识别工具描述中试图劫持 LLM 的指令（如 "Ignore previous instructions", "System Override"）。
*   **RCE/LFI 验证**: 发送安全的 Payload（如算术运算 `echo $((1+1))`）来区分代码执行漏洞和简单的文本回显，消除误报。

## 0x05 修复与防御建议

如果您发现自己的 Moltbot 实例被扫描出漏洞，请立即执行以下操作：

1.  **切断公网访问**：在云服务商的安全组（Security Group）中，立即封禁 TCP 18789, 8080 和 UDP 5353 端口。
2.  **轮换凭据**：假设您的 OpenAI/Anthropic Key 已经泄露，立即 Revoke 并重新生成。
3.  **内网穿透**：不要直接暴露 Agent，请使用 Tailscale 或 Cloudflare Tunnel 等 VPN 方案进行远程访问。
4.  **审查 MCP 工具**：使用 `mcp-scan` 检查您编写的自定义工具，确保没有开启 `exec` 等高危权限，并为敏感操作开启 `isUserApprovalRequired`（人机回环确认）。

## 0x06 总结

AI Agent 赋予了 LLM 接触真实世界的能力，但也打开了通往核心系统的后门。`mcp-security-scanner` 旨在为这一新兴领域提供基础的安全检测能力。欢迎安全研究人员和开发者试用并提交 PR。

---
*免责声明：本工具仅供安全研究和授权测试使用。严禁用于非法扫描和攻击，开发者不承担任何连带责任。*
