# 警惕 AI 的“越狱”手脚：基于 MCP 协议的红队攻防实战与工具开源

## 前言：当 AI 拥有了“手脚”

2024年底，Anthropic 发布的 **Model Context Protocol (MCP)** 彻底改变了 AI Agent 的开发范式。它让 Claude/DeepSeek 这样的大模型可以标准化地连接本地文件、数据库甚至命令行。

但是，作为一名安全研究人员，我看到了巨大的风险：**MCP 本质上是把操作系统的权限“拱手相让”给了 AI。** 如果一个恶意的 Tool 定义了 `execute_shell`，而 LLM 遭受了提示词注入（Prompt Injection），后果就是直接的 **RCE (远程代码执行)**。

为了验证这个猜想，我开发并开源了一个针对 MCP Server 的安全扫描器——**`mcp-security-scanner`**。

## 一、MCP 协议的安全盲区

MCP 协议的设计哲学是“能力优先”，Server 通过 `ListTools` 接口告诉 Client（如 Claude Desktop）自己能干什么。

```json
{
  "name": "execute_command",
  "description": "Run any shell command",
  "inputSchema": { ... }
}
```

目前大部分开发者在编写 MCP Server 时，缺乏**最小权限原则 (Least Privilege)** 的意识。我在 GitHub 上随机审计了几个热门的 MCP 项目，发现不少直接暴露了文件系统根目录 (`/`) 或允许执行 SQL 语句。

## 二、红队工具：mcp-security-scanner

为了自动化发现这些风险，我开发了这个基于启发式规则（Heuristics）的扫描工具。

**项目地址**：[https://github.com/fsxchen/mcp-security-scanner](https://github.com/fsxchen/mcp-security-scanner)

### 核心原理
该工具模拟 MCP Client 与 Server 建立 Stdio 连接，获取所有暴露的 Tools 和 Resources，然后通过正则关键词匹配和 Schema 分析来识别风险：

1.  **高危能力检测**：扫描 `exec`, `shell`, `system`, `delete` 等关键词。
2.  **资源越权检测**：检测 `file:///` 协议是否指向了 `/etc`, `.ssh` 等敏感目录。
3.  **输入验证缺失**：检测是否允许任意字符串输入（易受注入攻击）。

## 三、实战演示

我搭建了一个模拟的“不安全 Server”，它暴露了 Shell 执行和文件读取能力。

**扫描命令**：
```bash
python scanner.py python vulnerable_server.py
```

**扫描结果**：

*(此处插入你刚才运行扫描器的红色报警截图)*

可以看到，扫描器精准识别出了：
*   🔴 **[HIGH] Detected Risky Capability: shell** —— 对应 `execute_shell_command`
*   🔴 **[HIGH] Detected Risky Capability: delete** —— 对应 `drop_database`
*   🟠 **[MEDIUM] Detected Risky Capability: read** —— 对应 `read_system_file`

## 四、给开发者的防御建议

如果你正在开发 MCP Server，请务必遵守：

1.  **避免宽泛的工具**：不要给 AI `run_command` 这种万能接口，而是封装成 `restart_nginx_service` 这种原子操作。
2.  **人机回环 (Human-in-the-loop)**：对于高危操作，强制要求 Client 端进行用户确认（MCP 协议支持 `isUserApprovalRequired` 属性，但很多开发者没用）。
3.  **使用这个扫描器自查**：上线前跑一遍 `mcp-security-scanner`。

## 结语

AI Agent 的安全才刚刚起步。MCP 协议让连接变得简单，也让攻击变得简单。希望这个开源小工具能抛砖引玉，让大家关注 AI 基础设施的安全性。

---
*本文作者：Arron，关注 AI 安全与自动化。*
