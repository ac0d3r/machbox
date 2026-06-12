# MachBox

专为 macOS 设计的单二进制恶意软件分析沙盒工具，集成动静态分析能力，基于 Apple 原生框架构建（`Virtualization.framework`、`EndpointSecurity.framework`、`DTrace` 等）。

[English](../README.md) | 中文

<img src="imgs/machbox-reports.png" alt="关闭 SIP" width="680" />

## 支持格式

| 格式 | 说明 |
|------|------|
| **Mach-O** | 单二进制可执行文件 |
| **App Bundle** | `.app` 目录包，自动解析 `Contents/Info.plist` 及主可执行文件 |
| **ZIP 压缩包** | 支持密码解压（ZipCrypto），自动提取并识别包内主文件进行分析 |

## 系统要求

- **Apple Silicon Mac**
- **macOS 13+**

## 环境准备

只需执行一次，准备好后即可反复运行样本分析。

### 1. 准备虚拟机

使用 [VirtualBuddy](https://github.com/insidegui/VirtualBuddy) 创建一个新的 macOS 虚拟机：

1. 创建虚拟机时 **取消勾选 VirtualBuddy Guest App**；
    
    <img src="imgs/Disabled_VirtualBuddy_Guest_App.png" alt="取消 Guest App" width="350" />

2. 虚拟机创建且完成初始化后，再关闭虚拟机SIP；  
    - 开启 **Boot in recovery mode** 运行进入恢复模式：

    <img src="imgs/enable_Boot_in_recovery_mode.png" alt="关闭 SIP" width="300" />

    - 顶部菜单栏选择 Utilities → Terminal
    - 输入 `csrutil disable` 回车，重启虚拟机即可。

### 2. 安装 Machbox Guest Agent

在虚拟机中首次运行 MachBox 环境前，需要先安装 Guest Agent：

```bash
machbox setup -m /path/to/your_Machbox.vbvm
```

- 打开 Finder; 选择左侧 `MachboxGuest`; 安装 `machbox-guest.pkg`
  - 将静默安装 Xcode Command Line Tools（`clang`）；这是启用 DTrace 探针的必需依赖。

- 安装完成，关闭虚拟机即可。

---

## 分析样本

```bash
machbox analyze -m /path/to/your_Machbox.vbvm /path/to/sample
```

常用选项：

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-m, --vbvm` | **必需** VirtualBuddy 虚拟机包路径 | — |
| `--timeout` | 动态分析超时时间（秒） | `60` |
| `--password` | 加密压缩包的解压密码 | — |
| `--headless` | 无 GUI 模式运行（分析完成后自动关机） | `true` |
| `--display` | 分辨率设置 | `1920x1200` |
| `--network-mode` | 网络模式（如 `NAT`） | 禁用 |

## 查看分析报告

所有分析结果自动存入本地数据库，通过内置 Web UI 可视化查看：

```bash
machbox report-view
```

打开浏览器访问 `http://127.0.0.1:8080` 即可浏览完整的分析报告。

## 致谢

- https://github.com/blacktop/go-macho
- https://github.com/Code-Hex/vz
- https://github.com/insidegui/VirtualBuddy
