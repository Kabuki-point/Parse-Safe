# log-threat-detector

日志文件安全威胁检测工具，自动扫描日志文件并检测可疑的安全事件。

## 功能特性

- **多格式支持**: 解析 `.log`, `.txt`, `.gz`, `.json` 日志文件
- **威胁检测**: 内置 7 种威胁检测规则
  - SSH 暴力破解
  - Web 攻击 (SQL注入、XSS、目录遍历)
  - 危险命令执行
  - 认证成功事件
  - 敏感文件访问
  - 非工作时间活动
  - HTTP 错误响应
- **多进程并行**: 使用 ProcessPoolExecutor 并行处理
- **缓存机制**: 24小时内已解析文件自动跳过
- **JSON输出**: 解析结果保存为 JSON 格式
- **HTML报告**: 生成可视化威胁报告，支持颜色区分风险等级
- **统一输出目录**: 所有输出保存到 `~/.log_parse/reports/`
- **控制台警告**: 终端颜色高亮输出，支持 CRITICAL/WARNING/INFO 级别
- **系统通知**: Linux 桌面通知，根据告警级别显示（仅 Linux）
- **阈值配置**: 支持 JSON 配置文件自定义告警阈值

## 安装

```bash
git clone https://github.com/yourusername/log-threat-detector.git
cd log-threat-detector
```

可选依赖（用于系统通知）：
```bash
pip install plyer
```

## 使用方法

```bash
# 扫描默认目录 /var/log
python3 dir_parser.py

# 扫描指定目录
python3 dir_parser.py /var/log

# 扫描指定目录并设置最大行数
python3 dir_parser.py /path/to/logs --max-lines 1000
```

### 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `path` | `/var/log` | 扫描的目录路径 |
| `--pattern` | `\.(log\|txt\|gz\|json)$` | 文件匹配正则 |
| `--max-lines` | `1000` | 每个文件最大解析行数 |

## 项目结构

```
log-threat-detector/
├── .gitignore              # Git 忽略规则
├── LICENSE                 # MIT 许可证
├── dir_parser.py           # 主程序
├── tests/
│   └── test_parser.py    # 单元测试
├── config.example.json    # 配置文件模板
├── README.md              # 项目文档
└── dev_log.txt            # 开发日志
```

### 核心模块

| 模块 | 功能 |
|------|------|
| `parse_log_file()` | 解析日志文件（带错误处理） |
| `_do_parse_log_file()` | 纯解析逻辑（无错误处理） |
| `ThreatDetector` | 威胁检测引擎 |
| `DirParser` | 目录扫描与调度 |
| `ReportGenerator` | HTML 报告生成 |
| `AlertManager` | 控制台警告输出 |
| `NotificationManager` | Linux 系统通知 |
| `AlertThresholds` | 告警阈值配置 |

## 输出示例

运行后会在 `~/.log_parse/reports/` 目录生成以下文件：

```
~/.log_parse/reports/
├── <timestamp>_xxx.log.json    # 每个日志文件的解析结果
└── threat_report.html          # HTML 威胁报告
```

### 控制台输出示例

```
═══════════════════════════════════════════════════
  [CRITICAL] 安全威胁报告 - 2026-04-02 16:48:40
═══════════════════════════════════════════════════

  [!CRITICAL] 高风险威胁
    • SSH Brute Force: 15 次
    • Web Attack: 3 次

  [WARNING] 中风险威胁
    • Sensitive File Access: 5 次

  [INFO] 低风险威胁
    • Suspicious Time Access: 10 次

=== 高风险来源文件 ===
  [!] 1. /var/log/auth.log [23 威胁]

═══════════════════════════════════════════════════
```

### JSON 输出示例

```json
{
  "source_file": "/var/log/syslog",
  "parse_time": "2024-01-01T10:00:00",
  "stats": {
    "total_lines": 100,
    "threats_count": 3,
    "file_size": 1024,
    "errors": 0
  },
  "threats": [
    {
      "rule_id": "ssh_bruteforce",
      "category": "SSH Brute Force",
      "severity": "HIGH",
      "description": "Detected SSH Brute Force",
      "line_number": 42,
      "matched_text": "failed login attempt from 192.168.1.100"
    }
  ]
}
```

## 运行测试

```bash
python3 -m unittest tests/test_parser.py -v
```

## 配置文件

程序支持通过 `config.json` 配置文件自定义行为。将 `config.example.json` 复制为 `config.json` 即可启用。

```bash
cp config.example.json config.json
```

### 配置文件示例

```json
{
  "thresholds": {
    "critical_high_min": 1,
    "warning_high_max": 5,
    "warning_medium_min": 3
  },
  "notification": {
    "enabled": true
  },
  "display": {
    "enable_color": true
  }
}
```

### 配置项说明

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `thresholds.critical_high_min` | 1 | HIGH 风险 >= 此值时触发 CRITICAL |
| `thresholds.warning_high_max` | 5 | HIGH < 此值且 MEDIUM >= warning_medium_min 时触发 WARNING |
| `thresholds.warning_medium_min` | 3 | WARNING 触发的 MEDIUM 下限 |
| `notification.enabled` | true | 是否启用系统通知 |
| `display.enable_color` | true | 是否启用终端颜色输出 |

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/xxx`)
3. 提交更改 (`git commit -m 'Add xxx'`)
4. 推送分支 (`git push origin feature/xxx`)
5. 创建 Pull Request
