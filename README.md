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
├── dir_parser.py          # 主程序
├── tests/
│   └── test_parser.py    # 单元测试
└── README.md
```

### 核心模块

| 模块 | 功能 |
|------|------|
| `parse_log_file()` | 解析日志文件（带错误处理） |
| `_do_parse_log_file()` | 纯解析逻辑（无错误处理） |
| `ThreatDetector` | 威胁检测引擎 |
| `DirParser` | 目录扫描与调度 |
| `ReportGenerator` | HTML 报告生成 |

## 输出示例

运行后会在 `~/.log_parse/reports/` 目录生成以下文件：

```
~/.log_parse/reports/
├── <timestamp>_xxx.log.json    # 每个日志文件的解析结果
└── threat_report.html          # HTML 威胁报告
```

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

## 贡献指南

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/xxx`)
3. 提交更改 (`git commit -m 'Add xxx'`)
4. 推送分支 (`git push origin feature/xxx`)
5. 创建 Pull Request
