import os
import re
import mmap
import hashlib
import subprocess
import platform
import ipaddress
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterator, Optional, Callable, List
import multiprocessing as mp
import json
from datetime import datetime, timedelta
from enum import Enum


class AlertLevel(Enum):
    CRITICAL = 3
    WARNING = 2
    INFO = 1

    def __str__(self):
        return self.name


@dataclass
class AlertThresholds:
    critical_high_min: int = 1
    warning_high_max: int = 5
    warning_medium_min: int = 3
    
    @classmethod
    def from_dict(cls, config: dict) -> 'AlertThresholds':
        return cls(
            critical_high_min=config.get('critical_high_min', 1),
            warning_high_max=config.get('warning_high_max', 5),
            warning_medium_min=config.get('warning_medium_min', 3),
        )


def load_config(config_path: str = 'config.json') -> Optional[dict]:
    if not os.path.exists(config_path):
        return None
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


class IPWhitelist:
    def __init__(self, ips: list[str]):
        self.entries = []
        for entry in ips:
            if '/' in entry:
                try:
                    self.entries.append(ipaddress.ip_network(entry))
                except ValueError:
                    pass
            elif '*' in entry:
                prefix = entry.replace('*', '0')
                try:
                    self.entries.append(ipaddress.ip_network(f"{prefix}/24"))
                except ValueError:
                    pass
            else:
                try:
                    self.entries.append(ipaddress.ip_address(entry))
                except ValueError:
                    pass
    
    def is_whitelisted(self, ip: str) -> bool:
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
            for entry in self.entries:
                if isinstance(entry, ipaddress.IPv4Address):
                    if addr == entry:
                        return True
                else:
                    if addr in entry:
                        return True
            return False
        except ValueError:
            return False


class TrustedIPLearner:
    def __init__(self, learn_logs: list[str], max_lines: int = 10000):
        self.learn_logs = learn_logs
        self.max_lines = max_lines
    
    def learn(self) -> set[str]:
        """从日志文件学习可信 IP"""
        trusted = set()
        pattern = r'Accepted publickey.*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        
        for log_file in self.learn_logs:
            if not os.path.exists(log_file):
                continue
            
            try:
                with open(log_file, 'r') as f:
                    for i, line in enumerate(f):
                        if i >= self.max_lines:
                            break
                        m = re.search(pattern, line)
                        if m:
                            trusted.add(m.group(1))
            except (IOError, PermissionError):
                continue
        
        return trusted
    
    def load_existing(self) -> set[str]:
        """加载已保存的可信 IP"""
        path = 'trusted_ips.json'
        if not os.path.exists(path):
            return set()
        
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                return set(data.get('learned_ips', []))
        except (json.JSONDecodeError, IOError):
            return set()
    
    def save(self, trusted: set[str]) -> None:
        """保存可信 IP 到文件"""
        data = {
            'learned_ips': sorted(list(trusted)),
            'last_updated': datetime.now().isoformat()
        }
        with open('trusted_ips.json', 'w') as f:
            json.dump(data, f, indent=2)


class ThreatExtractor:
    @staticmethod
    def extract_ip(text: str) -> Optional[str]:
        patterns = [
            r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+',
            r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'client\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\-\s+\-',
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None
    
    @staticmethod
    def extract_user(text: str) -> Optional[str]:
        patterns = [
            r'user\s+(\w+)',
            r'for\s+(\w+)',
            r'invalid user\s+(\w+)',
            r'Failed password for\s+(\w+)',
            r'user=([^\s,]+)',
        ]
        for pattern in patterns:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None
    
    @staticmethod
    def extract_process(text: str) -> Optional[str]:
        patterns = [
            r'([\w\-]+)\[\d+\]',
            r'\[([\w\-]+)\]',
            r'process\s+([\w\-]+)',
        ]
        for pattern in patterns:
            m = re.search(pattern, text)
            if m:
                return m.group(1)
        return None
    
    @staticmethod
    def extract_command(text: str) -> Optional[str]:
        patterns = [
            r'(rm\s+-rf[^\n]{0,50})',
            r'(wget[^\n]{0,100})',
            r'(curl[^\n]{0,100})',
            r'(nc\s+-[^\n]{0,50})',
            r'(chmod\s+777[^\n]{0,30})',
            r'(chown\s+[^\n]{0,50})',
        ]
        for pattern in patterns:
            m = re.search(pattern, text)
            if m:
                cmd = m.group(1).strip()
                return cmd[:80]
        return None


class NotificationManager:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled
    
    def send(self, title: str, message: str, alert_level: AlertLevel) -> None:
        if not self.enabled:
            return
        
        if platform.system() != 'Linux':
            return
        
        urgency_map = {
            AlertLevel.CRITICAL: 'critical',
            AlertLevel.WARNING: 'normal',
            AlertLevel.INFO: 'low'
        }
        urgency = urgency_map.get(alert_level, 'normal')
        
        try:
            subprocess.run([
                'notify-send',
                '-a', 'log-threat-detector',
                '-u', urgency,
                '-t', '10000',
                title,
                message
            ], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            pass
    
    def _build_title(self, alert_level: AlertLevel) -> str:
        titles = {
            AlertLevel.CRITICAL: "Security Threat Alert",
            AlertLevel.WARNING: "Security Warning",
            AlertLevel.INFO: "Security Report"
        }
        return titles.get(alert_level, "Security Report")
    
    def _build_message(self, high_count: int, medium_count: int, low_count: int) -> str:
        parts = []
        if high_count > 0:
            parts.append(f"HIGH: {high_count}")
        if medium_count > 0:
            parts.append(f"MEDIUM: {medium_count}")
        if low_count > 0:
            parts.append(f"LOW: {low_count}")
        return " | ".join(parts) if parts else "No threats found"


@dataclass
class ThreatEvent:
    rule_id: str
    category: str
    severity: str
    description: str
    line_number: int
    matched_text: str
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    process_name: Optional[str] = None
    command: Optional[str] = None


@dataclass
class LogEntry:
    line_number: int
    content: str
    timestamp: Optional[str] = None
    level: Optional[str] = None


@dataclass
class LogFile:
    path: str
    size: int
    entries: list[LogEntry]
    errors: int
    threats: list[ThreatEvent] = field(default_factory=list)


def _do_parse_log_file(filepath: str, max_lines: Optional[int]) -> LogFile:
    """纯解析逻辑，无错误处理"""
    entries = []
    
    with open(filepath, 'r', buffering=8192) as f:
        for i, line in enumerate(f):
            if max_lines and i >= max_lines:
                break
            
            line = line.rstrip('\n')
            entry = LogEntry(
                line_number=i + 1,
                content=line,
                timestamp=_extract_timestamp(line),
                level=_extract_level(line)
            )
            entries.append(entry)
    
    size = os.path.getsize(filepath)
    return LogFile(filepath, size, entries, 0)


def parse_log_file(args: tuple) -> LogFile:
    """带错误处理的包装函数"""
    filepath, patterns, max_lines = args
    
    try:
        size = os.path.getsize(filepath)
    except (OSError, IOError):
        return LogFile(filepath, 0, [], 0)
    
    try:
        return _do_parse_log_file(filepath, max_lines)
    except (UnicodeDecodeError, IOError):
        return LogFile(filepath, os.path.getsize(filepath) if os.path.exists(filepath) else 0, [], 1)


def _extract_timestamp(line: str) -> Optional[str]:
    patterns = [
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
        r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
        r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
    ]
    for p in patterns:
        m = re.search(p, line)
        if m:
            return m.group(1)
    return None


def _extract_level(line: str) -> Optional[str]:
    levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL', 'FATAL', 'WARN', 'ERR']
    line_upper = line.upper()
    for lvl in levels:
        if lvl in line_upper:
            return lvl
    return None


class ThreatDetector:
    def __init__(self):
        self.rules = [
            {
                'rule_id': 'ssh_bruteforce',
                'category': 'SSH Brute Force',
                'severity': 'HIGH',
                'patterns': [
                    r'failed login',
                    r'invalid user',
                    r'authentication failure',
                    r'Failed password for',
                    r'Bad protocol version',
                    r'Disconnected from',
                ]
            },
            {
                'rule_id': 'web_attack',
                'category': 'Web Attack',
                'severity': 'HIGH',
                'patterns': [
                    r'union select',
                    r'union.*select',
                    r'select.*from',
                    r'or\s+1\s*=\s*1',
                    r'<script>',
                    r'javascript:',
                    r'\.\./',
                    r'\.\.\\',
                    r'eval\(',
                    r'alert\(',
                ]
            },
            {
                'rule_id': 'dangerous_command',
                'category': 'Dangerous Command',
                'severity': 'HIGH',
                'patterns': [
                    r'rm\s+-rf',
                    r'wget.*\|',
                    r'curl.*\|',
                    r'nc\s+-e',
                    r'bash\s+-i',
                    r'sh\s+-i',
                    r'/bin/sh\s+-i',
                    r'chmod\s+777',
                    r'chown\s+',
                    r'&&rm\s',
                ]
            },
            {
                'rule_id': 'auth_success',
                'category': 'Authentication Success',
                'severity': 'MEDIUM',
                'patterns': [
                    r'session opened',
                    r'accepted password',
                    r'login successful',
                    r'authenticated \(',
                    r'Accepted publickey',
                ]
            },
            {
                'rule_id': 'sensitive_file_access',
                'category': 'Sensitive File Access',
                'severity': 'MEDIUM',
                'patterns': [
                    r'/etc/passwd',
                    r'/etc/shadow',
                    r'authorized_keys',
                    r'id_rsa',
                    r'id_dsa',
                    r'\.ssh/known_hosts',
                ]
            },
            {
                'rule_id': 'suspicious_time',
                'category': 'Suspicious Time Access',
                'severity': 'LOW',
                'patterns': []
            },
            {
                'rule_id': 'error_response',
                'category': 'Error Response',
                'severity': 'LOW',
                'patterns': [
                    r'\s404\s',
                    r'\s500\s',
                    r'\s503\s',
                    r'404\sNot Found',
                    r'500\sInternal Server Error',
                    r'403\sForbidden',
                ]
            },
        ]

    def detect(self, entries: list[LogEntry]) -> list[ThreatEvent]:
        threats = []
        
        for entry in entries:
            content = entry.content
            line_num = entry.line_number
            
            for rule in self.rules:
                if rule['rule_id'] == 'suspicious_time':
                    if entry.timestamp:
                        time_threat = self._check_suspicious_time(entry.timestamp, line_num, content)
                        if time_threat:
                            threats.append(time_threat)
                    continue
                
                for pattern in rule['patterns']:
                    if re.search(pattern, content, re.IGNORECASE):
                        threats.append(ThreatEvent(
                            rule_id=rule['rule_id'],
                            category=rule['category'],
                            severity=rule['severity'],
                            description=f"Detected {rule['category']}",
                            line_number=line_num,
                            matched_text=content[:200],
                            source_ip=ThreatExtractor.extract_ip(content),
                            target_user=ThreatExtractor.extract_user(content),
                            process_name=ThreatExtractor.extract_process(content),
                            command=ThreatExtractor.extract_command(content)
                        ))
                        break
        
        return threats

    def _check_suspicious_time(self, timestamp: str, line_num: int, content: str) -> Optional[ThreatEvent]:
        time_patterns = [
            r'(\d{4}-\d{2}-\d{2})\s+(\d{2}):\d{2}:\d{2}',
            r'(\d{2}/\w{3}/\d{4}):(\d{2}):\d{2}:\d{2}',
            r'\w{3}\s+\d{1,2}\s+(\d{2}):\d{2}:\d{2}',
        ]
        
        for pattern in time_patterns:
            m = re.search(pattern, timestamp)
            if m:
                hour = int(m.group(2) if len(m.groups()) > 1 else m.group(1))
                if hour >= 22 or hour < 6:
                    return ThreatEvent(
                        rule_id='suspicious_time',
                        category='Suspicious Time Access',
                        severity='LOW',
                        description='Activity during non-work hours (22:00-06:00)',
                        line_number=line_num,
                        matched_text=content[:200],
                        source_ip=ThreatExtractor.extract_ip(content),
                        target_user=ThreatExtractor.extract_user(content),
                        process_name=ThreatExtractor.extract_process(content),
                        command=ThreatExtractor.extract_command(content)
                    )
        return None


class ReportGenerator:
    def __init__(self, output_path: Optional[str] = None):
        if output_path:
            self.output_path = output_path
        else:
            reports_dir = os.path.expanduser('~/.log_parse/reports')
            os.makedirs(reports_dir, exist_ok=True)
            self.output_path = os.path.join(reports_dir, 'threat_report.html')

    def generate(self, results: list) -> str:
        high = []
        medium = []
        low = []
        
        for r in results:
            for t in r.get('threats_detail', []):
                if t['severity'] == 'HIGH':
                    high.append(t)
                elif t['severity'] == 'MEDIUM':
                    medium.append(t)
                else:
                    low.append(t)
        
        html = self._header()
        html += self._summary(results, high, medium, low)
        html += self._threat_table('HIGH', high)
        html += self._threat_table('MEDIUM', medium)
        html += self._threat_table('LOW', low)
        html += self._footer()
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return self.output_path
    
    def _header(self) -> str:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>安全威胁报告</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
    h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
    h2 {{ color: #555; margin-top: 30px; }}
    .timestamp {{ color: #888; font-size: 14px; }}
    .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
    .stat-box {{ flex: 1; padding: 20px; border-radius: 5px; text-align: center; }}
    .stat-box.high {{ background: #ffebee; border: 2px solid #f44336; }}
    .stat-box.medium {{ background: #fff3e0; border: 2px solid #ff9800; }}
    .stat-box.low {{ background: #e8f5e9; border: 2px solid #4CAF50; }}
    .stat-box .number {{ font-size: 36px; font-weight: bold; }}
    .stat-box.high .number {{ color: #f44336; }}
    .stat-box.medium .number {{ color: #ff9800; }}
    .stat-box.low .number {{ color: #4CAF50; }}
    table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
    th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
    th {{ background-color: #4CAF50; color: white; }}
    tr:nth-child(even) {{ background-color: #f9f9f9; }}
    .severity-high {{ color: #f44336; font-weight: bold; }}
    .severity-medium {{ color: #ff9800; font-weight: bold; }}
    .severity-low {{ color: #4CAF50; }}
    .empty {{ color: #888; font-style: italic; }}
</style>
</head>
<body>
<div class="container">
<h1>安全威胁报告</h1>
<p class="timestamp">生成时间: {timestamp}</p>
"""

    def _summary(self, results: list, high: list, medium: list, low: list) -> str:
        total_files = len(results)
        total_threats = len(high) + len(medium) + len(low)
        total_lines = sum(r.get('entries_count', 0) for r in results)
        
        return f"""
<div class="summary">
    <div class="stat-box">
        <div class="number">{total_files}</div>
        <div>扫描文件数</div>
    </div>
    <div class="stat-box">
        <div class="number">{total_threats}</div>
        <div>威胁总数</div>
    </div>
    <div class="stat-box">
        <div class="number">{total_lines}</div>
        <div>日志行数</div>
    </div>
    <div class="stat-box high">
        <div class="number">{len(high)}</div>
        <div>高风险</div>
    </div>
    <div class="stat-box medium">
        <div class="number">{len(medium)}</div>
        <div>中风险</div>
    </div>
    <div class="stat-box low">
        <div class="number">{len(low)}</div>
        <div>低风险</div>
    </div>
</div>
"""

    def _threat_table(self, severity: str, threats: list) -> str:
        severity_label = {
            'HIGH': ('高风险', 'severity-high'),
            'MEDIUM': ('中风险', 'severity-medium'),
            'LOW': ('低风险', 'severity-low')
        }
        label, css_class = severity_label[severity]
        
        if not threats:
            return f'<h2>{label} ({len(threats)})</h2><p class="empty">未发现此级别威胁</p>'
        
        rows = []
        for t in threats:
            rows.append(f"""
        <tr>
            <td class="{css_class}">{t['category']}</td>
            <td>{t['description']}</td>
            <td>{t.get('file', 'N/A')}</td>
            <td>Line {t['line_number']}</td>
            <td><code>{t['matched_text'][:80]}...</code></td>
        </tr>""")
        
        return f"""
<h2>{label} ({len(threats)})</h2>
<table>
    <tr>
        <th>类型</th>
        <th>描述</th>
        <th>来源文件</th>
        <th>行号</th>
        <th>匹配内容</th>
    </tr>
    {"".join(rows)}
</table>"""

    def _footer(self) -> str:
        return """
</div>
</body>
</html>"""


class AlertManager:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    
    def __init__(self, enable_color: bool = True, enable_notification: bool = True, thresholds: Optional[AlertThresholds] = None, whitelist: Optional[IPWhitelist] = None):
        self.enable_color = enable_color
        self.notification_manager = NotificationManager(enabled=enable_notification)
        self.thresholds = thresholds or AlertThresholds()
        self.whitelist = whitelist
    
    def send_summary(self, results: list) -> tuple[AlertLevel, dict]:
        summary = self._summarize_threats(results)
        alert_level = self.determine_alert_level(results)
        
        print()
        self._print_header(alert_level)
        
        self._print_threat_summary(summary)
        
        self._show_top_files(results)
        
        self._print_footer(alert_level)
        
        high_count = sum(d['count'] for d in summary.get('HIGH', {}).values())
        medium_count = sum(d['count'] for d in summary.get('MEDIUM', {}).values())
        low_count = sum(d['count'] for d in summary.get('LOW', {}).values())
        
        title = self.notification_manager._build_title(alert_level)
        message = self.notification_manager._build_message(high_count, medium_count, low_count)
        self.notification_manager.send(title, message, alert_level)
        
        return alert_level, summary
    
    def determine_alert_level(self, results: list) -> AlertLevel:
        high_count = 0
        medium_count = 0
        
        for r in results:
            for t in r.get('threats_detail', []):
                if t['severity'] == 'HIGH':
                    high_count += 1
                elif t['severity'] == 'MEDIUM':
                    medium_count += 1
        
        t = self.thresholds
        
        if high_count >= t.critical_high_min:
            return AlertLevel.CRITICAL
        elif high_count < t.warning_high_max and medium_count >= t.warning_medium_min:
            return AlertLevel.WARNING
        else:
            return AlertLevel.INFO
    
    def _colorize(self, text: str, color: str) -> str:
        if not self.enable_color:
            return text
        return f"{color}{text}{self.RESET}"
    
    def _summarize_threats(self, results: list) -> dict:
        summary = {
            'HIGH': {},
            'MEDIUM': {},
            'LOW': {}
        }
        
        for r in results:
            for t in r.get('threats_detail', []):
                category = t['category']
                original_severity = t['severity']
                severity = original_severity
                
                if self.whitelist and t.get('source_ip'):
                    if self.whitelist.is_whitelisted(t['source_ip']):
                        if severity == 'HIGH':
                            severity = 'MEDIUM'
                        elif severity == 'MEDIUM':
                            severity = 'LOW'
                
                if category not in summary[severity]:
                    summary[severity][category] = {'count': 0, 'ips': [], 'users': [], 'commands': []}
                
                summary[severity][category]['count'] += 1
                
                if t.get('source_ip'):
                    summary[severity][category]['ips'].append(t['source_ip'])
                if t.get('target_user'):
                    summary[severity][category]['users'].append(t['target_user'])
                if t.get('command'):
                    summary[severity][category]['commands'].append(t['command'])
        
        return summary
    
    def _format_table(self, headers: list, rows: list) -> str:
        if not rows:
            return ""
        
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        separator = '+' + '+'.join('-' * (w + 2) for w in col_widths) + '+'
        
        lines = [separator]
        header_line = '|' + '|'.join(f" {h:<{col_widths[i]}} " for i, h in enumerate(headers)) + '|'
        lines.append(header_line)
        lines.append(separator)
        
        for row in rows:
            row_line = '|' + '|'.join(f" {str(cell):<{col_widths[i]}} " for i, cell in enumerate(row)) + '|'
            lines.append(row_line)
        
        lines.append(separator)
        return '\n'.join(lines)
    
    def _show_top_files(self, results: list) -> None:
        file_threats = {}
        for r in results:
            if r['threats_count'] > 0:
                file_threats[r['path']] = r['threats_count']
        
        if not file_threats:
            return
        
        sorted_files = sorted(file_threats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        print()
        print(self._colorize("=== 高风险来源文件 ===", self.YELLOW))
        for i, (path, count) in enumerate(sorted_files, 1):
            high_count = sum(
                1 for r in results if r['path'] == path
                for t in r.get('threats_detail', [])
                if t['severity'] == 'HIGH'
            )
            marker = self._colorize("[!]", self.RED) if high_count > 0 else "   "
            print(f"  {marker} {i}. {path} [{count} 威胁]")
    
    def _print_header(self, alert_level: AlertLevel) -> None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        colors = {
            AlertLevel.CRITICAL: self.RED,
            AlertLevel.WARNING: self.YELLOW,
            AlertLevel.INFO: self.GREEN,
        }
        color = colors[alert_level]
        
        print(self._colorize(f"═" * 50, color))
        print(self._colorize(f"  [{alert_level}] 安全威胁报告 - {timestamp}", color))
        print(self._colorize(f"═" * 50, color))
    
    def _print_threat_summary(self, summary: dict) -> None:
        total = sum(d['count'] for level in summary.values() for d in level.values())
        
        if total == 0:
            print(self._colorize("  ✓ 未发现威胁", self.GREEN))
            return
        
        if summary['HIGH']:
            print()
            print(self._colorize("  [!CRITICAL] 高风险威胁", self.RED))
            for category, data in summary['HIGH'].items():
                info_parts = []
                ips = list(set(data['ips']))[:5]
                users = list(set(data['users']))[:5]
                commands = list(set(data['commands']))[:5]
                
                if ips:
                    ip_str = ', '.join(ips)
                    if len(ip_str) > 40:
                        ip_str = ip_str[:40] + '...'
                    info_parts.append(f"IP: {ip_str}")
                if users:
                    info_parts.append(f"用户: {', '.join(users[:5])}")
                if commands:
                    cmd_str = commands[0][:30] if commands else ''
                    if len(commands) > 1:
                        cmd_str += '...'
                    info_parts.append(f"命令: {cmd_str}")
                
                info_str = f" ({', '.join(info_parts)})" if info_parts else ""
                print(f"    • {category}: {data['count']} 次{info_str}")
        
        if summary['MEDIUM']:
            print()
            print(self._colorize("  [WARNING] 中风险威胁", self.YELLOW))
            for category, data in summary['MEDIUM'].items():
                info_parts = []
                ips = list(set(data['ips']))[:5]
                users = list(set(data['users']))[:5]
                
                if ips:
                    ip_str = ', '.join(ips)
                    if len(ip_str) > 40:
                        ip_str = ip_str[:40] + '...'
                    info_parts.append(f"IP: {ip_str}")
                if users:
                    info_parts.append(f"用户: {', '.join(users[:5])}")
                
                info_str = f" ({', '.join(info_parts)})" if info_parts else ""
                print(f"    • {category}: {data['count']} 次{info_str}")
        
        if summary['LOW']:
            print()
            print(self._colorize("  [INFO] 低风险威胁", self.GREEN))
            for category, data in summary['LOW'].items():
                print(f"    • {category}: {data['count']} 次")
    
    def _print_footer(self, alert_level: AlertLevel) -> None:
        colors = {
            AlertLevel.CRITICAL: self.RED,
            AlertLevel.WARNING: self.YELLOW,
            AlertLevel.INFO: self.GREEN,
        }
        color = colors[alert_level]
        print()
        print(self._colorize(f"═" * 50, color))


class DirParser:
    def __init__(
        self,
        root_path: str,
        pattern: str = r'\.(log|txt|gz)$',
        max_workers: Optional[int] = None,
        max_lines_per_file: Optional[int] = None,
        follow_symlinks: bool = False,
        output_dir: Optional[str] = None
    ):
        self.root_path = root_path
        self.pattern = re.compile(pattern)
        self.max_workers = max_workers or max(1, mp.cpu_count() - 1)
        self.max_lines = max_lines_per_file
        self.follow_symlinks = follow_symlinks
        self.output_dir = output_dir or os.path.expanduser('~/.log_parse')
        self.threat_detector = ThreatDetector()

    def _should_skip_file(self, filepath: str) -> bool:
        if not os.path.exists(self.output_dir):
            return False
        
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_name = f"{timestamp}_{filename}.json"
        json_path = os.path.join(self.output_dir, json_name)
        
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                    parse_time = datetime.fromisoformat(data.get('parse_time', ''))
                    if datetime.now() - parse_time < timedelta(hours=24):
                        return True
            except (json.JSONDecodeError, KeyError, ValueError, OSError):
                pass
        return False

    def _get_json_path(self, filepath: str) -> str:
        reports_dir = os.path.join(self.output_dir, 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(reports_dir, f"{timestamp}_{filename}.json")

    def save_to_json(self, log_file: LogFile) -> None:
        output_path = self._get_json_path(log_file.path)
        
        data = {
            'source_file': log_file.path,
            'parse_time': datetime.now().isoformat(),
            'stats': {
                'total_lines': len(log_file.entries),
                'threats_count': len(log_file.threats),
                'file_size': log_file.size,
                'errors': log_file.errors
            },
            'threats': [
                {
                    'rule_id': t.rule_id,
                    'category': t.category,
                    'severity': t.severity,
                    'description': t.description,
                    'line_number': t.line_number,
                    'matched_text': t.matched_text
                }
                for t in log_file.threats
            ],
            'entries': [
                {
                    'line_number': e.line_number,
                    'content': e.content,
                    'timestamp': e.timestamp,
                    'level': e.level
                }
                for e in log_file.entries
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def scan_files(self) -> Iterator[str]:
        dirs = [self.root_path]
        
        while dirs:
            current = dirs.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=self.follow_symlinks):
                                dirs.append(entry.path)
                            elif entry.is_file(follow_symlinks=self.follow_symlinks):
                                if self.pattern.search(entry.name):
                                    yield entry.path
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue

    def parse(self, progress_callback: Optional[Callable[[int], None]] = None) -> Iterator[LogFile]:
        files = [f for f in self.scan_files() if not self._should_skip_file(f)]
        
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            args = [(f, None, self.max_lines) for f in files]
            
            for i, future in enumerate(as_completed(executor.submit(parse_log_file, a) for a in args)):
                result = future.result()
                result.threats = self.threat_detector.detect(result.entries)
                if self.output_dir:
                    self.save_to_json(result)
                if progress_callback:
                    progress_callback(i + 1)
                yield result


def parse_cli_args():
    import argparse
    parser = argparse.ArgumentParser(description='log-threat-detector')
    parser.add_argument('path', nargs='?', default='/var/log', help='Directory to scan')
    parser.add_argument('--add-ip', action='append', help='Add IP to whitelist')
    parser.add_argument('--remove-ip', action='append', help='Remove IP from whitelist')
    parser.add_argument('--list-ips', action='store_true', help='List whitelisted IPs')
    return parser.parse_args()


def main():
    import sys
    
    cli_args = parse_cli_args()
    
    learner = TrustedIPLearner([], 0)
    existing_ips = learner.load_existing()
    
    if cli_args.add_ip:
        for ip in cli_args.add_ip:
            existing_ips.add(ip)
        learner.save(existing_ips)
        print(f"Added IPs: {cli_args.add_ip}")
    
    if cli_args.remove_ip:
        for ip in cli_args.remove_ip:
            existing_ips.discard(ip)
        learner.save(existing_ips)
        print(f"Removed IPs: {cli_args.remove_ip}")
    
    if cli_args.list_ips:
        if existing_ips:
            print("Whitelisted IPs:")
            for ip in sorted(existing_ips):
                print(f"  {ip}")
        else:
            print("No IPs in whitelist")
    
    if any([cli_args.add_ip, cli_args.remove_ip, cli_args.list_ips]):
        return
    
    config = load_config('config.json')
    
    enable_notification = True
    thresholds = AlertThresholds()
    enable_color = True
    whitelist = None
    
    if config:
        if 'notification' in config:
            enable_notification = config['notification'].get('enabled', True)
        if 'thresholds' in config:
            thresholds = AlertThresholds.from_dict(config['thresholds'])
        if 'display' in config:
            enable_color = config['display'].get('enable_color', True)
        if 'whitelist' in config:
            whitelist_config = config['whitelist']
            if whitelist_config.get('enabled', False):
                all_ips = list(whitelist_config.get('ips', []))
                
                if whitelist_config.get('auto_learn', False):
                    learner = TrustedIPLearner(
                        whitelist_config.get('learn_logs', ['/var/log/auth.log']),
                        whitelist_config.get('learn_max_lines', 10000)
                    )
                    learned_ips = list(learner.learn())
                    existing_from_config = list(learner.load_existing())
                    all_ips = sorted(list(set(all_ips) | set(learned_ips) | set(existing_from_config)))
                    learner.save(set(all_ips))
                    if learned_ips:
                        print(f"Learned {len(learned_ips)} trusted IPs from logs")
                
                whitelist = IPWhitelist(all_ips)
    
    path = cli_args.path
    
    print(f"Scanning: {path}")
    
    parser = DirParser(
        root_path=path,
        pattern=r'\.(log|txt|gz|json)$',
        max_workers=4,
        max_lines_per_file=1000
    )
    
    results = []
    skipped = 0
    count = 0
    
    for filepath in parser.scan_files():
        if parser._should_skip_file(filepath):
            skipped += 1
    
    print(f"Total files found: {len(list(parser.scan_files()))}")
    print(f"Skipped (within 24h): {skipped}")
    
    def progress(i):
        nonlocal count
        count = i
        if i % 10 == 0:
            print(f"Processed {i} files...", flush=True)
    
    results = []
    for log_file in parser.parse(progress_callback=progress):
        if log_file.entries:
            threats_detail = []
            for threat in log_file.threats:
                threats_detail.append({
                    'rule_id': threat.rule_id,
                    'category': threat.category,
                    'severity': threat.severity,
                    'description': threat.description,
                    'line_number': threat.line_number,
                    'matched_text': threat.matched_text,
                    'source_ip': threat.source_ip,
                    'target_user': threat.target_user,
                    'process_name': threat.process_name,
                    'command': threat.command,
                    'file': log_file.path
                })
            results.append({
                'path': log_file.path,
                'size': log_file.size,
                'entries_count': len(log_file.entries),
                'threats_count': len(log_file.threats),
                'error_count': log_file.errors,
                'threats_detail': threats_detail
            })
    
    print(f"\nTotal files processed: {len(results)}")
    print(f"Total threats detected: {sum(r['threats_count'] for r in results)}")
    
    print("\nTop files by threats:")
    sorted_results = sorted(results, key=lambda x: x['threats_count'], reverse=True)
    for r in sorted_results[:5]:
        print(f"  {r['path']}: {r['threats_count']} threats, {r['entries_count']} entries")
    
    report_gen = ReportGenerator()
    report_path = report_gen.generate(results)
    print(f"\nHTML report saved: {report_path}")
    
    alert_manager = AlertManager(
        enable_color=enable_color,
        enable_notification=enable_notification,
        thresholds=thresholds,
        whitelist=whitelist
    )
    alert_level, summary = alert_manager.send_summary(results)


if __name__ == '__main__':
    main()