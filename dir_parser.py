import os
import re
import mmap
import hashlib
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Iterator, Optional, Callable, List
import multiprocessing as mp
import json
from datetime import datetime, timedelta


@dataclass
class ThreatEvent:
    rule_id: str
    category: str
    severity: str
    description: str
    line_number: int
    matched_text: str


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
                            matched_text=content[:200]
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
                        matched_text=content[:200]
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
    
    def __init__(self, enable_color: bool = True):
        self.enable_color = enable_color
    
    def send_summary(self, results: list) -> None:
        summary = self._summarize_threats(results)
        
        print()
        self._print_header()
        
        self._print_threat_summary(summary)
        
        self._show_top_files(results)
        
        self._print_footer()
    
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
                severity = t['severity']
                if category not in summary[severity]:
                    summary[severity][category] = 0
                summary[severity][category] += 1
        
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
    
    def _print_header(self) -> None:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(self._colorize(f"═" * 50, self.RED))
        print(self._colorize(f"  安全威胁报告 - {timestamp}", self.RED))
        print(self._colorize(f"═" * 50, self.RED))
    
    def _print_threat_summary(self, summary: dict) -> None:
        total = sum(sum(d.values()) for d in summary.values())
        
        if total == 0:
            print(self._colorize("  ✓ 未发现威胁", self.GREEN))
            return
        
        if summary['HIGH']:
            print()
            print(self._colorize("  [!CRITICAL] 高风险威胁", self.RED))
            for category, count in summary['HIGH'].items():
                print(f"    • {category}: {count} 次")
        
        if summary['MEDIUM']:
            print()
            print(self._colorize("  [WARNING] 中风险威胁", self.YELLOW))
            for category, count in summary['MEDIUM'].items():
                print(f"    • {category}: {count} 次")
        
        if summary['LOW']:
            print()
            print(self._colorize("  [INFO] 低风险威胁", self.GREEN))
            for category, count in summary['LOW'].items():
                print(f"    • {category}: {count} 次")
    
    def _print_footer(self) -> None:
        print()
        print(self._colorize(f"═" * 50, self.RED))


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


def main():
    import sys
    
    if len(sys.argv) < 2:
        path = '/var/log'
    else:
        path = sys.argv[1]
    
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
    
    alert_manager = AlertManager()
    alert_manager.send_summary(results)


if __name__ == '__main__':
    main()