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


def parse_log_file(args: tuple) -> LogFile:
    filepath, patterns, max_lines = args
    
    try:
        size = os.path.getsize(filepath)
    except (OSError, IOError):
        return LogFile(filepath, 0, [], 0)

    entries = []
    errors = 0
    
    try:
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
                
    except (UnicodeDecodeError, IOError) as e:
        errors = 1
    
    return LogFile(filepath, size, entries, errors)


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
        os.makedirs(self.output_dir, exist_ok=True)
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        return os.path.join(self.output_dir, f"{timestamp}_{filename}.json")

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
    
    for log_file in parser.parse(progress_callback=progress):
        if log_file.entries:
            results.append({
                'path': log_file.path,
                'size': log_file.size,
                'entries_count': len(log_file.entries),
                'threats_count': len(log_file.threats),
                'error_count': log_file.errors
            })
    
    print(f"\nTotal files processed: {len(results)}")
    print(f"Total threats detected: {sum(r['threats_count'] for r in results)}")
    
    print("\nTop files by threats:")
    sorted_results = sorted(results, key=lambda x: x['threats_count'], reverse=True)
    for r in sorted_results[:5]:
        print(f"  {r['path']}: {r['threats_count']} threats, {r['entries_count']} entries")


if __name__ == '__main__':
    main()