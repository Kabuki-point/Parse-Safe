#!/usr/bin/env python3
"""可信 IP 白名单管理工具"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dir_parser import TrustedIPLearner, IPWhitelist


def main():
    parser = argparse.ArgumentParser(description='可信 IP 白名单管理工具')
    subparsers = parser.add_subparsers(dest='command', help='子命令')
    
    add_parser = subparsers.add_parser('add', help='添加 IP 到白名单')
    add_parser.add_argument('ips', nargs='+', help='要添加的 IP 地址')
    
    remove_parser = subparsers.add_parser('remove', help='从白名单移除 IP')
    remove_parser.add_argument('ips', nargs='+', help='要移除的 IP 地址')
    
    list_parser = subparsers.add_parser('list', help='列出所有白名单 IP')
    
    clear_parser = subparsers.add_parser('clear', help='清空白名单')
    
    check_parser = subparsers.add_parser('check', help='检查 IP 是否在白名单中')
    check_parser.add_argument('ip', help='要检查的 IP 地址')
    
    args = parser.parse_args()
    
    learner = TrustedIPLearner([], 0)
    existing = learner.load_existing()
    
    if args.command == 'add':
        for ip in args.ips:
            existing.add(ip)
        learner.save(existing)
        print(f"Added {len(args.ips)} IP(s)")
    
    elif args.command == 'remove':
        for ip in args.ips:
            existing.discard(ip)
        learner.save(existing)
        print(f"Removed {len(args.ips)} IP(s)")
    
    elif args.command == 'list':
        if existing:
            print("Whitelisted IPs:")
            for ip in sorted(existing):
                print(f"  {ip}")
        else:
            print("No IPs in whitelist")
    
    elif args.command == 'clear':
        learner.save(set())
        print("Whitelist cleared")
    
    elif args.command == 'check':
        wl = IPWhitelist(list(existing))
        if wl.is_whitelisted(args.ip):
            print(f"OK {args.ip} is whitelisted")
        else:
            print(f"FAIL {args.ip} is NOT whitelisted")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
