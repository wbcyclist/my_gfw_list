#!/usr/bin/env python3
#coding=utf-8
import sys
import os
import errno
from socket import inet_aton
import struct

if sys.version_info<(3,0,0):
    sys.stderr.write("You need python 3 or later to run this script\n")
    exit(1)

import ipaddress
import validators


def make_sure_path_exists(path):
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


def listdir(path):
    dirs, files, links = [], [], []
    for name in os.listdir(path):
        path_name = os.path.join(path, name)
        if os.path.isdir(path_name):
            dirs.append(name)
        elif os.path.isfile(path_name):
            files.append(name)
        elif os.path.islink(path_name):
            links.append(name)
    return dirs, files, links


def sorted_ip_network(ip_list):
    ip_obj_list = [ipaddress.ip_network(ip) for ip in ip_list]
    return [str(obj) for obj in sorted(ip_obj_list)]


def sorted_ip_address(ip_list):
    ip_obj_list = [ipaddress.ip_address(ip) for ip in ip_list]
    return [str(obj) for obj in sorted(ip_obj_list)]


def load_rule_list(rule_dir):
    domain_list = []
    ipv4_list = []
    ipv4_CIDR_list = []
    ipv6_list = []
    ipv6_CIDR_list = []

    rule_files = [x for x in listdir(rule_dir)[1] if os.path.splitext(x)[1].lower()=='.txt']
    for filename in rule_files:
        filepath = os.path.join(rule_dir, filename)
        with open(filepath, 'r') as rf:
            for line in rf.readlines():
                line = line.strip()
                if not len(line) or line.startswith('#') or line.startswith('/'):
                    continue

                if validators.domain(line):
                    # 域名
                    domain_list.append(line)
                elif validators.ipv4(line):
                    # ipv4
                    ipv4_list.append(line)
                    ipv4_CIDR_list.append(ipaddress.ip_network(line))
                elif validators.ipv6(line):
                    # ipv6
                    ipv6_list.append(line)
                    ipv6_CIDR_list.append(ipaddress.ip_network(line))
                elif line.find('/') > 0:
                    try:
                        temp_net = ipaddress.ip_network(line)
                        if isinstance(temp_net, ipaddress.IPv4Network):
                            # ipv4 段
                            ipv4_CIDR_list.append(temp_net)
                        else:
                            # ipv6 段
                            ipv6_CIDR_list.append(line)
                    except ValueError:
                        print('无效值:', line, 'in', filepath)
                else:
                    print('无效值:', line, 'in', filepath)

    ipv4_CIDR_list = [str(ip) for ip in ipv4_CIDR_list]
    ipv6_CIDR_list = [str(ip) for ip in ipv6_CIDR_list]
    # 去重并排序
    domain_list = list(set(domain_list))
    ipv4_list = list(set(ipv4_list))
    ipv6_list = list(set(ipv6_list))
    ipv4_CIDR_list = list(set(ipv4_CIDR_list))
    ipv6_CIDR_list = list(set(ipv6_CIDR_list))

    domain_list = sorted(domain_list)
    ipv4_list = sorted_ip_address(ipv4_list)
    ipv6_list = sorted_ip_address(ipv6_list)
    ipv4_CIDR_list = sorted_ip_network(ipv4_CIDR_list)
    ipv6_CIDR_list = sorted_ip_network(ipv6_CIDR_list)

    # print(domain_list)
    # print(ipv4_list)
    # print(ipv4_CIDR_list)
    # print(ipv6_list)
    # print(ipv6_CIDR_list)
    return domain_list, ipv4_list, ipv4_CIDR_list, ipv6_list, ipv6_CIDR_list


def add_gfw_domain_merlin(file_wf, domain):
    file_wf.write('server=/.' + domain + '/127.0.0.1#7913\n')
    file_wf.write('ipset=/.' + domain + '/gfwlist\n')


def gen_merlin_conf(root_dir):
    proxy_dir = os.path.join(root_dir, 'list', 'proxy_list')
    output_file = os.path.join(root_dir, 'output', 'merlin', 'gfwlist.conf')
    make_sure_path_exists(os.path.dirname(output_file))

    try:
        file_wf = open(output_file, 'w')
        domain_list, ipv4_list, ipv4_CIDR_list, ipv6_list, ipv6_CIDR_list = load_rule_list(proxy_dir)
        # 域名
        for line in domain_list:
            add_gfw_domain_merlin(file_wf, line)
        # # ipv4
        # for line in ipv4_list:
        #     pass
        # # ipv4 CIDR
        # for line in ipv4_CIDR_list:
        #     pass
        # # ipv6
        # for line in ipv6_list:
        #     pass
        # # ipv6 CIDR
        # for line in ipv6_CIDR_list:
        #     pass
    finally:
        if file_wf:
            file_wf.close()


def gen_surge_conf(root_dir):
    block_dir = os.path.join(root_dir, 'list', 'block_list')
    proxy_dir = os.path.join(root_dir, 'list', 'proxy_list')
    tmp_file = os.path.join(root_dir, 'template', 'surge', 'surge.conf')
    output_file = os.path.join(root_dir, 'output', 'surge', 'surge.conf')
    make_sure_path_exists(os.path.dirname(output_file))

    # block rule
    block_content = ''
    domain_list, ipv4_list, ipv4_CIDR_list, ipv6_list, ipv6_CIDR_list = load_rule_list(block_dir)
    # 域名
    for line in domain_list:
        block_content += 'DOMAIN-SUFFIX,' + line + ',REJECT\n'
    # ipv4 CIDR
    block_content += '\n'
    for line in ipv4_CIDR_list:
        block_content += 'IP-CIDR,' + line + ',REJECT,no-resolve\n'

    # proxy rule
    proxy_content = ''
    domain_list, ipv4_list, ipv4_CIDR_list, ipv6_list, ipv6_CIDR_list = load_rule_list(proxy_dir)
    # 域名
    for line in domain_list:
        proxy_content += 'DOMAIN-SUFFIX,' + line + ',PROXY,force-remote-dns\n'
    # ipv4 CIDR
    proxy_content += '\n'
    for line in ipv4_CIDR_list:
        proxy_content += 'IP-CIDR,' + line + ',PROXY,no-resolve\n'

    with open(tmp_file, 'r', encoding='utf-8') as rf, \
            open(output_file, 'w', encoding='utf-8') as wf:
        file_content = rf.read()
        file_content = file_content.replace('__BLOCK__', block_content)
        file_content = file_content.replace('__PROXY__', proxy_content)
        wf.write(file_content)


def main():
    root_dir = os.path.abspath('.')

    print('生成 merlin 规则...')
    gen_merlin_conf(root_dir)

    print('生成 surge 规则...')
    gen_surge_conf(root_dir)

    print ('处理完毕! 请检查output目录')


if __name__ == '__main__':
    main()
