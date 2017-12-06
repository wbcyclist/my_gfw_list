#!/usr/bin/env python3
#coding=utf-8
import sys
import os
import errno

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


def add_gfw_domain_merlin(merlin_wf, domain):
    merlin_wf.write('server=/.' + domain + '/127.0.0.1#7913\n')
    merlin_wf.write('ipset=/.' + domain + '/gfwlist\n')


def gen_gfw_conf(root_dir, proxy_dir):
    output_merlin_gfw_file = os.path.join(root_dir, 'output', 'merlin', 'gfwlist.conf')
    make_sure_path_exists(os.path.dirname(output_merlin_gfw_file))

    try:
        merlin_wf = open(output_merlin_gfw_file, 'w')

        proxy_files = [x for x in listdir(proxy_dir)[1] if os.path.splitext(x)[1].lower()=='.txt']
        for filename in proxy_files:
            filepath = os.path.join(proxy_dir, filename)
            with open(filepath, 'r') as rf:
                for line in rf.readlines():
                    line = line.strip()
                    if not len(line) or line.startswith('#') or line.startswith('/'):
                        continue

                    if validators.domain(line):
                        # 域名
                        add_gfw_domain_merlin(merlin_wf, line)
                    elif validators.ipv4(line):
                        # ipv4
                        pass
                    elif validators.ipv6(line):
                        # ipv6
                        pass
                    elif line.find('/') > 0:
                        try:
                            temp_net = ipaddress.ip_network(line)
                            if isinstance(temp_net, ipaddress.IPv4Network):
                                # ipv4 段
                                pass
                            else:
                                # ipv6 段
                                pass
                        except ValueError:
                            print('无效值:', line, 'in', filepath)
                    else:
                        print('无效值:', line, 'in', filepath)
    finally:
        if merlin_wf:
            merlin_wf.close()


def main():
    root_dir = os.path.abspath('.')
    block_dir = os.path.join(root_dir, 'list', 'block_list')
    proxy_dir = os.path.join(root_dir, 'list', 'proxy_list')

    print('生成 GFW List...')
    gen_gfw_conf(root_dir, proxy_dir)

    print ('处理完毕! 请检查output目录')


if __name__ == '__main__':
    main()
