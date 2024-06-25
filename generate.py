#!/usr/bin/env python3
# 针对部分网站显示IP归属地的分流规则
# anti-ip-attribution generate.py
# https://github.com/zacred0rryn/anti-ip-attribution
# 从rules.yaml生成配置文件，由Actions调用。
# 读取文件：
# rules.yaml 配置文件
# 输出文件：
# rule-provider-direct.yaml rule-provider-proxy.yaml rule-provider-reject.yaml
import copy
import os
import sys

import yaml


def read_yaml(file):
    '''读取YAML文件'''
    with open(file, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def save_yaml(config, filename):
    '''保存YAML文件'''
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False)


def get_yaml_string(config):
    '''获取YAML字符串'''
    return yaml.dump(config, default_flow_style=False)


def save_string(string, filename):
    '''保存字符串'''
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(string)


def get_head_comment(config, filename=''):
    '''获取头部注释'''
    comment = ''
    comment += '# ' + config['config']['name'] + ' ' + \
        filename + ' ' + config['config']['version'] + '\n'
    return comment


def seprate_comma(string):
    '''分割字符串'''
    return string.split(',')


def check_rules(config):
    '''检查规则是否有误'''
    rules = config['config']['rules']
    # 预期中可用的规则方法
    expected_methods = ['DOMAIN', 'DOMAIN-SUFFIX',
                        'DOMAIN-KEYWORD', 'IP-CIDR', 'GEOIP', 'DST-PORT', 'IP-CIDR6']
    # 容易出错的规则方法
    questioned_methods = ['SRC-IP-CIDR',
                          'SRC-PORT', 'RULE-SET', 'MATCH', 'IP6-CIDR']
    # 预期中可用的规则部分
    expected_rules = ['DIRECT', 'REJECT', 'no-resolve']
    # rules中不需要出现IP类关键词，生成脚本会按需自动添加
    should_not_appear_rules = ['IP', 'IP归属地']
    for rule in rules:
        rule = rule.strip()
        print(rule)
        # 检查空行
        if rule == '':
            print('规则空行')
            return False
        else:
            print('非空行')
        # 检查逗号分隔
        length = len(seprate_comma(rule))
        print('length: ' + str(length))
        if length == 1:
            print('规则不完整？没有逗号分隔？：' + rule)
            return False
        elif length == 2:
            pass
        elif length == 3:
            pass
        else:
            print('规则有误？逗号分隔超过三个部分：' + rule)
            return False
        # 检查规则方法
        method = seprate_comma(rule)[0]
        print('method: ' + method)
        if method not in expected_methods and method not in questioned_methods:
            print('规则方法有误？：' + rule)
            return False
        if method.upper() in questioned_methods:
            print('规则方法有误？' + method + '可能是常见错误：' + rule)
            return False
        if method not in expected_methods and method.upper() in expected_methods:
            print('规则方法未大写？：' + rule)
            return False
        # 检查规则部分
        if length == 3:
            print('length == 3')
            this_rule = seprate_comma(rule)[2]
            print('rule: ' + this_rule)
            if this_rule not in expected_rules:
                print('规则有误？' + this_rule + '是预期之外的规则：' + rule)
                return False
            for should_not_appear_rule in should_not_appear_rules:
                if should_not_appear_rule in this_rule.upper():
                    print('规则有误？rules中不需要出现“IP归属地”类规则描述：' + rule)
                    return False
    return True


def generate_rule_provider(config):
    '''生成rule-provider.yaml'''
    comment = get_head_comment(config, 'rule-provider.yaml')
    # 为了不影响其他软件规则的生成，使用深拷贝
    rules = copy.deepcopy(config['config']['rules'])
    
    # 检查 IP rules 有无 `no-resolve` 字段，没有的话加上, 防止 DNS 泄漏
    # for i in range(len(rules)):
    #     if rules[i].startswith('IP-CIDR') and 'no-resolve' not in rules[i]:
    #         rules[i] = rules[i] + ',no-resolve'

    # https://github.com/lwd-temp/anti-ip-attribution/issues/23#issuecomment-1223931835
    direct = []
    proxy = []
    reject = []
    for rule in rules:
        
        if 'REJECT' in rule:
            reject.append(rule)
        elif 'DIRECT' in rule:
            direct.append(rule)
        else:
            proxy.append(rule)


    # Direct rules
    for i in range(len(direct)):
        if direct[i].startswith('DOMAIN'):
            direct[i] = direct[i].rstrip(',DIRECT') # Remove `,DIRECT` for rule-set generation in other repo
    print('生成rule-provider-direct.yaml')
    comment = get_head_comment(config, 'rule-provider-direct.yaml')
    output = {}
    output['payload'] = direct
    output = comment + get_yaml_string(output)
    save_string(output, os.path.join('generated', 'rule-provider-direct.yaml'))
    # Proxy rules
    print('生成rule-provider-proxy.yaml')
    comment = get_head_comment(config, 'rule-provider-proxy.yaml')
    output = {}
    output['payload'] = proxy
    output = comment + get_yaml_string(output)
    save_string(output, os.path.join('generated', 'rule-provider-proxy.yaml'))
    # Reject rules
    for i in range(len(reject)):
        if reject[i].startswith('DOMAIN') | reject[i].startswith('IP-CIDR'):
            reject[i] = reject[i].rstrip(',REJECT') # Remove `,REJECT` for rule-set generation in other repo
    print('生成rule-provider-reject.yaml')
    comment = get_head_comment(config, 'rule-provider-reject.yaml')
    output = {}
    output['payload'] = reject
    output = comment + get_yaml_string(output)
    save_string(output, os.path.join('generated', 'rule-provider-reject.yaml'))


if __name__ == '__main__':
    config = read_yaml('rules.yaml')
    print(get_head_comment(config, 'generate.py'))
    print('=====================')
    print('开始生成配置文件...')
    print('=====================')
    print(config)
    print('=====================')
    print('检查规则是否有误...')
    if check_rules(config):
        print('规则检查通过！')
        print('=====================')
        print('生成rule-provider.yaml...')
        generate_rule_provider(config)
        print('=====================')
        print('生成配置文件完成！')
    else:
        print('规则检查未通过！')
        print('=====================')
        print('请检查规则是否有误！')
        print('生成配置文件失败！')
        sys.exit(1)
