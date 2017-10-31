#!/usr/bin/python
# -*- coding:utf-8 -*-
'''
作者：张翼飞
邮箱：yifie0727@gmail.com

"""新增密码输入*替代，更新获取公网地址的网站"""
最后修改时间：2014.05.14
最后修改时间：2014.04.12
最后修改时间：2014.01.20
'''

"""
接口根据Dnspod官方API规范编写；参见http://www.dnspod.cn/docs/info.html#id1
方法 POST ;类型 HTTPS;url编码 UTF-8;
在拥有 Domain下-->did 例如 baidu.com
对记录 record  -->rid 例如 www.baidu.com
获取实时IP对比IP是否一致，如果一致不修改，如果不一致，则修改
"""
__version__ = '0.2.0'
__author_email__ = 'yifei0727+dnspod@gmail.com'
__link__ = 'https://github.com/KEDYY/Ddns_CN'

import requests
import re
import json
import logging  # New in version 2.3


def initlog(logfile):
    """
    创建日志实例
    """
    logger = logging.getLogger()
    hdlr = logging.FileHandler(logfile)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.NOTSET)
    return logger


class DnspodApiError(Exception):
    """2014/4/16新增错误类，用于对外显示错误信息
    """

    def __init__(self, error_code, error_message):
        super(DnspodApiError).__init__(self)
        self.error_code = int(error_code)
        self.error_message = error_message


class DnspodApi:
    def __init__(self, user=None, pwd=None, token=None, format='json', lang='cn', error_on_empty='no', user_id=None):
        # 用户配置数据
        self.Duser = user
        self.Dpwd = pwd
        self.Dformat = format
        self.Dlang = lang
        self.Derror_on_empty = error_on_empty
        self.Dtoken = token
        self.Duser_id = user_id

    def auth_param(self):
        u"""生成公共 通用参数部分"""
        if self.Dtoken is None:
            pam = [('login_email', self.Duser),
                   ('login_password', self.Dpwd),
                   ('format', self.Dformat),
                   ('lang', self.Dlang),
                   ('error_on_empty', self.Derror_on_empty)]
        else:
            pam = [('login_token', self.Dtoken),
                   ('format', self.Dformat),
                   ('lang', self.Dlang),
                   ('error_on_empty', self.Derror_on_empty)]
        if self.Duser_id is not None:
            pam.append(('user_id', self.Duser_id))
        return pam

    def post_data(self, param_data):
        u"""将 方法,基础url,参数合并成 url请求,并向服务器发送获取结果然后返回
        """
        # UserAgent  #节点标识版本更新为全局控制，开发者邮箱
        user_agent = "Dynamic DNS API[%s]/%s(%s)" % (__link__, __version__, __author_email__)
        auth_param = self.auth_param()
        url = param_data[0]
        params = dict(auth_param + param_data[1])

        header = {'User-Agent': user_agent}
        try:
            reader = requests.post(url, data=params, headers=header)
        except Exception as e:
            logging.error(e)
            return ""
        msg = reader.text
        logging.info(msg)
        return msg

    def get_record_ip(self, domain, sub_domain):
        domain_id = self.__get_domain_id(domain)
        record_address = self.__get_record_ip(domain_id, sub_domain)
        logging.info(u"DnsPod获取到记录IP是:[%s]" % record_address)
        return record_address

    def __get_domain_id(self, domain_name):
        u"""http://www.dnspod.cn/docs/domains.html#id6"""
        url = "https://dnsapi.cn/Domain.Info"
        pam = [('domain', domain_name)]
        ret_json = self.post_data((url, pam))
        if ret_json == "":
            raise DnspodApiError(-1000, u"与服务器通讯通讯失败，未获取到数据")
        status_code = json.loads(ret_json, encoding='utf-8').get('status').get('code')
        if int(status_code) == 1:
            return json.loads(ret_json, encoding='utf-8').get('domain').get('id')
        error_code, error_message = int(status_code), self.get_error_msg(ret_json)
        logging.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (error_code, error_message))
        raise DnspodApiError(error_code, error_message)

    def __get_record_id(self, domain_id, sub_domain):
        u"""http://www.dnspod.cn/docs/records.html#id3"""
        url = "https://dnsapi.cn/Record.List"
        if domain_id is None:
            logging.warn(u"参数Domain 是None 类型")
            return None
        pam = [('domain_id', domain_id), ('sub_domain', sub_domain)]
        ret_json = self.post_data((url, pam))
        status_code = json.loads(ret_json, encoding='utf-8').get('status').get('code')
        if int(status_code) == 1:
            return json.loads(ret_json, encoding='utf-8').get('records')[0].get('id')
        error_code, error_message = int(status_code), self.get_error_msg(ret_json)
        logging.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (error_code, error_message))
        raise DnspodApiError(error_code, error_message)

    def __get_record_ip(self, domain_id, sub_domain):
        u"""http://www.dnspod.cn/docs/records.html#id3"""
        url = "https://dnsapi.cn/Record.List"
        if domain_id is None:
            logging.warn(u"参数Domain 是None 类型")
            return None
        pam = [('domain_id', domain_id), ('sub_domain', sub_domain)]
        ret_json = self.post_data((url, pam))
        status_code = json.loads(ret_json, encoding='utf-8').get('status').get('code')
        if int(status_code) == 1:
            return json.loads(ret_json, encoding='utf-8').get('records')[0].get('value')
        error_code, error_message = int(status_code), self.get_error_msg(ret_json)
        logging.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (error_code, error_message))
        raise DnspodApiError(error_code, error_message)

    def add_new_domain(self):
        u"""参见http://www.dnspod.cn/docs/domains.html#id2"""
        url = "https://dnsapi.cn/Domain.Create"
        # TODO
        raise NotImplementedError()

    def add_new_record(self, sub_domain, domain, rec_value, record_type="A", record_line=u"默认".encode('utf-8'), mx=None,
                       ttl=600):
        u"""add in 20140412,224300
        """
        url = "https://dnsapi.cn/Record.Create"
        domain_id = self.__get_domain_id(domain)
        pam = [('domain_id', domain_id),
               ('sub_domain', sub_domain),
               ('record_type', record_type),
               ('record_line', record_line),
               ('value', rec_value)]
        if record_type == 'MX':
            if mx is None:
                pam.append(('mx', mx))
            else:
                pam.append(('mx', '5'))
                logging.warn(u"邮件协议 MX 类型 需要添加MX优先级[1-20]")
        pam.append(('ttl', ttl))
        ret_json = self.post_data((url, pam))
        status_code = json.loads(ret_json, encoding='utf-8').get('status').get('code')
        if int(status_code) == 1:
            return "OK"
        error_code, error_message = int(status_code), self.get_error_msg(ret_json)
        logging.error(u"API返回错误,错误码:%d,错误说明:%s" % (error_code, error_message))
        raise DnspodApiError(error_code, error_message)

    def dynamic_dns_record(self, value_IP, domain, sub_domain, record_line=u"默认".encode('utf-8')):
        url = "https://dnsapi.cn/Record.Ddns"
        domain_id = self.__get_domain_id(domain)
        pam = [('domain_id', domain_id),
               ('record_id', self.__get_record_id(domain_id, sub_domain)),
               ('sub_domain', sub_domain),
               ('record_line', record_line),
               ('value', value_IP)]
        ret_json = self.post_data((url, pam))
        status_code = json.loads(ret_json, encoding='utf-8').get('status').get('code')
        if int(status_code) == 1:
            return "OK"
        error_code, error_message = int(status_code), self.get_error_msg(ret_json)
        logging.error(u"API返回错误,错误码:%d,错误说明:%s" % (error_code, error_message))
        raise DnspodApiError(error_code, error_message)

    @staticmethod
    def get_error_info(error_code):
        if int(error_code) == -1:
            return u"登陆失败"
        elif int(error_code) == -2:
            return u"API使用超出限制"
        elif int(error_code) == -3:
            return u"不是合法代理 (仅用于代理接口)"
        elif int(error_code) == -4:
            return u"不在代理名下 (仅用于代理接口)"
        elif int(error_code) == -7:
            return u"无权使用此接口"
        elif int(error_code) == -8:
            return u"登录失败次数过多，帐号被暂时封禁"
        elif int(error_code) == -99:
            return u"此功能暂停开放，请稍候重试"
        elif int(error_code) == 1:
            return u"操作成功"
        elif int(error_code) == 2:
            return u"只允许POST方法"
        elif int(error_code) == 3:
            return u"未知错误"
        elif int(error_code) == 6:
            return u"用户ID错误 (仅用于代理接口)"
        elif int(error_code) == 7:
            return u"用户不在您名下 (仅用于代理接口)"
        else:
            return u"无说明" + error_code

    @staticmethod
    def get_error_msg(last_json_data):
        """2014/4/16 增加服务器返回错误信息
        """
        return json.loads(last_json_data, encoding='utf-8').get('status').get("message")


class MyDDns:
    def __init__(self, userEmail=None, userPasswd=None, domain=None, subDomain=None, token=None):
        if token:
            self.ddns = DnspodApi(token=token)
        else:
            self.ddns = DnspodApi(user=userEmail, pwd=userPasswd)
        try:
            self.record_address = self.ddns.get_record_ip(domain, subDomain)
        # 2014/4/16 对错误类增加定义和改正
        except DnspodApiError as e:
            raise DnspodApiError(e.error_code, e.error_message)
        except Exception:
            logging.warn(u"获取记录地址失败")
            self.record_address = ""
        try:
            self.current_address = self.get_public_address()
        except Exception as e:
            logging.error(e)
            self.current_address = ''
        self.domain = domain
        self.sub_domain = subDomain

    @staticmethod
    def get_public_address():
        u"""
        :return:
        """
        link = "http://ip.cn"
        status = requests.get(link)
        address = re.match(r'.*<code>([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})</code>.*',
                           status.text[status.text.find(u'IP\uff1a<code>'):]).groups()[0]
        logging.info(u"主机当前IP地址是:[%s]" % address)
        return address

    def check_address(self):
        try:
            if self.record_address == "":
                self.record_address = self.ddns.get_record_ip(self.domain,
                                                              self.sub_domain)  # 20140416 fix bug add self.
            if self.current_address == "":
                self.current_address = self.get_public_address()

            if self.record_address == self.current_address:
                return "OK"
            else:
                return self.ddns.dynamic_dns_record(self.current_address, self.domain, self.sub_domain)
        except DnspodApiError as e:
            raise DnspodApiError(e.error_code, e.error_message)
        except Exception as e:
            logging.error(e)
        return "FALSE"

    def add_record(self):
        """2014/4/12 增加添加接口
        """
        if self.record_address != "":
            self.check_address()
            return u"记录中已存在，无需重新添加,但已更新IP"

        logic = self.ddns.add_new_record(self.sub_domain, self.domain, self.current_address)
        if logic == "OK":
            return u"成功添加记录"
        else:
            return u"添加失败"


""" 新增密码隐藏为*号替代"""
import getpass, sys, os

_real_getpass = getpass.getpass


def getpass_getpass(prompt='EnterPassword:', stream=None):
    """this code from GoogleAppEngine  appcfg.py"""
    try:
        import msvcrt
        password = ''
        sys.stdout.write(prompt)
        while 1:
            ch = msvcrt.getch()
            if ch == '\b':
                if password:
                    password = password[:-1]
                    sys.stdout.write('\b \b')
                else:
                    continue
            elif ch == '\r':
                sys.stdout.write(os.linesep)
                return password
            else:
                password += ch
                sys.stdout.write('*')
    except Exception:
        return _real_getpass(prompt, stream)


getpass.getpass = getpass_getpass


def service(name, password, token, domain, sub_domain, log_file):
    try:
        initlog(logfile=log_file)
        doObj = MyDDns(userEmail=name, userPasswd=password, token=token, domain=domain, subDomain=sub_domain)
    except DnspodApiError as e:
        print u"调用失败，错误码:%d,错误信息:%s" % (e.error_code, e.error_message)
        return None


def test():
    userNm = raw_input("Input user's email:")
    passwd = getpass.getpass("Input user's password:")
    domain = raw_input("Input your Top Domain:")
    subDom = raw_input("Input your sub Domain:")
    try:
        doObj = MyDDns(userNm, passwd, domain=domain, subDomain=subDom)
    except DnspodApiError as e:
        print u"调用失败，错误码:%d,错误信息:%s" % (e.error_code, e.error_message)
        return None
    print doObj.add_record()
    raw_input("Press any key to continue....")


def main():
    token_id = raw_input("Input token id:")
    token_vl = raw_input("Input token value:")

    domain = raw_input("Input your Top Domain:")
    subDom = raw_input("Input your sub Domain:")
    try:
        doObj = MyDDns(domain=domain, subDomain=subDom, token='%s,%s' % (token_id, token_vl))
    except DnspodApiError as e:
        print u"调用失败，错误码:%d,错误信息:%s" % (e.error_code, e.error_message)
        return None
    print doObj.add_record()
    raw_input("Press any key to continue....")


if __name__ == '__main__':
    initlog('./trans.log')
    test()
