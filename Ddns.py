#!/usr/bin/python
#-*- coding:utf-8 -*-
'''
作者：张翼飞
邮箱：yifie0727@gmail.com
最后修改时间：2014.04.12
最后修改时间：2014.01.20
'''
"""
接口根据Dnspod官方API规范编写；参见http://www.dnspod.cn/docs/info.html#id1
方法 POST ;类型 HTTPS;URL编码 UTF-8;
在拥有 Domain下-->did 例如 baidu.com
对记录 record  -->rid 例如 www.baidu.com
获取实时IP对比IP是否一致，如果一致不修改，如果不一致，则修改
"""
from urllib import urlencode
import urllib2,json

import  logging    #New in version 2.3
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

mlog = initlog('./trans.log')
DDNSAPI_VERSION = "0.1.1"
class DnspodApiError(Exception):
    """2014/4/16新增错误类，用于对外显示错误信息
    """
    def __init__(self, errCode, errMsg):
        Exception.__init__(self)
        self.errCode = int(errCode)
        self.errMsg  = errMsg

class DnspodApi():
    def __init__(self, Duser, Dpwd, Dformat = 'json', Dlang = 'cn', Derror_on_empty = 'no', Duser_id = None):
        #用户配置数据
        self.Duser = Duser
        self.Dpwd  = Dpwd
        self.Dformat = Dformat
        self.Dlang = Dlang
        self.Derror_on_empty = Derror_on_empty
        self.Duser_id = Duser_id

    def authPam(self):
        u"""生成公共 通用参数部分"""
        pam = [('login_email', self.Duser), ('login_password', self.Dpwd), 
               ('format', self.Dformat), ('lang', self.Dlang), 
               ('error_on_empty', self.Derror_on_empty), ('user_id', self.Duser_id)]
        pam = urlencode(pam)
        return pam 
    def PostData( self ,pamData ):
        u"""将 方法,基础URL,参数合并成 URL请求,并向服务器发送获取结果然后返回
        """
        #UserAgent  #节点标识版本更新为全局控制，开发者邮箱(定值)更改为 用户邮箱动态值
        UserAgent = "DNSPOD PYTHON2 FOR DDNS API/(%s)(%s)" %(DDNSAPI_VERSION, self.Duser)
        AuthPam = self.authPam()
        URL = pamData[0] 
        urlData = AuthPam + '&'+ pamData[1]
        request = urllib2.Request(URL)
        request.add_data( urlData )
        request.add_header('User-Agent', UserAgent)
        try:
            reader= urllib2.urlopen(request)
        except Exception as e:
            mlog.error(e)
            return ""
        msg = reader.read()
        mlog.info(msg)
        return msg        
    def GetRecordIP(self, domain, subdomain):
        DomainId = self.__GetDomainID( domain )
        RecIP = self.__GetRecordIP(DomainId, subdomain)
        mlog.info( u"DNSPOD获取到记录IP是:[%s]" % RecIP)
        return RecIP

    def __GetDomainID(self, DomainName):
        u"""http://www.dnspod.cn/docs/domains.html#id6"""
        URL = "https://dnsapi.cn/Domain.Info"  
        pam = [('domain', DomainName)]
        pam = urlencode(pam)
        retJson = self.PostData( (URL, pam ))
        if retJson == "":
            raise DnspodApiError(-1000, u"与服务器通讯通讯失败，未获取到数据")
        statusCode = json.loads(retJson,  encoding='utf-8').get('status').get('code')
        if int(statusCode) == 1:
            return json.loads(retJson,  encoding='utf-8').get('domain').get('id')
        errCode, errMsg = int(statusCode), self.getErrorMsg( retJson )
        mlog.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (errCode, errMsg) )
        raise DnspodApiError(errCode, errMsg)
    def __GetRecordID(self, DomainID, subDomain):
        u"""http://www.dnspod.cn/docs/records.html#id3"""
        URL = "https://dnsapi.cn/Record.List"
        if DomainID == None:
            mlog.warn(u"参数Domain 是None 类型")
            return None
        pam = [('domain_id', DomainID), ('sub_domain', subDomain)]
        pam =  urlencode(pam)
        retJson = self.PostData( (URL, pam) )
        statusCode = json.loads(retJson,  encoding='utf-8').get('status').get('code')
        if int(statusCode) == 1:
            return json.loads(retJson,  encoding='utf-8').get('records')[0].get('id')
        errCode, errMsg = int(statusCode), self.getErrorMsg( retJson )
        mlog.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (errCode, errMsg) )
        raise DnspodApiError(errCode, errMsg)
    def __GetRecordIP(self, DomainID, subDomain):
        u"""http://www.dnspod.cn/docs/records.html#id3"""
        URL = "https://dnsapi.cn/Record.List"
        if DomainID == None:
            mlog.warn(u"参数Domain 是None 类型")
            return None
        pam = [('domain_id', DomainID), ('sub_domain', subDomain)]
        pam =  urlencode(pam)
        retJson = self.PostData( (URL, pam) )
        statusCode = json.loads(retJson,  encoding='utf-8').get('status').get('code')
        if int(statusCode) == 1:
            return json.loads(retJson,  encoding='utf-8').get('records')[0].get('value')
        errCode, errMsg = int(statusCode), self.getErrorMsg( retJson )
        mlog.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (errCode, errMsg) )
        raise DnspodApiError(errCode, errMsg)     

    def AddNewDomain(self):
        u"""参见http://www.dnspod.cn/docs/domains.html#id2"""
        URL = "https://dnsapi.cn/Domain.Create"
        #todo
    def AddNewRecord(self, subdomain, domain, rec_value, record_type="A", record_line=u"默认".encode('utf-8'), mx=None, ttl=600):
        u"""add in 20140412,224300
        """
        URL = "https://dnsapi.cn/Record.Create"
        domain_id = self.__GetDomainID(domain)
        pam = [('domain_id', domain_id),
               ('sub_domain', subdomain),
               ('record_type', record_type),('record_line', record_line),
               ('value', rec_value)]
        if record_type == 'MX':
            if  mx == None:
                pam.append(('mx', mx))
            else:
                pam.append(('mx', '5'))
                mlog.warn(u"[AddNewRecord:]邮件协议 MX 类型 需要添加MX优先级[1-20]")
        pam.append( ('ttl', ttl) )
        pam =  urlencode(pam)
        retJson = self.PostData( (URL, pam) )
        statusCode = json.loads(retJson, encoding='utf-8').get('status').get('code')
        if int(statusCode) == 1:
            return "OK"
        errCode, errMsg = int(statusCode), self.getErrorMsg( retJson )
        mlog.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (errCode, errMsg) )
        raise DnspodApiError(errCode, errMsg)

    def DdnsRecord( self, value_IP, domain, sub_domain, record_line = u"默认".encode('utf-8')):
        URL = "https://dnsapi.cn/Record.Ddns"
        domain_id = self.__GetDomainID(domain)
        pam = [('domain_id', domain_id), 
               ('record_id', self.__GetRecordID( domain_id, sub_domain ) ), 
               ('sub_domain', sub_domain), 
               ('record_line', record_line),
               ('value', value_IP )]
        pam =  urlencode(pam)
        retJson = self.PostData( (URL, pam) )
        statusCode = json.loads(retJson, encoding='utf-8').get('status').get('code')
        if int(statusCode) == 1:
            return "OK"
        errCode, errMsg = int(statusCode), self.getErrorMsg( retJson )
        mlog.error(u"[__GetRecordIP:]API返回错误,错误码:%d,错误说明:%s" % (errCode, errMsg) )
        raise DnspodApiError(errCode, errMsg)
    def errorInfo (self, errorCode ):
        if ( int(errorCode) == -1):
            return u"登陆失败"
        elif ( int(errorCode) == -2):
            return u"API使用超出限制"
        elif ( int(errorCode) == -3):
            return u"不是合法代理 (仅用于代理接口)"
        elif ( int(errorCode) == -4):
            return u"不在代理名下 (仅用于代理接口)"
        elif ( int(errorCode) == -7):
            return u"无权使用此接口"
        elif ( int(errorCode) == -8):
            return u"登录失败次数过多，帐号被暂时封禁"
        elif ( int(errorCode) == -99):
            return u"此功能暂停开放，请稍候重试"
        elif ( int(errorCode) == 1):
            return u"操作成功"
        elif ( int(errorCode) == 2):
            return u"只允许POST方法"
        elif ( int(errorCode) == 3):
            return u"未知错误"
        elif ( int(errorCode) == 6):
            return u"用户ID错误 (仅用于代理接口)"
        elif ( int(errorCode) == 7):
            return u"用户不在您名下 (仅用于代理接口)"
        else:
            return u"无说明" + errorCode
    def getErrorMsg(self, lastJosnData):
        """2014/4/16 增加服务器返回错误信息
        """
        return json.loads(lastJosnData,  encoding='utf-8').get('status').get("message")

    def __del__(self):
        pass


import requests as rt
class MyDDns( ):
    def __init__(self, userEmail, userPasswd, domain, subDomain):
        self.ddns = DnspodApi(userEmail, userPasswd)
        try:
            self.RecIP = self.ddns.GetRecordIP(domain, subDomain)
        #2014/4/16 对错误类增加定义和改正
        except DnspodApiError as apierr: 
            raise DnspodApiError(apierr.errCode, apierr.errMsg)
        except Exception as err:
            mlog.warn(u"获取记录地址失败")
            self.RecIP = ""
        try:
            self.CurIP = self.GetMyPubIP()
        except Exception as e:
            import time
            self.CurIP = ""
            for i in range(600):
                time.sleep(1)
                try:
                    self.CurIP = self.GetMyPubIP()
                    if self.CurIP != "":
                        break
                except Exception as e:
                    continue
        self.domain  = domain
        self.subdomain  = subDomain
    def GetMyPubIP(self):
        #URL = "http://v.kedyy.com/api/getip"
        #URL = "http://justurl.sinaapp.com/api/getip"
        URL = "http://iframe.ip138.com/ic.asp"
        ct = rt.get( URL )
        self.curIP = ct.text.split('[')[1].split(']')[0]
        mlog.info(u"主机当前IP地址是:[%s]" % self.curIP)
        return self.curIP
    def CheckIP(self):
        try:
            if self.RecIP == "":
                self.RecIP = self.ddns.GetRecordIP(self.domain, self.subdomain) #20140416 fix bug add self.
            if self.CurIP == "":
                self.CurIP = self.GetMyPubIP()
            if self.RecIP == self.curIP:
                return "OK"
            else:
                ret = self.ddns.DdnsRecord( self.curIP, self.domain, self.subdomain )
        except DnspodApiError as e:
            raise DnspodApiError(e.errCode, e.errMsg)
        except Exception as e:
            mlog.error(e)
        return "FALSE"
    def AddRecord(self):
        """2014/4/12 增加添加接口
        """
        if self.RecIP != "":
            self.CheckIP()
            return u"记录中已存在，无需重新添加,但已更新IP"
        logic = self.ddns.AddNewRecord( self.subdomain, self.domain, self.curIP)
        if logic == "OK":
            return u"成功添加记录"
        else:
            return u"添加失败"

def  main():
    userNm=raw_input("Input user's email:")
    passwd=raw_input("Input user's password:")
    domain=raw_input("Input your Top Domain:")
    subDom=raw_input("Input your sub Domain:")
    try:
        doObj = MyDDns(userNm, passwd, domain, subDom)
    except DnspodApiError as e:
        print u"调用失败，错误码:%d,错误信息:%s" % (e.errCode, e.errMsg)
        return None
    print doObj.AddRecord()

if __name__ == '__main__':
    main()
