# -*- coding: utf-8 -*-
import win32serviceutil
import win32service
import win32event
from time import sleep


class DynamicDnsService(win32serviceutil.ServiceFramework):
    _svc_name_ = "DNSPod_DDNS_Service"
    _svc_display_name_ = "DnsPodDynamicDNS"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isAlive = True

    def SvcStop(self):
        # 先告诉SCM停止这个过程
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        # 设置事件
        win32event.SetEvent(self.hWaitStop)
        self.isAlive = False

    def SvcDoRun(self):
        # 等待服务被停止
        import Ddns
        cn = 0
        while self.isAlive:
            if cn % 60 == 0:
                Ddns.service(None, None, token='_YOUR_TOKEN_ID_,_YOUR_TOKEN_VALUE_', domain='_YOUR_TOP_DOMAIN_',
                             sub_domain='_YOU_SUB_DOMAIN_', log_file='_LOG_FILE_PATH_')
            else:
                sleep(1)
            cn += 1

        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(DynamicDnsService)
