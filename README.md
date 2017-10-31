Ddns_CN
=======

该接口来源于Dnspod提供的公开API开发，基于Python2编写

接口目前版本 0.2.0
使用前提：
    1.拥有独立的顶级域名，切拥有DNS服务器解析转移的管理权限
    2.在DnsPod.com上注册了账户，切已经将顶级域名的DNS服务器NS记录指向了到了DnsPod上提供的服务器地址
    3.目前版本不支持DnsPod的动态令牌，所以请勿开启
    4.在DnsPod上只有一个顶级域名

目前版本提供两个动态接口
    1.创建子域名
    2.动态更新已添加的子域名的当前地址。
建议大家直接调用第一个接口，因为第一个接口会判断是否已经添加，如果添加了则会自行调用第二个接口。

### Site Access: 
* Get Public IP Address from [IP.cn](http://ip.cn)
* Update Record on [DnsPod](https://dnspod.cn)



## WINDOWS Service
### Required
* requests
* pywin32 Download from [sourceforge](https://sourceforge.net/projects/pywin32/files/pywin32/)

### Config


### Help Info
Execute this commond 
> python svc_ddns.py 

then you will get help message like this

```
Usage: 'svc_ddns.py [options] install|update|remove|start [...]|stop|restart [...]|debug [...]'
Options for 'install' and 'update' commands only:
 --username domain\username : The Username the service is to run under
 --password password : The password for the username
 --startup [manual|auto|disabled|delayed] : How the service starts, default = manual
 --interactive : Allow the service to interact with the desktop.
 --perfmonini file: .ini file to use for registering performance monitor data
 --perfmondll file: .dll file to use when querying the service for
   performance data, default = perfmondata.dll
Options for 'start' and 'stop' commands only:
 --wait seconds: Wait for the service to actually start or stop.
                 If you specify --wait with the 'stop' option, the service
                 and all dependent services will be stopped, each waiting
                 the specified period.
```


### Install

> python svc_ddns.py --startup delayed install
> python svc_ddns.py start

### Update
> python svc_ddns.py --startup delayed update

### Remove
stop then remove service
> python svc_ddns.py stop
> python svc_ddns.py remove


## Linux

TODO