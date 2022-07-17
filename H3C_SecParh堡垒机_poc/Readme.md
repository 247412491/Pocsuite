# Readme

## 安装

```
git clone https://github.com/247412491/pocsuite-.git
cd H3C_SecParh堡垒机_poc
pip3 install -r requirements.txt
```

## 使用

poc

批量测试

```
python3 cli.py  -r ./pocs/H3C_SecParh堡垒机_poc.py  --dork-fofa app="H3C-SecPath-运维审计系统" && body="2018"  --max-size 500 --save-file ./H3C_SecParh堡垒机.txt  --threads 50
```

单url测试

```
python3 cli.py  -r ./pocs/H3C_SecParh堡垒机_poc.py  -u http:xxxxx.com   --verify
```



## 免责声明🧐

本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建测试环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

# Pocsuite