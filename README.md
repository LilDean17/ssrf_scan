# SSRF Scanner - Burp Suite Plugin

SSRF 带外检测插件，通过 ceye.io 回调平台自动识别 Burp Proxy 流量中的 SSRF 漏洞。

## 功能说明

基于 `ssrf_fuzzer` 项目改造的 Burp Suite SSRF 检测插件，使用 [ceye.io](http://ceye.io) 作为带外（Out-of-Band）回调平台。

主要功能：

1. **监听 Proxy 请求**：自动拦截通过 Burp Proxy 的所有 HTTP 请求
2. **URL 参数扫描**：智能识别请求参数中的 URL 值（基于参数内容而非参数名）
3. **带外地址替换**：将识别到的 URL / IP / 域名参数替换为 `*.ceye.io` 带外地址
4. **自动检测带外响应**：通过 ceye.io API (`api.ceye.io/v1/records`) 检查 DNS/HTTP 记录，验证 SSRF 漏洞
5. **可视化结果展示**：类似 Proxy 的请求列表界面，双击查看详情

## 与 ssrf_fuzzer 项目的差异

| 项 | ssrf_fuzzer | ssrf_scan (本项目) |
| --- | --- | --- |
| OOB 平台 | eyes.sh | ceye.io |
| API 域名 | eyes.sh (HTTPS) | api.ceye.io (HTTP) |
| 默认回调域名 | l1ldean.eyes.sh | <your-ceye-domain>.ceye.io |
| API 响应格式 | `True` / `False` 文本 | JSON（含 `data[].name` 字段） |
| 命中判断 | 响应体等于 `True` | 响应体包含 `{prefix}.{domain}` 子串（大小写不敏感） |
| 跳过域名 | `*.eyes.sh` | `*.ceye.io` |
| 插件名 | `SSRF Scanner - Eyes` | `SSRF Scanner - Ceye` |

## 使用方法

### 编译插件

1. 修改 `compile.bat` 中的 `BURP_JAR` 路径，指向你的 Burp Suite 安装目录
2. 运行 `compile.bat` 进行编译
3. 编译成功后会生成 `ssrf-scan.jar`
4. 也可以使用 Maven：`mvn clean package`，输出 jar 在项目根目录

### 加载插件

1. 打开 Burp Suite
2. 进入 `Extender` -> `Extensions` 标签
3. 点击 `Add` 按钮
4. 选择编译好的 `ssrf-scan.jar` 文件（Java 类型）
5. 插件加载后会出现 `SSRF Scanner` 标签

### 配置和使用

1. 在 `SSRF Scanner` 标签中确认配置：
   - **Ceye Domain**: `<your-ceye-domain>.ceye.io`
   - **Ceye Token**: `<your-ceye-token>`

2. 点击 `Start Scanner` 开始扫描

3. 通过 Burp Proxy 的所有请求都会被自动检测

4. 发现 SSRF 漏洞时，结果会显示在下方表格中：
   - 序号
   - 目标主机
   - 请求 URL
   - 触发参数（普通参数为参数名，JSON 参数为 JSONPath）
   - OOB Payload

5. 双击结果行可查看完整的请求/响应详情

## ceye.io API

本插件使用 ceye.io 公开的查询接口：

- DNS 记录：`GET http://api.ceye.io/v1/records?token={token}&type=dns`
- HTTP 记录：`GET http://api.ceye.io/v1/records?token={token}&type=http`

响应示例：

```json
{
  "meta": {"code": 200, "message": "OK"},
  "data": [
    {"id": "1", "type": "A", "name": "abc12345.<your-ceye-domain>.ceye.io", "value": "1.2.3.4", "created": "..."}
  ]
}
```

插件会等待 `Thread.sleep(2000)` 后查询 DNS 与 HTTP 两类记录，判断响应体的 `name` 字段是否包含本次测试的随机前缀子串。

## Payload 形式

- **URL 参数**：完整替换为 `http://{random}.<your-ceye-domain>.ceye.io`
- **IP / 域名参数**：原值中匹配到的 IP 或域名被替换为 `{random}.<your-ceye-domain>.ceye.io`（不携带协议，保留原始前缀上下文）
- **JSON 字符串**：逻辑同上，按 JSONPath 定位后替换

## 注意事项

1. ceye.io 公共 DNS / HTTP 记录会有延迟，sleep 时间如不足可调整 `Thread.sleep(2000)` 为更长值
2. 确保 ceye.io 账户有效且 API token 正确
3. 扫描过程中请保持网络连接正常
4. 检测结果可能存在误报，建议手动验证
5. 仅用于授权的安全测试

## 文件结构

```
ssrf_scan/
├── src/
│   └── main/
│       └── java/
│           └── burp/
│               └── BurpExtender.java   # 插件源代码
├── pom.xml                             # Maven 配置
├── README.md                           # 说明文档
└── ssrf-scan.jar                       # 编译后的插件（编译后生成）
```
