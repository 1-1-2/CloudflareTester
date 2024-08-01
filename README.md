# 简介
Cloudflare Tester 是一个使用 Golang 编写的小工具，用于测试 Cloudflare IP 地址的延迟、回源时间和下载速度，并将结果输出到 CSV 文件中。

# Action 编译
详见本库 Github Actions。

# 手动编译
首先安装 Golang 和 Git，然后在终端中运行以下命令：

```sh
git clone https://github.com/1-1-2/CloudflareTester.git
cd CloudflareTester
go build -o CFtester main.go
```

这将编译可执行文件 `CFtester`。

# 参数说明
`CFtester` 接受以下参数：

- `-ipin`：指定IP地址文件的名称。默认值为`ip.txt`。
- `-xout`：输出文件的前缀。默认值为`result`。
- `-tcport`：TCP测试端口号。默认值为443。
- `-th`：并发请求的最大协程数。默认值为100。
- `-spdt`：下载测速的协程数量，设为0时禁用测速。默认值为0。
- `-spdurl`：测速文件的URL。默认值为`https://speed.cloudflare.com/__down?bytes=500000000`。
- `-origin`：回源测试的地址，支持英文逗号分隔的多个目标。默认留空禁用回源测试。
- `-tls`：是否强制启用TLS。默认值为false。
- `-attempt`：测试中每个IP的最大重试次数。默认值为5。

# 运行
在终端运行命令示例：

```sh
# 启用回源和测速
./CFtester -ipin=myip.txt -spdt=5 -origin=www.cloudflare.com,www.example.com

# 指定输入和输出的前缀
./CFtester -ipin=myip.txt -xout=myrst

# 启用全局tls，减少线程数和最大重试次数
./CFtester -tls=true -th=50 -attempt=3
```

# 输出
测试结果以CSV文件格式输出，包含以下字段：

- IP地址
- 端口
- 使用TLS
- 数据中心
- 地区
- 城市
- TCP成功率
- TCP RTT最小值
- TCP RTT平均值
- TCP RTT最大值
- HTTP RTT
- 各回源目标的RTT
- 下载速度（单位KB/s，如果启用了测速）

# 提示
1. **确保IP地址文件格式正确**：每行应包含一个IP地址或CIDR块。
2. **选择合适的并发线程数**：高并发数可能导致高资源消耗，需根据系统性能调整。
3. **测速文件大小影响测试结果**：选择合适的测速文件，以确保结果的准确性。
4. **检查系统文件描述符限制**：高并发可能导致文件描述符不够用，尤其在Linux系统下，请确保`ulimit`设置合理（程序也会尝试提升文件描述符的上限以支持更多的并发请求）。

# 说明
- 程序会自动从 `https://speed.cloudflare.com/locations` 下载位置信息，并将其存储在 `locations.json` 文件中。如果该文件已存在，则会直接使用本地文件。
- 对于地址数大于 2^10 个的 IPv6 网络，程序会随机抽样 1024 个 IP 进行测试。
- 如果没有启用全局 TLS，对未指定协议的地址会默认使用 HTTP ，并在 HTTP 和回源测试中使用 80 端口。
