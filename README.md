# 简介
Cloudflare Tester 是一个使用 Golang 编写的小工具，用于测试 Cloudflare IP 地址的延迟、回源时间和下载速度，并将结果输出到 CSV 文件中。

# 编译
## Action

直接查看[本库 Github Actions](https://github.com/1-1-2/CloudflareTester/actions)，或 fork 执行。

## 为本机编译
以 Linux 为例首先安装 Golang 和 Git，然后在终端中运行以下命令：

```sh
git clone https://github.com/1-1-2/CloudflareTester.git
cd CloudflareTester
go build -o CFtester-linux main.go
```

## 交叉编译

以在 Windows 中编译 linux mipsle 为例

### 在 Windows 命令行中

```bat
set GOOS=linux
set GOARCH=mipsle
set GOMIPS=softfloat
go build -o CFtester-linux-mipsle
```

### 在 Windows PowerShell 中
```powershell
$env:GOOS="linux"
$env:GOARCH="mipsle"
$env:GOMIPS="softfloat"
go build -o CFtester-linux-mipsle
```

# 使用

## 命令行参数

`CFtester` 接受以下参数：

- `-ipin`：指定IP地址文件的名称。默认值为`ip.txt`。
- `-xout`：输出文件的前缀。默认值为`result`。
- `-limcidr`：单条CIDR取样数量上限。默认值为1024。
- `-tcport`：TCP测试端口号。默认值为443。
- `-urlspd`：测速文件的URL。默认值为`https://speed.cloudflare.com/__down?bytes=500000000`。
- `-urlori`：回源测试的地址，支持英文逗号分隔的多个目标。默认留空禁用回源测试。
- `-tls`：是否强制启用TLS。默认值为false。
- `-thtcp`：TCP测试并发上限。默认值为100。
- `-thttp`：HTTP请求并发上限。默认值为100。
- `-thspd`：测速并发上限，设为0时跳过速度测试。默认值为0。
- `-rttcp`：TCP测试重试次数。默认值为5。
- `-rthttp`：HTTP请求最大重试次数。默认值为5。
- `-rtspeed`：速度测试最大重试次数。默认值为3。
- `-totcp`：TCP连接超时时间(ms)。默认值为1000。
- `-tohttp`：HTTP请求超时时间(ms)。默认值为2000。
- `-tospeed`：测速最大持续时间(s)。默认值为5。

## 运行示例

```sh
# 启用回源和测速，全局tls
./CFtester -tls=true -urlori=www.cloudflare.com,www.example.com -thspd=5

# 指定输入和输出的前缀，调整CIDR取样数量
./CFtester -ipin=myip.txt -xout=myrst -limcidr=512

# 减少测试并发上限和TCP重试次数
./CFtester -thtcp=50 -thttp=10 -rttcp=3
```

## 报告字段
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

## 提示
1. **确保IP地址文件格式正确**：每行应包含一个IP地址或CIDR块。
2. **选择合适的并发线程数**：高并发数可能导致高资源消耗，需根据系统性能调整。这在低性能平台上非常重要，过高的并发数将导致更高的延迟甚至超时。这需要积极的尝试以确定最佳值。
3. **测速文件大小影响测试结果**：选择合适的测速文件，以确保结果的准确性。
4. **检查系统文件描述符限制**：高并发可能导致文件描述符不够用，尤其在Linux系统下，请确保`ulimit`设置合理（程序也会尝试提升文件描述符的上限以支持更多的并发请求）。

# 说明
- 程序初始化时，从 `https://speed.cloudflare.com/locations` 下载位置信息，并将其存储在 `locations.json` 文件中。如果该文件已存在，则会直接使用本地文件。**如果需要刷新该文件，删除本地的 `locations.json` 文件即可**。
- 默认设置下，对于地址数大于 2^10 个的 CIDR 网络，程序默认会随机抽样 1024 个 IP 进行测试，可通过`-limcidr`参数改变这一行为。注意，过多的IP数会导致不可预估的性能下降，因此请确保输入的IP地址数在合理范围内。
- 程序不支持带端口号的URL
  - 默认情况下，对未指定协议的地址会默认使用 HTTP ，并在 HTTP 和回源测试中使用 80 端口。
  - 启用全局 TLS，会对所有 URL 强制使用 HTTPS 协议，并使用 443 端口。在 HTTP-trace 和回源测试中，这可能不是必要的。

# 致谢

- 本程序 base [badafans](https://github.com/badafans)/[Cloudflare-IP-SpeedTest](https://github.com/badafans/Cloudflare-IP-SpeedTest)

