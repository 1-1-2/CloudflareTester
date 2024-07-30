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

- `ipin`: IP 地址文件名称 (默认值: "ip.txt")
- `xout`: 输出文件前缀 (默认值: "result")
- `tcport`: tcp测试端口 (默认值: 443)
- `th`: 并发请求最大协程数 (默认值: 100)
- `spdt`: 下载测速协程数量, 设为 0 禁用测速 (默认值: 0)
- `tls`: 全局使用 TLS (默认值: false)
- `url`: 测速文件地址 (默认值: "https://speed.cloudflare.com/__down?bytes=500000000")
- `origin`: 回源测试地址 (默认值: ""，留空则禁用)

# 运行
在终端运行命令示例：

```sh
# 启用回源和测速
./CFtester -ipin=myip.txt -xout=myrst -th=50 -spdt=5 -origin=www.cloudflare.com

# 指定输入和输出的前缀
./CFtester -ipin=myip.txt -xout=myrst

# 启用全局tls，减少线程数
./CFtester -tls=true -th=50
```

# 输出
输出的 CSV 文件包含以下列：

- IP地址
- TCP端口
- TLS
- 数据中心
- 地区（如出错，则为空）
- 城市（如出错，则为空）
- TCP Reach (TCP 请求成功率)
- TCP RTT min (最小延迟)
- TCP RTT avg (平均延迟)
- TCP RTT max (最大延迟)
- HTTP RTT（如出错，则为0）
- 回源 RTT（如出错，则为0）
- 下载速度 (如果启用测速)

# 提示
- 程序会自动从 `https://speed.cloudflare.com/locations` 下载位置信息，并将其存储在 `locations.json` 文件中。如果该文件已存在，则会直接使用本地文件。
- 对于地址数大于 2^10 个的 IPv6 网络，程序会随机抽样 1024 个 IP 进行测试。
- 如果没有启用全局 TLS，对未指定协议的地址会默认使用 HTTP ，并在 HTTP 和回源测试中使用 80 端口。
- 如果操作系统是 Linux，程序会尝试提升文件描述符的上限以支持更多的并发请求。

# TODO
- 测速待测试