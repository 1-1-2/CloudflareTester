package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tcpTimeout       = 1 * time.Second                              // TCP连接超时时间
	httpTimeout      = 2 * time.Second                              // HTTP请求超时时间
	downloadDuration = 5 * time.Second                              // 最长下载持续时间
	traceURL         = "https://speed.cloudflare.com/cdn-cgi/trace" // Cloudflare trace URL
	UA               = "Mozilla/5.0"                                // User-Agent
	limitCIDR        = 1024                                         // 单条CIDR最大长度限制
)

var (
	ipFile        = flag.String("ipin", "ip.txt", "IP地址文件名称")                                           // IP地址文件名称
	outFilePrefix = flag.String("xout", "result", "输出文件前缀")                                             // 输出文件前缀
	tcpPort       = flag.Int("tcport", 443, "端口")                                                       // 端口
	maxThreads    = flag.Int("th", 100, "并发请求最大协程数")                                                    // 最大协程数
	doSpeedTest   = flag.Int("spdt", 0, "下载测速协程数量,设为0禁用测速")                                             // 下载测速协程数量
	speedTestURL  = flag.String("url", "https://speed.cloudflare.com/__down?bytes=500000000", "测速文件地址") // 测速文件地址
	originTestURL = flag.String("origin", "", "回源测试地址，默认留空禁用")                                          // 回源测试地址
	forceTLS      = flag.Bool("tls", false, "是否强制启用TLS")                                                // TLS是否启用
	maxAttempt    = flag.Int("attempt", 5, "最大重试次数")                                                    // 各项测试最大重试次数
	ipCounts      = 0                                                                                   // 存储读入的ip总数
	startTime     = time.Now()                                                                          // 记录程序开始运行的时间
	locationMap   = make(map[string]location)                                                           // 存储位置信息
)

type resultTCP struct {
	ip         string        // IP地址
	port       int           // 端口
	tcpReach   int           // TCP请求成功次数
	reachRatio float64       // TCP请求成功率
	tcpRTTsum  time.Duration // TCP请求延迟总和
	tcpRTTmin  time.Duration // TCP请求最小延迟
	tcpRTTavg  time.Duration // TCP请求平均延迟
	tcpRTTmax  time.Duration // TCP请求最大延迟
}

type resultHTTP struct {
	ip         string        // IP地址
	dataCenter string        // 数据中心
	region     string        // 地区
	city       string        // 城市
	httpRTT    time.Duration // HTTP请求延迟
	originRTT  time.Duration // 回源测试延迟
}

type resultSpeed struct {
	ip        string  // IP地址
	downSpeed float64 // 下载速度
}

// 结果聚合
type resultMerge struct {
	resultTCP
	resultHTTP
	resultSpeed
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// 带时间前缀的printf
func timef(format string, a ...interface{}) {
	fmt.Printf(fmt.Sprintf("|%.2fs| %s", float64(time.Since(startTime).Milliseconds())/1000, format), a...)
}

func getJSON(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("非预期的状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("无法读取响应体: %v", err)
	}

	err = os.WriteFile(filepath, body, 0644)
	if err != nil {
		return fmt.Errorf("无法写入文件: %v", err)
	}
	return nil
}

// loadLocations 从本地文件或远程URL加载位置信息
// 如果本地文件不存在，会从远程URL下载
// 返回一个map，key是IATA代码，value是location结构体
func loadLocations() {
	const locationFile = "locations.json"
	const locationURL = "https://speed.cloudflare.com/locations"

	// 检查本地文件是否存在
	if _, err := os.Stat(locationFile); os.IsNotExist(err) {
		timef("本地未找到 locations.json, 正从 %s 下载...", locationURL)
		if err := getJSON(locationURL, locationFile); err != nil {
		}
	} else {
		timef("本地 locations.json 已存在, 无需重新下载\n")
	}

	// 读取和解析 JSON 文件
	jsbody, err := os.ReadFile(locationFile)
	if err != nil {
		fmt.Printf("无法读取文件: %v", err)
	}
	var locations []location
	if err := json.Unmarshal(jsbody, &locations); err != nil {
		fmt.Printf("JSON解析失败: %v", err)
	}

	// 构建 location 字典
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}
}

// IPaddOne 将给定的IP地址递增1
func IPaddOne(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IPaddN 将给定的IP地址增加1
func IPaddN(ip net.IP, n *big.Int) net.IP {
	// 判断是否是IPv4并转换为IPv6表示法
	if ip.To4() != nil {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}

	ipInt := big.NewInt(0)
	ipInt.SetBytes(ip)

	ipInt.Add(ipInt, n)

	ipBytes := ipInt.Bytes()
	if len(ipBytes) > net.IPv6len {
		ipBytes = ipBytes[len(ipBytes)-net.IPv6len:]
	} else if len(ipBytes) < net.IPv6len {
		ipBytes = append(make([]byte, net.IPv6len-len(ipBytes)), ipBytes...)
	}

	return net.IP(ipBytes)
}

// hasIPv6 检查设备是否有可用的IPv6外部网络连接
func hasIPv6() bool {
	publicDNS := "2400:3200::1" // 公共DNS的IPv6地址

	for i := 1; i <= *maxAttempt; i++ {
		timef("通过 DOH 可达性检测 IPv6 连接，第 %d 次尝试...\n", i)
		conn, err := net.DialTimeout("tcp6", net.JoinHostPort(publicDNS, "80"), httpTimeout)
		if err != nil {
			timef("失败 : %v\n", err)
		} else {
			conn.Close()
			timef("IPv6 可达(%s)\n", publicDNS)
			return true
		}
		time.Sleep(1 * time.Second) // 在下一次尝试前等待
	}
	timef("多次尝试后未能连接到IPv6地址\n")
	return false
}

func readIPs(filepath string) ([]string, error) {
	ips := []string{}
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件: %v", err)
	}
	defer file.Close()

	v6able := hasIPv6()
	if v6able {
		timef("本机已启用IPv6网络\n")
	} else {
		timef("本机未启用IPv6网络\n")
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, ":") && !v6able {
			timef("提示: 本机未启用IPv6网络, %s 将被跳过\n", line)
			continue
		}

		ip, network, err := net.ParseCIDR(line)
		if err == nil {
			// 处理CIDR地址块
			// 计算CIDR范围内的IP地址数量
			ones, bits := network.Mask.Size()
			ipCount := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
			if ipCount.Cmp(big.NewInt(limitCIDR)) > 0 {
				timef("提示: %s 包含 %s 个IP地址，等距抽样 %d 个参与测试\n", line, ipCount.String(), limitCIDR)
				sampled := make([]string, limitCIDR)
				gap := new(big.Int).Div(ipCount, big.NewInt(limitCIDR))
				for i := 0; i < limitCIDR; i++ {
					perm := new(big.Int).Mul(gap, big.NewInt(int64(i)))
					sampledIP := IPaddN(ip, perm)
					sampled[i] = sampledIP.String()
				}
				ips = append(ips, sampled...)
			} else {
				timef("%s 包含 %s 个IP地址\n", line, ipCount.String())
				cidr_ips := make([]string, 0)
				for ip := ip.Mask(network.Mask); network.Contains(ip); IPaddOne(ip) {
					cidr_ips = append(cidr_ips, ip.String())
				}
				ips = append(ips, cidr_ips...)
			}
		} else if ip = net.ParseIP(line); ip != nil {
			// 单个IP
			ips = append(ips, ip.String())
		} else {
			timef("无法解析的IP或CIDR: %s\n", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取文件时发生错误: %v", err)
	}

	ipCounts = len(ips)
	return ips, nil
}

// tcpOnce执行一次TCP拨号并返回持续时间
func tcpOnce(ip string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tcpTimeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout:   tcpTimeout,
		KeepAlive: 0, // 不保留链接，每次请求都建立一个新的TCP连接
	}

	// 使用自定义拨号器拨号
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(*tcpPort)))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return time.Since(start), nil
}

// 对 IP 集合执行多轮 TCP 测试
func tcpTests(ips []string) ([]resultTCP, []string) {
	var wg sync.WaitGroup
	thread := make(chan struct{}, *maxThreads)

	timef("开始执行 TCP连通性 测试, 共 %d 个目标\n", len(ips))

	// 初始化用于统计响应信息的 map
	tcpStats := make(map[string]*resultTCP)
	var mu sync.Mutex // 保护 tcpStats 的互斥锁

	for attempts := 0; attempts < *maxAttempt; attempts++ {
		for _, ip := range ips {
			wg.Add(1)
			thread <- struct{}{}
			go func(ip string, attempts int) {
				defer func() {
					<-thread
					wg.Done()
				}()

				tcpRTT, err := tcpOnce(ip)
				mu.Lock() // 加锁
				if err == nil {
					if _, exists := tcpStats[ip]; !exists {
						tcpStats[ip] = &resultTCP{
							ip:        ip,
							port:      *tcpPort,
							tcpRTTmin: time.Duration(math.MaxInt64), // 初始化为最大值
						}
					}

					stats := tcpStats[ip]
					stats.tcpReach++
					if tcpRTT < stats.tcpRTTmin {
						stats.tcpRTTmin = tcpRTT
					}
					if tcpRTT > stats.tcpRTTmax {
						stats.tcpRTTmax = tcpRTT
					}
					stats.tcpRTTsum += tcpRTT
				} else {
					fmt.Printf("[%s] TCP连接失败(第%d次): %v\n", ip, attempts+1, err)
				}
				mu.Unlock() // 解锁
			}(ip, attempts)
		}
	}

	timef("正在等待 TCP 测试结束...\n")
	wg.Wait()

	timef("TCP 测试已结束，正在统计数据...\n")
	resultAlive := []resultTCP{}
	ipDead := []string{}
	for _, ip := range ips {
		if _, exists := tcpStats[ip]; exists {
			// 有响应结果
			stats := tcpStats[ip]
			if stats.tcpReach > 0 {
				stats.tcpRTTavg = stats.tcpRTTsum / time.Duration(stats.tcpReach)
				stats.reachRatio = float64(stats.tcpReach) / float64(*maxAttempt) * 100
				resultAlive = append(resultAlive, *stats)

				// fmt.Printf("[%s] TCP Reach: %.2f%%, TCP-RTT min: %d ms, avg: %d ms, max: %d ms\n",
				// 	stats.ip, stats.reachRatio, stats.tcpRTTmin.Milliseconds(),
				// 	stats.tcpRTTavg.Milliseconds(), stats.tcpRTTmax.Milliseconds())
			} else {
				// 被记录的异常响应
				timef("哪里出了错，%s 没有测试结果？\n", ip)
				ipDead = append(ipDead, ip)
			}
		} else {
			// 没有响应结果
			ipDead = append(ipDead, ip)
		}
	}

	timef("TCP 测试流程结束，与 %d 个IP中的 %d 个握手成功\n", ipCounts, len(resultAlive))
	return resultAlive, ipDead
}

// genURL 根据 oriURL 检查或添加正确的协议头，并返回端口号
func genURL(oriURL string) (string, int) {
	if strings.HasPrefix(oriURL, "https://") {
		return oriURL, 443
	}
	if strings.HasPrefix(oriURL, "http://") {
		if *forceTLS {
			return "https" + strings.TrimPrefix(oriURL, "http"), 443
		} else {
			return oriURL, 80
		}
	}
	// 未指定协议的
	if *forceTLS {
		return "https://" + oriURL, 443
	} else {
		return "http://" + oriURL, 80
	}
}

// 公共函数，用于创建 HTTP 客户端和请求
func genClient(ip string, port int, url string) (*http.Client, *http.Request, error) {
	// 创建一个用于拨号的结构体
	dialer := &net.Dialer{
		Timeout:   tcpTimeout, // 设置超时时间
		KeepAlive: 0,          // 关闭 keepalive
	}
	// 创建一个 http 传输结构体
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// 使用拨号结构体连接到指定的 ip 和端口
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		},
	}
	// 创建一个 http 客户端
	client := &http.Client{
		Transport: transport,   // 设置传输结构体
		Timeout:   httpTimeout, // 设置超时时间
	}
	// 创建一个 http 请求
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	// 设置请求头
	req.Header.Set("User-Agent", UA)
	// 关闭请求
	req.Close = true
	return client, req, nil
}

// httpTraceOnce 执行官方节点测试并返回持续时间
func httpTraceOnce(ip string) (time.Duration, *bytes.Buffer, error) {
	URL, port := genURL(traceURL)
	for attempts := 0; attempts < *maxAttempt; attempts++ {
		startTime := time.Now()

		client, req, err := genClient(ip, port, URL)
		if err != nil {
			return 0, nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			if os.IsTimeout(err) {
				fmt.Printf("[%s] trace请求(第%d次)超时: %v\n", ip, attempts+1, err)
			} else {
				fmt.Printf("[%s] trace请求(第%d次)失败: %v\n", ip, attempts+1, err)
			}
			continue
		}
		defer resp.Body.Close()

		duration := time.Since(startTime)
		buf := &bytes.Buffer{}
		_, err = io.Copy(buf, resp.Body)
		if err != nil {
			fmt.Printf("[%s] trace请求(第%d次)读取响应体失败: %v\n", ip, attempts+1, err)
			continue
		}

		return duration, buf, nil
	}
	return 0, nil, fmt.Errorf("trace请求全部超时")
}

// httpOriginOnce 执行回源时间测试并返回持续时间
func httpOriginOnce(ip string) (time.Duration, error) {
	URL, port := genURL(*originTestURL)
	for attempts := 0; attempts < *maxAttempt; attempts++ {
		startTime := time.Now()
		client, req, err := genClient(ip, port, URL)
		if err != nil {
			return 0, err
		}
		req.Body = http.NoBody // 不关注响应，设置请求体为空

		resp, err := client.Do(req)
		if err != nil {
			if os.IsTimeout(err) {
				fmt.Printf("[%s] 回源请求(第%d次)超时: %v\n", ip, attempts+1, err)
			} else {
				fmt.Printf("[%s] 回源请求(第%d次)失败: %v\n", ip, attempts+1, err)
			}
			continue
		}
		defer resp.Body.Close()

		duration := time.Since(startTime)
		return duration, nil
	}
	return 0, fmt.Errorf("回源请求全部超时")
}

// HTTP 和回源测试部分
func httpTests(ips []string) []resultHTTP {
	var wg sync.WaitGroup
	thread := make(chan struct{}, *maxThreads)
	resultHTTPChan := make(chan resultHTTP, len(ips))

	re := regexp.MustCompile(`colo=([A-Z]+)`)

	timef("开始执行 HTTP和回源 测试\n")
	for _, ip := range ips {
		wg.Add(1)
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
			}()

			// HTTP 测试
			httpRTT, body, err := httpTraceOnce(ip)
			if err != nil {
				fmt.Printf("[%s] HTTP测试失败: %v\n", ip, err)
			}

			// 回源测试
			originRTT := time.Duration(0)
			if *originTestURL != "" {
				originRTT, err = httpOriginOnce(ip)
				if err != nil {
					fmt.Printf("[%s] 回源测试失败: %v\n", ip, err)
				}
			}

			var dataCenter, region, city string
			if matches := re.FindStringSubmatch(body.String()); len(matches) > 1 {
				Colo := matches[1]
				if loc, ok := locationMap[Colo]; ok {
					dataCenter = Colo
					region = loc.Region
					city = loc.City
				} else {
					timef("未找到数据中心 %s 的位置信息\n", Colo)
					dataCenter = Colo
				}
			}

			result := resultHTTP{
				ip:         ip,
				dataCenter: dataCenter,
				region:     region,
				city:       city,
				httpRTT:    httpRTT,
				originRTT:  originRTT,
			}
			resultHTTPChan <- result

			fmt.Printf("[%s] HTTP-RTT %d ms，回源RTT %d ms，数据中心: %s, 地区: %s, 城市: %s\n",
				ip, httpRTT.Milliseconds(), originRTT.Milliseconds(), dataCenter, region, city)
		}(ip)
	}

	go func() {
		timef("正在等待 HTTP 测试结束...\n")
		wg.Wait()
		close(resultHTTPChan)
		timef("HTTP 测试已结束，正在等待数据整理...\n")
	}()

	// resultHTTPChan 转切片
	var resultHTTPSlice []resultHTTP
	for res := range resultHTTPChan {
		resultHTTPSlice = append(resultHTTPSlice, res)
	}

	return resultHTTPSlice
}

// 重构后的 speedOnce 函数
func speedOnce(ip string) (float64, error) {
	URL, port := genURL(*speedTestURL)
	speedAttempts := 3
	for attempts := 0; attempts < speedAttempts; attempts++ {
		startTime := time.Now()
		client, req, err := genClient(ip, port, URL)
		if err != nil {
			return 0, err
		}
		// 修改 client 的超时时间为 downloadDuration
		client.Timeout = downloadDuration

		timef("启动 [%s:%d] 测速(第%d次)\n", ip, port, attempts+1)

		resp, err := client.Do(req)
		if err != nil {
			timef("[%s:%d] 测速(第%d次)出错%v\n", ip, port, attempts+1, err)
			continue
		}
		defer resp.Body.Close()

		written, _ := io.Copy(io.Discard, resp.Body)
		duration := time.Since(startTime)
		speed := float64(written) / duration.Seconds() / 1024
		return speed, nil
	}
	return 0, fmt.Errorf("%d次重试均未成功", speedAttempts)
}

// speedTests 对已经通过延迟测试的IP进行下载速度测试
// 它使用goroutine并发进行测速，并通过channel返回结果
// 过程中，调用reportProgress报告测试进度
func speedTests(ips []string) []resultSpeed {
	var wg sync.WaitGroup
	thread := make(chan struct{}, *doSpeedTest)

	// 创建 speedResultsChan 通道，用于存储 speedtestresult 结构体
	speedResultsChan := make(chan resultSpeed, len(ips))
	// 创建 progressChan 和 doneChan 通道，启动一个协程用于报告进度
	progressChan := make(chan int, 1)
	go func(progressChan chan int, total int) {
		currentCount := 0
		for count := range progressChan {
			currentCount += count
			percentage := float64(currentCount) / float64(total) * 100
			timef("测速进度：%d / %d 已完成（%.2f%%）\r", currentCount, total, percentage)
		}
	}(progressChan, len(ips))

	timef("开始执行 测速 测试\n")
	for _, ip := range ips {
		wg.Add(1)
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
			}()

			speed, err := speedOnce(ip)
			if err != nil {
				fmt.Printf("[%s] 测速失败: %v\n", ip, err)
			} else {
				fmt.Printf("[%s] 测速结果: %.2f KB/s\n", ip, speed)
				speedResultsChan <- resultSpeed{ip: ip, downSpeed: speed}
			}

			// 进度+1
			progressChan <- 1
		}(ip)
	}

	go func() {
		timef("正在等待 测速 结束...\n")
		wg.Wait()
		close(speedResultsChan)
		close(progressChan)
		timef("测速已结束，正在统计数据...\n")
	}()

	results := []resultSpeed{}
	for speedResult := range speedResultsChan {
		results = append(results, speedResult)
	}

	return results
}

func resultsToCSV(results []resultMerge, tcpDead []string, outFileName string) {
	file, err := os.Create(outFileName)
	if err != nil {
		timef("无法创建文件: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入 CSV 头部
	header := []string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市",
		"TCP Reach", "RTT min", "RTT avg", "RTT max", "HTTP RTT", "回源 RTT"}
	if *doSpeedTest > 0 {
		header = append(header, "下载速度")
	}
	writer.Write(header)

	// 写入 CSV 记录
	for _, res := range results {
		// 有响应的记录
		record := []string{
			res.resultTCP.ip,
			strconv.Itoa(res.port),
			strconv.FormatBool(*forceTLS),
			res.dataCenter,
			res.region,
			res.city,
			fmt.Sprintf("%.2f%%", res.reachRatio),
			fmt.Sprintf("%d", res.tcpRTTmin.Milliseconds()),
			fmt.Sprintf("%d", res.tcpRTTavg.Milliseconds()),
			fmt.Sprintf("%d", res.tcpRTTmax.Milliseconds()),
			fmt.Sprintf("%d", res.httpRTT.Milliseconds()),
			fmt.Sprintf("%d", res.originRTT.Milliseconds()),
		}
		if *doSpeedTest > 0 {
			record = append(record, fmt.Sprintf("%.0f", res.downSpeed))
		}
		writer.Write(record)
	}
	for _, ip := range tcpDead {
		// 没得响应的记录
		writer.Write([]string{ip, "", "", "", "", "", "不可达", "", "", "", ""})
	}
}

func clearConsole() {
	switch runtime.GOOS {
	case "linux", "android", "darwin", "dragonfly", "freebsd", "netbsd", "openbsd", "illumos", "solaris":
		fmt.Print("\033[2J\033[H")
	case "windows":
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		cmd.Run()
	default:
		// fmt.Println("清屏命令不适用于当前系统")
	}
}

func terminalTitle(title string) {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "netbsd", "openbsd", "illumos", "solaris":
		fmt.Printf("\033]0;%s\007", title)
	case "windows":
		cmd := exec.Command("cmd", "/c", "title", title)
		cmd.Run()
	default:
		// fmt.Println("不支持的操作系统")
	}
}

// 检查并尝试提升文件描述符上限
func ulimitLinux() {
	timef("尝试提升文件描述符的上限...\n")

	// 检查当前文件描述符的限制
	output, err := exec.Command("sh", "-c", "ulimit -n").Output()
	if err != nil {
		timef("获取当前文件描述符上限时出现错误: %v\n", err)
	} else {
		currentLimit, err := strconv.Atoi(strings.TrimSpace(string(output)))
		if err != nil {
			timef("解析当前文件描述符上限时出现错误: %v\n", err)
		} else if currentLimit >= 10000 {
			timef("当前文件描述符上限为 %d，无需提升\n", currentLimit)
		} else {
			// 尝试提升文件描述符上限
			cmd := exec.Command("sh", "-c", "ulimit -n 10000")
			if err := cmd.Run(); err != nil {
				timef("提升文件描述符上限时出现错误: %v\n", err)
			} else {
				timef("文件描述符上限已成功提升到 10000\n")
			}
		}
	}
}

func main() {
	flag.Parse()

	// 设置控制台运行标题
	terminalTitle(fmt.Sprintf("[CFtester]%s To %s", *ipFile, *outFilePrefix))

	// 如果操作系统是 linux 尝试提升文件描述符上限
	if runtime.GOOS == "linux" {
		ulimitLinux()
	}

	// 加载地址库
	loadLocations()

	// 从文件中读取 IP 地址
	ips, err := readIPs(*ipFile)
	if err != nil {
		timef("读取文件时发生错误: %v\n", err)
		return
	}

	// TCP测试
	resultAlive, ipDead := tcpTests(ips)
	var ipAlive []string
	for _, result := range resultAlive {
		ipAlive = append(ipAlive, result.ip)
	}

	// HTTP和回源测试
	resultHTTPSlice := httpTests(ipAlive)

	// 测速
	var resultSpeedSlice []resultSpeed
	if *doSpeedTest > 0 {
		resultSpeedSlice = speedTests(ipAlive)
	}

	// 初始化 resultMap
	resultMap := make(map[string]*resultMerge)
	for _, ip := range ipAlive {
		resultMap[ip] = &resultMerge{}
	}

	// 合并 TCP 测试结果
	for _, res := range resultAlive {
		resultMap[res.ip].resultTCP = res
	}

	// 合并 HTTP 测试结果
	for _, res := range resultHTTPSlice {
		resultMap[res.ip].resultHTTP = res

	}

	// 合并 测速结果
	for _, res := range resultSpeedSlice {
		resultMap[res.ip].resultSpeed = res
	}

	var results []resultMerge
	for _, res := range resultMap {
		results = append(results, *res)
	}
	if *doSpeedTest > 0 {
		// 根据下载速度排序
		sort.Slice(results, func(i, j int) bool {
			return results[i].downSpeed > results[j].downSpeed
		})
	} else {
		// 根据TCP平均RTT排序
		sort.Slice(results, func(i, j int) bool {
			return results[i].tcpRTTavg < results[j].tcpRTTavg
		})
	}

	// 清除输出内容
	clearConsole()

	// 输出结果到文件
	outFileName := fmt.Sprintf("%s-%s.csv", *outFilePrefix, startTime.Format("20060102_150405"))
	resultsToCSV(results, ipDead, outFileName)

	timef("读入的IP总数: %d, 响应的记录总数: %d\n", len(ips), len(results))
	timef("测试总耗时 %d 秒，结果写入文件 %s\n", time.Since(startTime)/time.Second, outFileName)
}
