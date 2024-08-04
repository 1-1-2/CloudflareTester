package main

import (
	"bufio"
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
	speedRetries     = 3                                            // 速度测试重试次数
)

var (
	ipFile        = flag.String("ipin", "ip.txt", "IP地址文件名")
	outFilePrefix = flag.String("xout", "result", "输出文件前缀")
	tcpPort       = flag.Int("tcport", 443, "TCP测试端口")
	maxThreads    = flag.Int("th", 100, "并发请求最大协程数")
	doSpeedTest   = flag.Int("spdt", 0, "下载速度测试协程数量,设为0禁用速度测试")
	speedTestURL  = flag.String("spdurl", "https://speed.cloudflare.com/__down?bytes=500000000", "测速文件地址")
	originTestURL = flag.String("origin", "", "回源测试地址，支持英文逗号分隔的多个目标，默认留空禁用")
	forceTLS      = flag.Bool("tls", false, "是否强制启用TLS")
	maxRetries    = flag.Int("attempt", 5, "最大重试次数")
	ipCounts      = 0                         // 读入的IP地址数量
	startTime     = time.Now()                // 程序开始时间
	locationMap   = make(map[string]location) // 机场码与地理位置的映射
	originURLs    []string                    // 分割后的回源测试目标URL
)

type resultTCP struct {
	// ip         string        // IP地址
	port       int           // 端口
	tcpReach   int           // TCP请求成功次数
	tcpFailed  int           // TCP请求失败次数
	reachRatio float64       // TCP请求成功率
	tcpRTTsum  time.Duration // TCP请求延迟总和
	tcpRTTmin  time.Duration // TCP请求最小延迟
	tcpRTTavg  time.Duration // TCP请求平均延迟
	tcpRTTmax  time.Duration // TCP请求最大延迟
}

type resultHTTP struct {
	// ip         string                   // IP地址
	dataCenter string                   // 数据中心
	region     string                   // 地区
	city       string                   // 城市
	httpRTT    time.Duration            // HTTP请求延迟
	originRTTs map[string]time.Duration // 回源测试延迟（多个目标）
}

type resultSpeed struct {
	ip        string  // IP地址
	downSpeed float64 // 下载速度
}

// 结果聚合
type resultMerge struct {
	ip string
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

	for i := 1; i <= *maxRetries; i++ {
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

type tcpRes struct {
	ip  string
	rtt time.Duration
	err error
}

// tcpOnce执行一次TCP拨号并返回持续时间
func tcpWorker(ipChan <-chan string, rspChan chan<- tcpRes, wg *sync.WaitGroup) {
	for ip := range ipChan {
		// 创建一个带超时的 context
		ctx, cancel := context.WithTimeout(context.Background(), tcpTimeout)

		// 创建一个带超时的 dialer
		dialer := &net.Dialer{
			Timeout:   tcpTimeout,
			KeepAlive: 0, // 不保留链接，每次请求都建立一个新的TCP连接
		}

		// 使用自定义拨号器拨号
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(*tcpPort)))
		duration := time.Since(start)
		if err == nil {
			conn.Close()
			rspChan <- tcpRes{ip: ip, rtt: duration}
		} else {
			rspChan <- tcpRes{ip: ip, err: err}
		}
		cancel()
		wg.Done()
	}
}

// 对 IP 集合执行多轮 TCP 测试
func tcpTests(ips []string) (map[string]*resultTCP, []string) {
	var wg sync.WaitGroup
	jobChan := make(chan string, len(ips)**maxRetries)
	respondChan := make(chan tcpRes, *maxThreads)

	timef("TCP连通性 测试, 共 %d 个目标，每个目标%d次重试\n", len(ips), *maxRetries)
	// 启动工作者
	timef("正在启动 TCP worker\n")
	for w := 0; w < *maxThreads; w++ {
		go tcpWorker(jobChan, respondChan, &wg)
	}

	timef("开始执行 TCP连通性 测试\n")
	// 将ips复制maxRetries次到jobChan中
	for retry := 0; retry < *maxRetries; retry++ {
		for _, ip := range ips {
			wg.Add(1)
			jobChan <- ip
		}
	}
	go func() {
		timef("正在等待 TCP连通性 测试结束...\n")
		wg.Wait()
		close(jobChan)
		close(respondChan)
		timef("TCP连通性 测试已结束，正在等待数据整理...\n")
	}()

	// 从respondChan中读取结果并整理
	// 初始化用于统计响应信息的 map
	aliveStats := make(map[string]*resultTCP)
	for rsd := range respondChan {
		// 初始化统计信息
		stat, exists := aliveStats[rsd.ip]
		if !exists {
			aliveStats[rsd.ip] = &resultTCP{
				// ip:        ip,
				port:      *tcpPort,
				tcpRTTmin: time.Duration(math.MaxInt64), // 用最大值初始化
			}
			stat = aliveStats[rsd.ip]
		}
		// 根据响应更新统计信息
		if rsd.err == nil {
			// 正常响应
			stat.tcpReach++
			if rsd.rtt < stat.tcpRTTmin {
				stat.tcpRTTmin = rsd.rtt
			}
			if rsd.rtt > stat.tcpRTTmax {
				stat.tcpRTTmax = rsd.rtt
			}
			stat.tcpRTTsum += rsd.rtt
		} else {
			// 响应超时
			stat.tcpFailed++
			fmt.Printf("[%s] TCP连接失败(%d成功/%d失败): %v\n", rsd.ip, stat.tcpReach, stat.tcpFailed, rsd.err)
		}
	}

	// 记录无响应IP，计算有响应IP的平均响应时间
	ipDead := []string{}
	for _, ip := range ips {
		if stat, exists := aliveStats[ip]; exists {
			// 有响应结果
			if stat.tcpReach > 0 {
				stat.tcpRTTavg = stat.tcpRTTsum / time.Duration(stat.tcpReach)
				stat.reachRatio = float64(stat.tcpReach) / float64(*maxRetries) * 100

				fmt.Printf("[%s] TCP Reach: %.2f%%, TCP-RTT min: %d ms, avg: %d ms, max: %d ms\n",
					ip, stat.reachRatio, stat.tcpRTTmin.Milliseconds(),
					stat.tcpRTTavg.Milliseconds(), stat.tcpRTTmax.Milliseconds())
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

	timef("TCP 测试流程结束，与 %d 个IP中的 %d 个握手成功\n", ipCounts, len(aliveStats))
	return aliveStats, ipDead
}

// rectifyURL 根据 oriURL 检查或添加正确的协议头，并返回端口号
func rectifyURL(oriURL string) (string, int) {
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

type httpJob struct {
	ip      string
	port    int
	url     string
	reqTag  string // 请求标签
	purpose string // 请求标的
}

type httpRes struct {
	ip        string
	url       string
	reqTag    string
	duration  time.Duration // HTTP请求的耗时
	body      []byte        // 响应体内容
	downSpeed float64       // 下载速度
	err       error
}

func httpWorker(timeout time.Duration, limRetries int, reqMAP map[string]*http.Request, jobChan <-chan httpJob, respondChan chan<- httpRes, wg *sync.WaitGroup) {
	// 创建一个用于拨号的结构体
	dialer := &net.Dialer{
		Timeout:   tcpTimeout, // 设置超时时间
		KeepAlive: 0,          // 关闭 keepalive
	}
	// 创建一个 http 客户端，使用默认的 Transport
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{
		Transport: transport, // 设置传输结构体
		Timeout:   timeout,   // 设置超时时间
	}

	for job := range jobChan {
		// 设置请求的 IP 和端口
		client.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(job.ip, strconv.Itoa(job.port)))
		}

		good := false
		for retry := 0; retry < limRetries; retry++ {
			req := reqMAP[job.url]
			startTime := time.Now()

			resp, err := client.Do(req)
			if err != nil {
				if os.IsTimeout(err) {
					fmt.Printf("[%s] %s请求(第%d次)超时: %v\n", job.ip, job.reqTag, retry+1, err)
				} else {
					fmt.Printf("[%s] %s请求(第%d次)失败: %v\n", job.ip, job.reqTag, retry+1, err)
				}
				continue
			}

			duration := time.Since(startTime)

			// 按请求标的处理响应
			switch job.purpose {
			case "body":
				// 需要响应体，应该是trace请求
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					fmt.Printf("[%s] %s请求(第%d次)读取响应体失败: %v\n", job.ip, job.reqTag, retry+1, err)
					continue
				}
				respondChan <- httpRes{ip: job.ip, reqTag: job.reqTag, duration: duration, body: body}
			case "rttonly":
				// 不需要响应体，应该是回源请求
				respondChan <- httpRes{ip: job.ip, reqTag: job.reqTag, duration: duration, url: job.url}
			case "speed":
				// 需要响应体长度，应该是测速请求
				written, _ := io.Copy(io.Discard, resp.Body) // _:忽略大概率会有的超时提示
				speed := float64(written) / duration.Seconds() / 1024
				respondChan <- httpRes{ip: job.ip, reqTag: job.reqTag, downSpeed: speed}
			}
			// 走到这里的都是好请求，关闭响应体给个good，跳出循环
			resp.Body.Close()
			good = true
			break
		}
		// 判断是break还是重试次数用尽
		if !good {
			// 全部超时
			respondChan <- httpRes{ip: job.ip, reqTag: job.reqTag, err: fmt.Errorf("请求全部超时")}
		} else {
			// 重置标志
			good = false
		}
		wg.Done()
	}
}

type requestMap struct {
	reqMap map[string]*http.Request
}

func (mp *requestMap) appendRequest(url string) {
	// 创建一个 nobody http 请求
	req, err := http.NewRequest("GET", url, http.NoBody)
	if err != nil {
		timef("Worker创建HTTP.Request时出错: %v\n", err)
	}
	// 设置请求头
	req.Header.Set("User-Agent", UA)
	// 关闭请求
	req.Close = true
	mp.reqMap[url] = req
}

// HTTP 和回源测试部分
func httpTests(ips []string) map[string]*resultHTTP {
	// 初始化请求集合
	reqMap := new(requestMap)
	reqMap.reqMap = make(map[string]*http.Request)

	// 获得修整后的traceURL
	rectifyTraceURL, tracePort := rectifyURL(traceURL)
	reqMap.appendRequest(rectifyTraceURL)
	type oriPair struct {
		URL  string
		port int
	}
	// 获得修整后的回源URL集合
	rectifyOriginURLs := make([]oriPair, len(originURLs))
	for i, url := range originURLs {
		rectifyOriginURLs[i].URL, rectifyOriginURLs[i].port = rectifyURL(url)
		originURLs[i] = rectifyOriginURLs[i].URL
		reqMap.appendRequest(rectifyOriginURLs[i].URL)
	}
	jobPerIP := 1 + len(originURLs)

	var wg sync.WaitGroup
	jobChan := make(chan httpJob, len(ips)*jobPerIP)
	respondChan := make(chan httpRes, *maxThreads)
	// 启动工作者
	timef("正在启动 HTTP worker\n")
	for w := 0; w < *maxThreads; w++ {
		go httpWorker(httpTimeout, *maxRetries, reqMap.reqMap, jobChan, respondChan, &wg)
	}

	timef("开始执行 HTTP和回源 测试\n")
	for _, ip := range ips {
		wg.Add(jobPerIP)
		// HTTP 测试
		jobChan <- httpJob{ip, tracePort, rectifyTraceURL, "HTTP", "body"}

		// 回源测试
		for _, ori := range rectifyOriginURLs {
			jobChan <- httpJob{ip, ori.port, ori.URL, "回源", "rttonly"}
		}
	}
	go func() {
		timef("任务队列构建完毕，正在等待 HTTP 测试结束...\n")
		wg.Wait()
		close(jobChan)
		close(respondChan)
		timef("HTTP 测试已结束，正在等待数据整理...\n")
	}()

	// 从respondChan中读取结果并整理
	var resultMap = make(map[string]*resultHTTP)
	re := regexp.MustCompile(`colo=([A-Z]+)`)
	for rsd := range respondChan {
		if rsd.err != nil {
			fmt.Printf("[%s] %s测试失败: %v\n", rsd.ip, rsd.reqTag, rsd.err)
			continue
		}
		// 检出结果或初始化
		result, exists := resultMap[rsd.ip]
		if !exists {
			// resultMap[rsd.ip] = resultHTTP{ip: rsd.ip}
			resultMap[rsd.ip] = new(resultHTTP)
			result = resultMap[rsd.ip]
		}
		// 根据请求类型处理结果输出
		switch rsd.reqTag {
		case "HTTP":
			// 记录 dataCenter, region, city, httpRTT
			result.httpRTT = rsd.duration
			if matches := re.FindStringSubmatch(string(rsd.body)); len(matches) > 1 {
				colo := matches[1]
				result.dataCenter = colo
				if loc, ok := locationMap[colo]; ok {
					result.region = loc.Region
					result.city = loc.City
					fmt.Printf("[%s] HTTP-RTT %d ms，数据中心: %s, 地区: %s, 城市: %s\n",
						rsd.ip, result.httpRTT.Milliseconds(), result.dataCenter, result.region, result.city)
				} else {
					fmt.Printf("[%s] HTTP-RTT %d ms，数据中心: %s，但未找到数据中心的位置信息\n",
						rsd.ip, result.httpRTT.Milliseconds(), result.dataCenter)
				}
			}
		case "回源":
			if result.originRTTs == nil {
				// 新增回源 RTT 记录
				result.originRTTs = make(map[string]time.Duration)
				result.originRTTs[rsd.url] = rsd.duration
			} else {
				// 增写回源 RTT 记录
				result.originRTTs[rsd.url] = rsd.duration
				fmt.Printf("[%s] 回源(%s)RTT: %d ms\n", rsd.ip, rsd.url, rsd.duration.Milliseconds())
			}
		}
	}

	return resultMap
}

// speedTests 对已经通过延迟测试的IP进行下载速度测试
// 它使用goroutine并发进行测速，并通过channel返回结果
// 过程中，调用reportProgress报告测试进度
func speedTests(ips []string) []resultSpeed {
	// 初始化请求集合
	reqMap := new(requestMap)
	reqMap.reqMap = make(map[string]*http.Request)

	// 获得修整后的traceURL
	rectifyspeedURL, speedPort := rectifyURL(*speedTestURL)
	reqMap.appendRequest(rectifyspeedURL)

	var wg sync.WaitGroup
	jobChan := make(chan httpJob, len(ips))
	respondChan := make(chan httpRes, *maxThreads)
	// 启动工作者
	timef("正在启动 HTTP worker\n")
	for w := 0; w < *maxThreads; w++ {
		go httpWorker(downloadDuration, speedRetries, reqMap.reqMap, jobChan, respondChan, &wg)
	}

	timef("开始执行 速度 测试\n")
	for _, ip := range ips {
		wg.Add(1)
		// HTTP 测试
		jobChan <- httpJob{ip, speedPort, rectifyspeedURL, "测速", "speed"}
	}
	go func() {
		timef("任务队列构建完毕，正在等待 速度 测试结束...\n")
		wg.Wait()
		close(jobChan)
		close(respondChan)
		timef("速度 测试已结束，正在等待数据整理...\n")
	}()

	doneCount := 0
	total := len(ips)
	resultSlice := make([]resultSpeed, 0)
	for rsd := range respondChan {
		// 报告进度
		doneCount++
		percentage := float64(doneCount) / float64(total) * 100
		timef("测速进度：%d / %d 已完成（%.2f%%）\n", doneCount, total, percentage)
		// 记录结果
		speed, err := rsd.downSpeed, rsd.err
		if err != nil {
			fmt.Printf("[%s] 测速失败: %v\n", rsd.ip, err)
		} else {
			fmt.Printf("[%s] 测速结果: %.2f KB/s\n", rsd.ip, speed)
			resultSlice = append(resultSlice, resultSpeed{ip: rsd.ip, downSpeed: speed})
		}
	}

	return resultSlice
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
		"TCP Reach", "RTT min", "RTT avg", "RTT max", "HTTP RTT"}
	for _, url := range originURLs {
		header = append(header, fmt.Sprintf("回源%s", url))
	}
	if *doSpeedTest > 0 {
		header = append(header, "下载速度")
	}
	writer.Write(header)

	// 写入 CSV 记录
	for _, res := range results {
		// 有响应的记录
		record := []string{
			res.ip,
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
		}
		// 回源 RTT 数据
		for _, url := range originURLs {
			if rtt, ok := res.originRTTs[url]; ok {
				record = append(record, fmt.Sprintf("%d", rtt.Milliseconds()))
			} else {
				record = append(record, "N/A")
			}
		}
		// 测速数据
		if *doSpeedTest > 0 {
			record = append(record, fmt.Sprintf("%.0f", res.downSpeed))
		}
		writer.Write(record)
	}
	for _, ip := range tcpDead {
		// 没得响应的记录
		writer.Write([]string{ip, "", "", "", "", "", "不可达"})
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
	// 解析回源测试URL
	if *originTestURL != "" {
		for _, url := range strings.Split(*originTestURL, ",") {
			if url != "" {
				originURLs = append(originURLs, url)
			}
		}
	}
	timef("解析到 %d 个回源测试目标：%v\n", len(originURLs), originURLs)

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
	aliveStats, ipDead := tcpTests(ips)
	var ipAlive []string
	for ip := range aliveStats {
		ipAlive = append(ipAlive, ip)
	}

	// HTTP和回源测试
	resultHTTPMap := httpTests(ipAlive)

	// 测速
	var resultSpeedSlice []resultSpeed
	if *doSpeedTest > 0 {
		resultSpeedSlice = speedTests(ipAlive)
	}

	// 初始化 resultMergeMap
	resultMergeMap := make(map[string]*resultMerge)
	for _, ip := range ipAlive {
		resultMergeMap[ip] = &resultMerge{ip: ip}
	}

	// resultMap <- TCP 测试结果
	for ip, res := range aliveStats {
		resultMergeMap[ip].resultTCP = *res
	}

	// resultMap <- HTTP 测试结果
	for ip, res := range resultHTTPMap {
		resultMergeMap[ip].resultHTTP = *res

	}

	// resultMap <- 测速结果
	for _, res := range resultSpeedSlice {
		resultMergeMap[res.ip].resultSpeed = res
	}

	// resultMap 转 slice，排序
	var results []resultMerge
	for _, res := range resultMergeMap {
		results = append(results, *res)
	}
	if *doSpeedTest > 0 {
		// 根据下载速度，降序排序
		sort.Slice(results, func(i, j int) bool {
			return results[i].downSpeed > results[j].downSpeed
		})
	} else {
		// 根据TCP平均RTT，升序排序
		sort.Slice(results, func(i, j int) bool {
			return results[i].tcpRTTavg < results[j].tcpRTTavg
		})
	}

	// 清除输出内容
	// clearConsole()

	// 输出结果到文件
	outFileName := fmt.Sprintf("%s-%s.csv", *outFilePrefix, startTime.Format("20060102_150405"))
	resultsToCSV(results, ipDead, outFileName)

	timef("读入的IP总数: %d, 响应的记录总数: %d\n", len(ips), len(results))
	timef("测试总耗时 %d 秒，结果写入文件 %s\n", time.Since(startTime)/time.Second, outFileName)
}
