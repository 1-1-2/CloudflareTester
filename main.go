package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	tcpTimeout       = 1 * time.Second                      // TCP连接超时时间
	httpTimeout      = 2 * time.Second                      // HTTP请求超时时间
	downloadDuration = 5 * time.Second                      // 最长下载持续时间
	traceURL         = "speed.cloudflare.com/cdn-cgi/trace" // Cloudflare trace URL
	UA               = "Mozilla/5.0"                        // User-Agent
	limitCIDR        = 1024                                 // 单条CIDR最大长度限制
)

var (
	ipFile       = flag.String("ipin", "ip.txt", "IP地址文件名称")                                   // IP地址文件名称
	outFile      = flag.String("outfile", "ip.csv", "输出文件名称")                                  // 输出文件名称
	tcpPort      = flag.Int("tcport", 443, "端口")                                               // 端口
	maxThreads   = flag.Int("th", 100, "并发请求最大协程数")                                            // 最大协程数
	doSpeedTest  = flag.Int("spdt", 0, "下载测速协程数量,设为0禁用测速")                                     // 下载测速协程数量
	speedTestURL = flag.String("url", "speed.cloudflare.com/__down?bytes=500000000", "测速文件地址") // 测速文件地址
	forceTLS     = flag.Bool("tls", false, "是否强制启用TLS")                                        // TLS是否启用
	maxAttempt   = flag.Int("attempt", 5, "最大重试次数")                                            // 各项测试最大重试次数
	ipCounts     = 0                                                                           // 存储读入的ip总数
	startTime    = time.Now()
)

type resultNoSpeed struct {
	ip         string        // IP地址
	port       int           // 端口
	dataCenter string        // 数据中心
	region     string        // 地区
	city       string        // 城市
	tcpRTT     time.Duration // TCP请求延迟
}

type resultAddSpeed struct {
	resultNoSpeed
	downSpeed float64 // 下载速度
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
func loadLocations() (map[string]location, error) {
	const locationFile = "locations.json"
	const locationURL = "https://speed.cloudflare.com/locations"

	// 检查本地文件是否存在
	if _, err := os.Stat(locationFile); os.IsNotExist(err) {
		timef("本地未找到 locations.json, 正从 %s 下载...", locationURL)
		if err := getJSON(locationURL, locationFile); err != nil {
			return nil, err
		}
	} else {
		timef("本地 locations.json 已存在, 无需重新下载\n")
	}

	// 读取和解析 JSON 文件
	jsbody, err := os.ReadFile(locationFile)
	if err != nil {
		return nil, fmt.Errorf("无法读取文件: %v", err)
	}
	var locations []location
	if err := json.Unmarshal(jsbody, &locations); err != nil {
		return nil, fmt.Errorf("JSON解析失败: %v", err)
	}

	// 构建 location 字典
	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}
	return locationMap, nil
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
	var ips []string
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

// 测速函数
func speedOnce(ip string) float64 {
	var protocol string
	if *forceTLS {
		protocol = "https://"
	} else {
		protocol = "http://"
	}
	speedTestURL := protocol + *speedTestURL
	// 创建请求
	req, _ := http.NewRequest("GET", speedTestURL, nil)
	req.Header.Set("User-Agent", UA)

	// 创建TCP连接
	dialer := &net.Dialer{
		Timeout:   downloadDuration,
		KeepAlive: 0,
	}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(*tcpPort)))
	if err != nil {
		return 0
	}
	defer conn.Close()

	fmt.Printf("正在测试IP %s 端口 %s\n", ip, strconv.Itoa(*tcpPort))
	startTime := time.Now()
	// 创建HTTP客户端
	client := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		//设置单个IP测速最长时间为5秒
		Timeout: 5 * time.Second,
	}
	// 发送请求
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("IP %s 端口 %s 测速无效\n", ip, strconv.Itoa(*tcpPort))
		return 0
	}
	defer resp.Body.Close()

	// 复制响应体到/dev/null，并计算下载速度
	written, _ := io.Copy(io.Discard, resp.Body)
	duration := time.Since(startTime)
	speed := float64(written) / duration.Seconds() / 1024

	// 输出结果
	fmt.Printf("IP %s 端口 %s 下载速度 %.0f kB/s\n", ip, strconv.Itoa(*tcpPort), speed)
	return speed
}

// speedTests 对已经通过延迟测试的IP进行下载速度测试
// 它使用goroutine并发进行测速，并通过channel返回结果
// 过程中，调用reportProgress报告测试进度
func speedTests(resultChan chan resultNoSpeed) []resultAddSpeed {
	var wg sync.WaitGroup
	thread := make(chan struct{}, *maxThreads)

	// 创建 speedResultsChan 通道，用于存储 speedtestresult 结构体
	speedResultsChan := make(chan resultAddSpeed, len(resultChan))

	// 创建 progressChan 和 doneChan 通道，启动 reportProgress 函数，用于报告进度
	progressChan := make(chan int, 1)
	doneChan := make(chan struct{})
	go reportProgress(progressChan, len(resultChan), doneChan)

	// 遍历 resultChan 通道，对每个结果进行处理
	for res := range resultChan {
		wg.Add(1)
		thread <- struct{}{}
		go func(res resultNoSpeed) {
			defer func() {
				<-thread
				wg.Done()
			}()

			// 测速，结果发送到 speedResultsChan 通道
			downloadSpeed := speedOnce(res.ip)
			speedResultsChan <- resultAddSpeed{resultNoSpeed: res, downSpeed: downloadSpeed}

			// 进度+1
			progressChan <- 1
		}(res)
	}

	// 等待所有任务完成
	timef("正在等待 测速 结束...\n")
	go func() {
		wg.Wait()
		close(speedResultsChan)
		close(progressChan)
	}()

	// 等待 reportProgress 函数完成
	<-doneChan

	timef("测速已结束，正在统计数据...\n")
	var results []resultAddSpeed
	for speedResult := range speedResultsChan {
		results = append(results, speedResult)
	}

	return results
}

func reportProgress(progressChan chan int, total int, doneChan chan struct{}) {
	currentCount := 0
	for count := range progressChan {
		currentCount += count
		percentage := float64(currentCount) / float64(total) * 100
		timef("已完成: %.2f%%\r", percentage)
		if currentCount == total {
			timef("已完成: %.2f%%\n", percentage)
			break
		}
	}
	doneChan <- struct{}{}
}

func main() {
	flag.Parse()

	osType := runtime.GOOS
	if osType == "linux" {
		// 尝试提升文件描述符的上限
		fmt.Println("正在尝试提升文件描述符的上限...")
		cmd := exec.Command("bash", "-c", "ulimit -n 10000")
		_, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("提升文件描述符上限时出现错误: %v\n", err)
		} else {
			fmt.Printf("文件描述符上限已提升!\n")
		}
	}

	// 从文件中读取 IP 地址
	ips, err := readIPs(*ipFile)
	if err != nil {
		timef("读取文件时发生错误: %v\n", err)
		return
	}

	// 加载地址库
	locationMap, err := loadLocations()

	var wg sync.WaitGroup
	wg.Add(len(ips))

	resultChan := make(chan resultNoSpeed, len(ips))

	thread := make(chan struct{}, *maxThreads)

	var count int
	total := len(ips)

	for _, ip := range ips {
		thread <- struct{}{}
		go func(ip string) {
			defer func() {
				<-thread
				wg.Done()
				count++
				percentage := float64(count) / float64(total) * 100
				fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", count, total, percentage)
				if count == total {
					fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\n", count, total, percentage)
				}
			}()

			dialer := &net.Dialer{
				Timeout:   tcpTimeout,
				KeepAlive: 0,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(*tcpPort)))
			if err != nil {
				return
			}
			defer conn.Close()

			tcpDuration := time.Since(start)
			start = time.Now()

			client := http.Client{
				Transport: &http.Transport{
					Dial: func(network, addr string) (net.Conn, error) {
						return conn, nil
					},
				},
				Timeout: tcpTimeout,
			}

			var protocol string
			if *forceTLS {
				protocol = "https://"
			} else {
				protocol = "http://"
			}
			requestURL := protocol + traceURL

			req, _ := http.NewRequest("GET", requestURL, nil)

			// 添加用户代理
			req.Header.Set("User-Agent", UA)
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return
			}

			duration := time.Since(start)
			if duration > httpTimeout {
				return
			}

			body := &bytes.Buffer{}
			// 创建一个读取操作的超时
			timeout := time.After(httpTimeout)
			// 使用一个 goroutine 来读取响应体
			done := make(chan bool)
			go func() {
				_, err := io.Copy(body, resp.Body)
				done <- true
				if err != nil {
					return
				}
			}()
			// 等待读取操作完成或者超时
			select {
			case <-done:
				// 读取操作完成
			case <-timeout:
				// 读取操作超时
				return
			}

			if strings.Contains(body.String(), "uag=Mozilla/5.0") {
				if matches := regexp.MustCompile(`colo=([A-Z]+)`).FindStringSubmatch(body.String()); len(matches) > 1 {
					dataCenter := matches[1]
					loc, ok := locationMap[dataCenter]
					if ok {
						fmt.Printf("发现有效IP %s 位置信息 %s 延迟 %d 毫秒\n", ip, loc.City, tcpDuration.Milliseconds())
						resultChan <- resultNoSpeed{ip, *tcpPort, dataCenter, loc.Region, loc.City, tcpDuration}
					} else {
						fmt.Printf("发现有效IP %s 位置信息未知 延迟 %d 毫秒\n", ip, tcpDuration.Milliseconds())
						resultChan <- resultNoSpeed{ip, *tcpPort, dataCenter, "", "", tcpDuration}
					}
				}
			}
		}(ip)
	}

	wg.Wait()
	close(resultChan)

	if len(resultChan) == 0 {
		// 清除输出内容
		fmt.Print("\033[2J")
		fmt.Println("没有发现有效的IP")
		return
	}

	var results []resultAddSpeed
	if *doSpeedTest > 0 {
		results := speedTests(resultChan)
		sort.Slice(results, func(i, j int) bool {
			return results[i].downSpeed > results[j].downSpeed
		})
	} else {
		for res := range resultChan {
			results = append(results, resultAddSpeed{resultNoSpeed: res})
		}
		sort.Slice(results, func(i, j int) bool {
			return results[i].resultNoSpeed.tcpRTT < results[j].resultNoSpeed.tcpRTT
		})
	}

	file, err := os.Create(*outFile)
	if err != nil {
		fmt.Printf("无法创建文件: %v\n", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if *doSpeedTest > 0 {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市", "网络延迟", "下载速度"})
	} else {
		writer.Write([]string{"IP地址", "端口", "TLS", "数据中心", "地区", "城市", "网络延迟"})
	}
	for _, res := range results {
		if *doSpeedTest > 0 {
			writer.Write([]string{res.resultNoSpeed.ip, strconv.Itoa(res.resultNoSpeed.port), strconv.FormatBool(*forceTLS), res.resultNoSpeed.dataCenter, res.resultNoSpeed.region, res.resultNoSpeed.city, fmt.Sprintf("%d ms", res.resultNoSpeed.tcpRTT), fmt.Sprintf("%.0f kB/s", res.downSpeed)})
		} else {
			writer.Write([]string{res.resultNoSpeed.ip, strconv.Itoa(res.resultNoSpeed.port), strconv.FormatBool(*forceTLS), res.resultNoSpeed.dataCenter, res.resultNoSpeed.region, res.resultNoSpeed.city, fmt.Sprintf("%d ms", res.resultNoSpeed.tcpRTT)})
		}
	}

	writer.Flush()
	// 清除输出内容
	fmt.Print("\033[2J")
	fmt.Printf("成功将结果写入文件 %s，耗时 %d秒\n", *outFile, time.Since(startTime)/time.Second)
}
