package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
	tcpTimeout  = 1 * time.Second                      // TCP连接超时时间
	httpTimeout = 2 * time.Second                      // HTTP请求超时时间
	traceURL    = "speed.cloudflare.com/cdn-cgi/trace" // Cloudflare trace URL
)

var (
	ipFile       = flag.String("ipin", "ip.txt", "IP地址文件名称")                                   // IP地址文件名称
	outFile      = flag.String("outfile", "ip.csv", "输出文件名称")                                  // 输出文件名称
	tcpPort      = flag.Int("tcport", 443, "端口")                                               // 端口
	maxThreads   = flag.Int("th", 100, "并发请求最大协程数")                                            // 最大协程数
	doSpeedTest  = flag.Int("spdt", 0, "下载测速协程数量,设为0禁用测速")                                     // 下载测速协程数量
	speedTestURL = flag.String("url", "speed.cloudflare.com/__down?bytes=500000000", "测速文件地址") // 测速文件地址
	forceTLS     = flag.Bool("tls", false, "是否强制启用TLS")                                        // TLS是否启用
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
	downloadSpeed float64 // 下载速度
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// IPaddOne函数实现ip地址自增
func IPaddOne(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 从文件中读取IP地址
func readIPs(File string) ([]string, error) {
	file, err := os.Open(File)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ipAddr := scanner.Text()
		// 判断是否为 CIDR 格式的 IP 地址
		if strings.Contains(ipAddr, "/") {
			ip, ipNet, err := net.ParseCIDR(ipAddr)
			if err != nil {
				fmt.Printf("无法解析CIDR格式的IP: %v\n", err)
				continue
			}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); IPaddOne(ip) {
				ips = append(ips, ip.String())
			}
		} else {
			ips = append(ips, ipAddr)
		}
	}
	return ips, scanner.Err()
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
	req.Header.Set("User-Agent", "Mozilla/5.0")

	// 创建TCP连接
	dialer := &net.Dialer{
		Timeout:   tcpTimeout,
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

func main() {
	flag.Parse()

	startTime := time.Now()
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

	var locations []location
	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在\n正在从 https://speed.cloudflare.com/locations 下载 locations.json")
		resp, err := http.Get("https://speed.cloudflare.com/locations")
		if err != nil {
			fmt.Printf("无法从URL中获取JSON: %v\n", err)
			return
		}

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("无法读取响应体: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
		file, err := os.Create("locations.json")
		if err != nil {
			fmt.Printf("无法创建文件: %v\n", err)
			return
		}
		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			fmt.Printf("无法写入文件: %v\n", err)
			return
		}
	} else {
		fmt.Println("本地 locations.json 已存在,无需重新下载")
		file, err := os.Open("locations.json")
		if err != nil {
			fmt.Printf("无法打开文件: %v\n", err)
			return
		}
		defer file.Close()

		body, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("无法读取文件: %v\n", err)
			return
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			fmt.Printf("无法解析JSON: %v\n", err)
			return
		}
	}

	locationMap := make(map[string]location)
	for _, loc := range locations {
		locationMap[loc.Iata] = loc
	}

	ips, err := readIPs(*ipFile)
	if err != nil {
		fmt.Printf("无法从文件中读取 IP: %v\n", err)
		return
	}

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
			req.Header.Set("User-Agent", "Mozilla/5.0")
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
		fmt.Printf("开始测速\n")
		var wg2 sync.WaitGroup
		wg2.Add(*doSpeedTest)
		count = 0
		total := len(resultChan)
		results = []resultAddSpeed{}
		for i := 0; i < *doSpeedTest; i++ {
			thread <- struct{}{}
			go func() {
				defer func() {
					<-thread
					wg2.Done()
				}()
				for res := range resultChan {

					downloadSpeed := speedOnce(res.ip)
					results = append(results, resultAddSpeed{resultNoSpeed: res, downloadSpeed: downloadSpeed})

					count++
					percentage := float64(count) / float64(total) * 100
					fmt.Printf("已完成: %.2f%%\r", percentage)
					if count == total {
						fmt.Printf("已完成: %.2f%%\033[0\n", percentage)
					}
				}
			}()
		}
		wg2.Wait()
	} else {
		for res := range resultChan {
			results = append(results, resultAddSpeed{resultNoSpeed: res})
		}
	}

	if *doSpeedTest > 0 {
		sort.Slice(results, func(i, j int) bool {
			return results[i].downloadSpeed > results[j].downloadSpeed
		})
	} else {
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
			writer.Write([]string{res.resultNoSpeed.ip, strconv.Itoa(res.resultNoSpeed.port), strconv.FormatBool(*forceTLS), res.resultNoSpeed.dataCenter, res.resultNoSpeed.region, res.resultNoSpeed.city, fmt.Sprintf("%d ms", res.resultNoSpeed.tcpRTT), fmt.Sprintf("%.0f kB/s", res.downloadSpeed)})
		} else {
			writer.Write([]string{res.resultNoSpeed.ip, strconv.Itoa(res.resultNoSpeed.port), strconv.FormatBool(*forceTLS), res.resultNoSpeed.dataCenter, res.resultNoSpeed.region, res.resultNoSpeed.city, fmt.Sprintf("%d ms", res.resultNoSpeed.tcpRTT)})
		}
	}

	writer.Flush()
	// 清除输出内容
	fmt.Print("\033[2J")
	fmt.Printf("成功将结果写入文件 %s，耗时 %d秒\n", *outFile, time.Since(startTime)/time.Second)
}
