package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	timeout     = 1 * time.Second // 超时时间
	maxDuration = 2 * time.Second // 最大持续时间
)

var (
	activeConnections  int32 // 用于跟踪活跃连接的数量
	validIPClientCache sync.Map
	randomMu           sync.Mutex
	randomGenerator    = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// IPManager 用于安全管理 IP 地址状态
type IPManager struct {
	mu            sync.RWMutex
	currentIP     string
	ipAddresses   []string
	currentIndex  int
	allIPsChecked bool
}

func NewIPManager() *IPManager {
	return &IPManager{}
}

func (m *IPManager) SetIPAddresses(ips []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAddresses = ips
	m.currentIndex = 0
	m.allIPsChecked = false
}

func (m *IPManager) GetCurrentIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentIP
}

func (m *IPManager) SetCurrentIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentIP = ip
}

func (m *IPManager) GetIPAddresses() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ipAddresses
}

func (m *IPManager) IsAllIPsChecked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.allIPsChecked
}

func (m *IPManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ipAddresses = []string{}
	m.currentIP = ""
	m.currentIndex = 0
	m.allIPsChecked = false
}

func (m *IPManager) switchToNextValidIP(useTLS bool, port int, domain string, code int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 尝试从当前索引的下一个 IP 开始检查
	for i := m.currentIndex + 1; i < len(m.ipAddresses); i++ {
		ip := m.ipAddresses[i]

		// 跳过当前 IP
		if ip == m.currentIP {
			continue
		}

		if checkValidIP(ip, port, useTLS, domain, code) {
			m.currentIP = ip
			m.currentIndex = i
			m.allIPsChecked = false
			log.Printf("切换到新的有效 IP: %s 更新 IP 索引: %d", m.currentIP, m.currentIndex)
			return true
		}
	}

	m.allIPsChecked = true
	log.Println("所有 IP 都已检查过，程序将退出")
	return false
}

type result struct {
	ip          string        // IP地址
	dataCenter  string        // 数据中心
	region      string        // 地区
	city        string        // 城市
	latency     string        // 延迟
	tcpDuration time.Duration // TCP请求延迟
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

func main() {
	localAddr := flag.String("addr", "0.0.0.0:1234", "本地监听的 IP 和端口")
	code := flag.Int("code", 200, "HTTP/HTTPS 响应状态码")
	coloFilter := flag.String("colo", "", "筛选数据中心例如 HKG,SJC,LAX (多个数据中心用逗号隔开,留空则忽略匹配)")
	Delay := flag.Int("delay", 300, "有效延迟（毫秒），超过此延迟将断开连接")
	domain := flag.String("domain", "cloudflaremirrors.com/debian", "响应状态码检查的域名地址")
	ipCount := flag.Int("ipnum", 20, "提取的有效IP数量")
	ipsType := flag.String("ips", "4", "指定生成IPv4还是IPv6地址 (4或6)")
	num := flag.Int("num", 5, "目标负载 IP 数量")
	port := flag.Int("port", 443, "转发的目标端口")
	random := flag.Bool("random", true, "是否随机生成IP，如果为false，则从CIDR中拆分出所有IP")
	maxThreads := flag.Int("task", 100, "并发请求最大协程数")
	useTLS := flag.Bool("tls", true, "是否为 TLS 端口")

	flag.Parse()

	// 创建 IP 管理器
	ipManager := NewIPManager()

	// 启动 TCP 监听
	listener, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Fatalf("无法监听 %s: %v", *localAddr, err)
	}
	defer listener.Close()

	log.Printf("正在监听 %s 并转发到 %d 个目标地址，有效延迟：%d ms", *localAddr, *num, *Delay)

	for {
		startTime := time.Now()

		// 使用函数处理 locations.json，确保 defer 正确执行
		locations, err := loadLocations()
		if err != nil {
			log.Printf("加载位置信息失败: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}

		locationMap := make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}

		var url string
		var filename string

		// 使用 switch 替代 if-else
		switch *ipsType {
		case "6":
			filename = "ips-v6.txt"
			url = "https://www.baipiao.eu.org/cloudflare/ips-v6"
		case "4":
			filename = "ips-v4.txt"
			url = "https://www.baipiao.eu.org/cloudflare/ips-v4"
		default:
			fmt.Println("无效的IP类型。请使用 '4' 或 '6'")
			return
		}

		var content string

		// 检查本地是否有文件
		if _, err = os.Stat(filename); os.IsNotExist(err) {
			fmt.Printf("文件 %s 不存在，正在从 URL %s 下载数据\n", filename, url)
			content, err = getURLContent(url)
			if err != nil {
				fmt.Println("获取URL内容出错:", err)
				return
			}
			err = saveToFile(filename, content)
			if err != nil {
				fmt.Println("保存文件出错:", err)
				return
			}
		} else {
			content, err = getFileContent(filename)
			if err != nil {
				fmt.Println("读取本地文件出错:", err)
				return
			}
		}

		var ipList []string
		if *random {
			ipList = parseIPList(content)
			switch *ipsType {
			case "6":
				ipList = getRandomIPv6s(ipList)
			case "4":
				ipList = getRandomIPv4s(ipList)
			}
		} else {
			ipList, err = readIPs(filename)
			if err != nil {
				fmt.Println("读取IP出错:", err)
				return
			}
		}

		// 从生成的 IP 列表进行处理
		results := scanIPs(ipList, locationMap, *maxThreads)

		if len(results) == 0 {
			fmt.Println("未发现有效IP")
			time.Sleep(3 * time.Second)
			continue
		}

		// 应用数据中心筛选
		if *coloFilter != "" {
			filters := strings.Split(*coloFilter, ",")
			var filteredResults []result
			for _, r := range results {
				for _, filter := range filters {
					if strings.EqualFold(r.dataCenter, filter) {
						filteredResults = append(filteredResults, r)
						break
					}
				}
			}
			results = filteredResults
		}

		// 按 TCP 延迟排序
		sort.Slice(results, func(i, j int) bool {
			return results[i].tcpDuration < results[j].tcpDuration
		})

		// 只显示指定数量的 IP
		if len(results) > *ipCount {
			results = results[:*ipCount]
		}

		fmt.Println("IP 地址 | 数据中心 | 地区 | 城市 | 延迟")
		for _, r := range results {
			fmt.Printf("%s | %s | %s | %s | %s\n", r.ip, r.dataCenter, r.region, r.city, r.latency)
		}

		fmt.Printf("成功提取 %d 个有效IP，耗时 %d秒\n", len(results), time.Since(startTime)/time.Second)

		// 设置 IP 地址列表
		var ips []string
		for _, r := range results {
			ips = append(ips, r.ip)
		}
		ipManager.SetIPAddresses(ips)

		// 选择一个有效 IP
		currentIP := selectValidIP(ipManager, *useTLS, *port, *domain, *code)
		if currentIP == "" {
			log.Printf("没有有效的 IP 可用")
			continue
		}
		ipManager.SetCurrentIP(currentIP)

		// 创建用于控制 goroutine 退出的 context
		ctx, cancel := context.WithCancel(context.Background())

		// 用于状态检查完成的信号
		done := make(chan bool)

		var loopWG sync.WaitGroup
		loopWG.Add(2)

		// 启动状态检查线程
		go func() {
			defer loopWG.Done()
			statusCheck(ctx, *localAddr, *useTLS, *port, done, *domain, *code, time.Duration(*Delay)*time.Millisecond, ipManager)
		}()

		// 主循环，接收连接
		go func() {
			defer loopWG.Done()
			for {
				select {
				case <-ctx.Done():
					log.Println("连接接受 goroutine 收到退出信号")
					return
				default:
					// 设置接受连接的超时，以便能够检查 context
					if tcpListener, ok := listener.(*net.TCPListener); ok {
						tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
					}
					conn, err := listener.Accept()
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
							return
						}
						log.Printf("接受连接时发生错误: %v", err)
						continue
					}

					clientAddr := conn.RemoteAddr().String()
					atomic.AddInt32(&activeConnections, 1)
					log.Printf("客户端来源: %s 连接建立，当前活跃连接数: %d", clientAddr, atomic.LoadInt32(&activeConnections))

					currIP := ipManager.GetCurrentIP()
					go handleConnection(conn, generateTargets(currIP, *port, *num), time.Duration(*Delay)*time.Millisecond)
				}
			}
		}()

		<-done
		cancel() // 取消 context，通知所有 goroutine 退出
		loopWG.Wait()

		// 清空 IP 地址
		ipManager.Clear()
		validIPClientCache = sync.Map{}
		log.Println("主函数将退出当前循环，因为所有 IP 都已用尽")
	}
}

// loadLocations 加载位置信息，使用函数封装确保 defer 正确执行
func loadLocations() ([]location, error) {
	var locations []location

	if _, err := os.Stat("locations.json"); os.IsNotExist(err) {
		fmt.Println("本地 locations.json 不存在\n正在从 https://www.baipiao.eu.org/cloudflare/locations 下载 locations.json")
		resp, err := http.Get("https://www.baipiao.eu.org/cloudflare/locations")
		if err != nil {
			return nil, fmt.Errorf("无法从URL中获取JSON: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("无法读取响应体: %v", err)
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			return nil, fmt.Errorf("无法解析JSON: %v", err)
		}

		file, err := os.Create("locations.json")
		if err != nil {
			return nil, fmt.Errorf("无法创建文件: %v", err)
		}
		defer file.Close()

		_, err = file.Write(body)
		if err != nil {
			return nil, fmt.Errorf("无法写入文件: %v", err)
		}
	} else {
		file, err := os.Open("locations.json")
		if err != nil {
			return nil, fmt.Errorf("无法打开文件: %v", err)
		}
		defer file.Close()

		body, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("无法读取文件: %v", err)
		}

		err = json.Unmarshal(body, &locations)
		if err != nil {
			return nil, fmt.Errorf("无法解析JSON: %v", err)
		}
	}

	return locations, nil
}

// scanIPs 扫描 IP 列表并返回结果
func scanIPs(ipList []string, locationMap map[string]location, maxThreads int) []result {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []result

	thread := make(chan struct{}, maxThreads)

	var count int32
	total := len(ipList)

	for _, ip := range ipList {
		wg.Add(1)
		thread <- struct{}{}
		go func(ipAddr string) {
			defer func() {
				<-thread
				wg.Done()
				current := atomic.AddInt32(&count, 1)
				percentage := float64(current) / float64(total) * 100
				fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\r", current, total, percentage)
				if int(current) == total {
					fmt.Printf("已完成: %d 总数: %d 已完成: %.2f%%\n", current, total, percentage)
				}
			}()

			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: 0,
			}
			start := time.Now()
			conn, err := dialer.Dial("tcp", net.JoinHostPort(ipAddr, "80"))
			if err != nil {
				return
			}
			defer conn.Close()

			tcpDuration := time.Since(start)

			// 通过根路径响应头里的 CF-RAY 提取机房信息
			requestURL := "http://" + net.JoinHostPort(ipAddr, "80")
			req, err := http.NewRequest("GET", requestURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			req.Close = true

			conn.SetDeadline(time.Now().Add(maxDuration))
			err = req.Write(conn)
			if err != nil {
				return
			}

			reader := bufio.NewReader(conn)
			resp, err := http.ReadResponse(reader, req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			cfRay := strings.TrimSpace(resp.Header.Get("CF-RAY"))
			if cfRay == "" {
				return
			}

			parts := strings.Split(cfRay, "-")
			if len(parts) < 2 {
				return
			}

			dataCenter := strings.TrimSpace(parts[len(parts)-1])
			if dataCenter == "" {
				return
			}

			loc, ok := locationMap[dataCenter]
			mu.Lock()
			if ok {
				fmt.Printf("发现有效IP %s 位置信息 %s 延迟 %d 毫秒\n", ipAddr, loc.City, tcpDuration.Milliseconds())
				results = append(results, result{ipAddr, dataCenter, loc.Region, loc.City, fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			} else {
				fmt.Printf("发现有效IP %s 位置信息未知 延迟 %d 毫秒\n", ipAddr, tcpDuration.Milliseconds())
				results = append(results, result{ipAddr, dataCenter, "", "", fmt.Sprintf("%d ms", tcpDuration.Milliseconds()), tcpDuration})
			}
			mu.Unlock()
		}(ip)
	}

	wg.Wait()
	return results
}

// 获取URL内容
func getURLContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP请求失败，状态码: %d", resp.StatusCode)
	}

	var content strings.Builder
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			content.WriteString(line + "\n")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return content.String(), nil
}

// 从本地文件读取内容
func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 将内容保存到本地文件
func saveToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

// 解析IP列表，跳过空行
func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			ipList = append(ipList, line)
		}
	}
	return ipList
}

func nextRandomIntn(n int) int {
	randomMu.Lock()
	defer randomMu.Unlock()
	return randomGenerator.Intn(n)
}

// 从每个/24子网随机提取一个IPv4
func getRandomIPv4s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		// 跳过空行
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/24")
		octets := strings.Split(baseIP, ".")
		if len(octets) >= 4 {
			octets[3] = fmt.Sprintf("%d", nextRandomIntn(256))
			randomIP := strings.Join(octets, ".")
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}

// 从每个/48子网随机提取一个IPv6
func getRandomIPv6s(ipList []string) []string {
	var randomIPs []string
	for _, subnet := range ipList {
		// 跳过空行
		subnet = strings.TrimSpace(subnet)
		if subnet == "" {
			continue
		}
		baseIP := strings.TrimSuffix(subnet, "/48")
		sections := strings.Split(baseIP, ":")
		if len(sections) >= 3 {
			sections = sections[:3]
			for i := 3; i < 8; i++ {
				sections = append(sections, fmt.Sprintf("%x", nextRandomIntn(65536)))
			}
			randomIP := strings.Join(sections, ":")
			randomIPs = append(randomIPs, randomIP)
		}
	}
	return randomIPs
}

// 从CIDR中拆分出所有IP
func readIPs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			ipAddr, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				return nil, err
			}
			// 使用新变量避免遮蔽
			for currentIP := ipAddr.Mask(ipNet.Mask); ipNet.Contains(currentIP); incrementIP(currentIP) {
				ips = append(ips, currentIP.String())
			}
		} else {
			ips = append(ips, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

// 增加IP
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func generateTargets(ip string, port int, num int) []string {
	targets := make([]string, num)
	address := ip
	if strings.Contains(ip, ":") {
		address = fmt.Sprintf("[%s]", ip)
	}
	for i := 0; i < num; i++ {
		targets[i] = fmt.Sprintf("%s:%d", address, port)
	}
	return targets
}

func checkValidIP(ip string, port int, useTLS bool, domain string, code int) bool {
	address := ip
	if strings.Contains(ip, ":") {
		address = fmt.Sprintf("[%s]", ip)
	}
	targetURL := fmt.Sprintf("http://%s", domain)
	if useTLS {
		targetURL = fmt.Sprintf("https://%s", domain)
	}

	cacheKey := fmt.Sprintf("%s:%d", address, port)
	clientAny, loaded := validIPClientCache.Load(cacheKey)
	var client *http.Client
	if loaded {
		client = clientAny.(*http.Client)
	} else {
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Printf("尝试连接 IP: %s 端口: %d", ip, port)
				dialer := &net.Dialer{Timeout: 2 * time.Second}
				return dialer.DialContext(ctx, network, fmt.Sprintf("%s:%d", address, port))
			},
		}
		newClient := &http.Client{
			Timeout:   2 * time.Second,
			Transport: transport,
		}
		actual, _ := validIPClientCache.LoadOrStore(cacheKey, newClient)
		client = actual.(*http.Client)
	}

	log.Printf("向 URL %s 发送请求以检查 IP %s 是否有效", targetURL, ip)
	resp, err := client.Get(targetURL)
	if err != nil {
		log.Printf("检查 IP %s 时发生错误: %v", ip, err)
		return false
	}
	defer resp.Body.Close()

	log.Printf("IP %s 的检查响应状态码: %d", ip, resp.StatusCode)

	isValid := resp.StatusCode == code
	if isValid {
		log.Printf("IP %s 是有效的", ip)
	} else {
		log.Printf("IP %s 不是有效的", ip)
	}

	return isValid
}

func selectValidIP(ipManager *IPManager, useTLS bool, port int, domain string, code int) string {
	for _, ip := range ipManager.GetIPAddresses() {
		if checkValidIP(ip, port, useTLS, domain, code) {
			return ip
		}
	}
	return ""
}

func statusCheck(ctx context.Context, localAddr string, useTLS bool, port int, done chan bool, domain string, code int, delay time.Duration, ipManager *IPManager) {
	_, localPort, _ := net.SplitHostPort(localAddr)
	checkAddr := fmt.Sprintf("127.0.0.1:%s", localPort)

	for {
		select {
		case <-ctx.Done():
			log.Println("状态检查收到退出信号")
			return
		default:
		}

		failCount := 0
		log.Printf("开始状态检查，目标地址: %s", checkAddr)

		for failCount < 2 {
			select {
			case <-ctx.Done():
				log.Println("状态检查收到退出信号")
				return
			default:
			}

			conn, err := net.DialTimeout("tcp", checkAddr, delay)
			if err != nil {
				failCount++
				log.Printf("状态检查失败 (%d/2): 无法连接到 %s 错误: %v", failCount, checkAddr, err)
				time.Sleep(1 * time.Second)
				continue
			}

			// 使用带超时的读取检查
			checkSuccess := make(chan bool, 1)
			go func() {
				reader := bufio.NewReader(conn)
				conn.SetReadDeadline(time.Now().Add(delay + 1*time.Second))
				_, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						checkSuccess <- false
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						// 超时说明连接保持正常
						checkSuccess <- true
					} else {
						checkSuccess <- false
					}
				} else {
					checkSuccess <- true
				}
			}()

			select {
			case success := <-checkSuccess:
				if success {
					log.Printf("状态检查成功: 连接到 %s 成功", checkAddr)
					failCount = 0
				} else {
					failCount++
					log.Printf("状态检查失败 (%d/2): 服务端断开连接", failCount)
				}
			case <-time.After(delay + 2*time.Second):
				log.Printf("状态检查成功: 连接到 %s 保持稳定", checkAddr)
				failCount = 0
			case <-ctx.Done():
				conn.Close()
				log.Println("状态检查收到退出信号")
				return
			}

			conn.Close()

			if failCount == 0 {
				time.Sleep(2 * time.Second)
				break
			}
		}

		if failCount >= 2 {
			log.Println("连续两次状态检查失败，切换到下一个 IP")
			if !ipManager.switchToNextValidIP(useTLS, port, domain, code) {
				log.Println("所有 IP 都已检查过，状态检查停止")
				done <- true
				return
			}
		}
	}
}

// 处理客户端连接，尝试连接到指定的转发地址，并选择延迟最低的连接
func handleConnection(conn net.Conn, forwardAddrs []string, delay time.Duration) {
	defer func() {
		clientAddr := conn.RemoteAddr().String()
		atomic.AddInt32(&activeConnections, -1)
		log.Printf("客户端来源: %s 连接关闭，当前活跃连接数: %d", clientAddr, atomic.LoadInt32(&activeConnections))
		conn.Close()
	}()

	type connResult struct {
		conn   net.Conn
		addr   string
		delay  time.Duration
		errMsg string
	}

	results := make(chan connResult, len(forwardAddrs))

	// 并发尝试连接每个转发地址
	for _, addr := range forwardAddrs {
		go func(targetAddr string) {
			start := time.Now()
			forwardConn, err := net.DialTimeout("tcp", targetAddr, delay)
			elapsed := time.Since(start)

			if err != nil {
				results <- connResult{nil, targetAddr, elapsed, fmt.Sprintf("连接到 %s 的延迟超过有效值 %d ms", targetAddr, delay.Milliseconds())}
				return
			}

			results <- connResult{forwardConn, targetAddr, elapsed, ""}
		}(addr)
	}

	var validConns []connResult
	var bestConn net.Conn
	var bestDelay time.Duration
	var bestAddr string

	// 收集结果并找到延迟最低的有效连接
	for i := 0; i < len(forwardAddrs); i++ {
		res := <-results
		if res.conn != nil {
			validConns = append(validConns, res)

			if bestConn == nil || res.delay < bestDelay {
				if bestConn != nil {
					bestConn.Close()
				}
				bestConn = res.conn
				bestDelay = res.delay
				bestAddr = res.addr
			} else {
				res.conn.Close()
			}
		} else {
			log.Printf("错误: %s", res.errMsg)
		}
	}

	log.Println("符合要求的连接:")
	for _, vc := range validConns {
		log.Printf("地址: %s 延迟: %d ms", vc.addr, vc.delay.Milliseconds())
	}

	// 如果找到最佳连接，开始转发数据
	if bestConn != nil {
		log.Printf("选择最佳连接: 地址: %s 延迟: %d ms", bestAddr, bestDelay.Milliseconds())
		pipeConnections(conn, bestConn)
	} else {
		log.Println("未找到符合延迟要求的连接，关闭客户端连接")
	}
}

func pipeConnections(src, dst net.Conn) {
	var wg sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			src.Close()
			dst.Close()
		})
	}

	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(src, dst)
		closeBoth()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		closeBoth()
	}()

	wg.Wait()
}
