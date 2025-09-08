// netscan.go
// A fast, concurrent TCP/UDP network/port scanner written in Go.
// ⚠️ For educational and authorized security testing ONLY.
//
// Features:
//   • CIDR, single host, or file input
//   • Port list parser: ranges + comma lists
//   • Highly concurrent worker pool
//   • Per-connection timeout
//   • Optional lightweight banner grab
//   • Optional JSON output
//   • Selectable protocol (TCP or UDP)
//
// Usage examples:
//   go run netscan.go -target scanme.nmap.org -ports 22,80,443
//   go run netscan.go -target 10.10.10.10 -ports 1-65535 -proto udp
//
// Or run without flags for interactive mode.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanResult represents a single open port finding
type ScanResult struct {
	Target  string `json:"target"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Banner  string `json:"banner,omitempty"`
	Elapsed int64  `json:"elapsed_ms"`
}

// Config holds CLI options
type Config struct {
	Target   string
	File     string
	Ports    string
	Proto    string // Added protocol field
	Timeout  time.Duration
	Workers  int
	Banner   bool
	JSONPath string
}

func main() {
	// Display a welcome and credit message at the very start
	fmt.Println("=== Netscan by Aman ===")

	cfg := parseFlags()

	var targets []string

	// Load from -target
	if cfg.Target != "" {
		t, err := expandTargets(cfg.Target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] target error: %v\n", err)
			os.Exit(1)
		}
		targets = append(targets, t...)
	}

	// Load from -file
	if cfg.File != "" {
		fileTargets, err := readTargetsFromFile(cfg.File)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] file error: %v\n", err)
			os.Exit(1)
		}
		for _, line := range fileTargets {
			t, err := expandTargets(line)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] skip %s: %v\n", line, err)
				continue
			}
			targets = append(targets, t...)
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No targets provided (use -target or -file)")
		os.Exit(2)
	}

	portList, err := parsePorts(cfg.Ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] ports error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[+] Starting scan with %d workers, timeout=%v\n", cfg.Workers, cfg.Timeout)
	ctx := context.Background()
	results := runScan(ctx, targets, portList, cfg)

	// sort output by target then port
	sort.Slice(results, func(i, j int) bool {
		if results[i].Target == results[j].Target {
			return results[i].Port < results[j].Port
		}
		return results[i].Target < results[j].Target
	})

	printResults(results)

	if cfg.JSONPath != "" {
		if err := writeJSON(cfg.JSONPath, results); err != nil {
			fmt.Fprintf(os.Stderr, "[!] failed to write JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n[+] JSON saved to %s\n", cfg.JSONPath)
	}
}

// parseFlags handles both flags and interactive prompts
func parseFlags() Config {
	var cfg Config
	flag.StringVar(&cfg.Target, "target", "", "Target host or CIDR (e.g., 192.168.1.0/24, scanme.nmap.org)")
	flag.StringVar(&cfg.File, "file", "", "File with list of targets (one per line)")
	flag.StringVar(&cfg.Ports, "ports", "", "Ports to scan (e.g., 22,80,443 or 1-1024)")
	flag.StringVar(&cfg.Proto, "proto", "tcp", "Protocol to scan (tcp or udp)")
	flag.DurationVar(&cfg.Timeout, "timeout", 1200*time.Millisecond, "Per-connection timeout (e.g., 1500ms, 2s)")
	flag.IntVar(&cfg.Workers, "workers", 400, "Number of concurrent workers")
	flag.BoolVar(&cfg.Banner, "banner", false, "Attempt lightweight banner grab on open ports")
	flag.StringVar(&cfg.JSONPath, "json", "", "Write results to JSON file path")
	flag.Parse()

	// Interactive prompts if no flags were provided
	if cfg.Target == "" && cfg.File == "" {
		fmt.Println("\n--- Interactive Mode ---\nLet's get started. Please provide a target for the scan.")
		fmt.Print("Enter a target host or CIDR (e.g., 192.168.1.0/24) or leave empty if using a file: ")
		fmt.Scanln(&cfg.Target)

		if cfg.Target == "" {
			fmt.Print("Enter the file path containing targets: ")
			fmt.Scanln(&cfg.File)
		}
	}
	if cfg.Ports == "" {
		fmt.Print("Enter ports to scan (e.g., 22,80,443 or 1-1024): ")
		fmt.Scanln(&cfg.Ports)
	}
	if cfg.Proto == "tcp" { // Only prompt for protocol if default is used
		fmt.Print("Enter the protocol to scan (tcp or udp) [default: tcp]: ")
		var p string
		if _, err := fmt.Scanln(&p); err == nil && (p == "tcp" || p == "udp") {
			cfg.Proto = p
		}
	}
	if cfg.Workers == 400 {
		fmt.Print("Enter number of concurrent workers [default: 400]: ")
		var w int
		if _, err := fmt.Scanln(&w); err == nil && w > 0 {
			cfg.Workers = w
		}
	}
	fmt.Print("Attempt banner grabbing on open ports? (y/n): ")
	var ans string
	fmt.Scanln(&ans)
	if strings.ToLower(ans) == "y" {
		cfg.Banner = true
	}
	fmt.Print("Enter a per-connection timeout in ms [default: 1200]: ")
	var t int
	if _, err := fmt.Scanln(&t); err == nil && t > 0 {
		cfg.Timeout = time.Duration(t) * time.Millisecond
	}
	fmt.Print("Enter a JSON output path (leave empty to skip): ")
	fmt.Scanln(&cfg.JSONPath)

	return cfg
}

// expandTargets returns a list of IP strings for either a hostname, IP, or CIDR
func expandTargets(s string) ([]string, error) {
	// Try CIDR first
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return cidrHosts(ipnet), nil
	}
	// Resolve hostname or raw IP
	ips, err := net.LookupHost(s)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// readTargetsFromFile loads each line of a file as a target
func readTargetsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// cidrHosts enumerates all IPs in a CIDR block (excluding network/broadcast for IPv4)
func cidrHosts(n *net.IPNet) []string {
	var out []string
	for ip := firstIP(n); n.Contains(ip); ip = nextIP(ip) {
		out = append(out, ip.String())
	}
	// drop network/broadcast for IPv4 if present
	if len(out) >= 2 && ip4(n.IP) != nil {
		return out[1 : len(out)-1]
	}
	return out
}

func firstIP(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	copy(ip, n.IP)
	return ip
}

func nextIP(ip net.IP) net.IP {
	ip = append(net.IP(nil), ip...)
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
	return ip
}

func ip4(ip net.IP) net.IP { return ip.To4() }

// parsePorts handles inputs like "22,80,443" and "1-1024"
func parsePorts(s string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			pieces := strings.SplitN(part, "-", 2)
			if len(pieces) != 2 {
				return nil, errors.New("bad port range")
			}
			lo, hi := atoi(pieces[0]), atoi(pieces[1])
			if lo <= 0 || hi <= 0 || lo > 65535 || hi > 65535 || lo > hi {
				return nil, errors.New("invalid port range")
			}
			for p := lo; p <= hi; p++ {
				seen[p] = true
			}
			continue
		}
		p := atoi(part)
		if p <= 0 || p > 65535 {
			return nil, fmt.Errorf("invalid port: %s", part)
		}
		seen[p] = true
	}
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}

func atoi(s string) int {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// runScan executes the worker pool across all targets and ports
func runScan(ctx context.Context, targets []string, ports []int, cfg Config) []ScanResult {
	type job struct {
		host string
		port int
	}
	jobs := make(chan job, cfg.Workers*2)
	results := make(chan ScanResult, cfg.Workers*2)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			start := time.Now()
			addr := fmt.Sprintf("%s:%d", j.host, j.port)

			// The "tcp" protocol is now dynamic based on the flag
			conn, err := net.DialTimeout(cfg.Proto, addr, cfg.Timeout)
			if err == nil {
				// Note: For UDP, net.DialTimeout will return a connection
				// immediately as it's a connectionless protocol.
				// This simple check will only detect if the port is "reachable",
				// not necessarily if a service is listening. A more robust
				// UDP scan would send a packet and wait for a response
				// or an ICMP "port unreachable" message.
				_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
				banner := ""
				if cfg.Banner {
					// Try a passive read for a short banner
					b := make([]byte, 128)
					n, _ := conn.Read(b)
					if n > 0 {
						banner = sanitize(string(b[:n]))
					}
				}
				_ = conn.Close()
				elapsed := time.Since(start).Milliseconds()
				results <- ScanResult{Target: j.host, Port: j.port, Proto: cfg.Proto, Banner: banner, Elapsed: elapsed}
			}
		}
	}

	wg.Add(cfg.Workers)
	for i := 0; i < cfg.Workers; i++ {
		go worker()
	}

	go func() {
		for _, t := range targets {
			for _, p := range ports {
				select {
				case jobs <- job{t, p}:
				case <-ctx.Done():
					close(jobs)
					return
				}
			}
		}
		close(jobs)
	}()

	go func() { wg.Wait(); close(results) }()

	var out []ScanResult
	for r := range results {
		out = append(out, r)
	}
	return out
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func printResults(res []ScanResult) {
	if len(res) == 0 {
		fmt.Println("\n[✔] No open ports found. The target may be protected by a firewall or no services are running on the specified ports.")
		return
	}
	cur := ""
	for _, r := range res {
		if r.Target != cur {
			cur = r.Target
			fmt.Printf("\n--- Scan Results for %s ---\n", cur)
		}
		if r.Banner != "" {
			fmt.Printf(" [✔] %5d/%s is open (took %dms) - Banner: %s\n", r.Port, r.Proto, r.Elapsed, r.Banner)
		} else {
			fmt.Printf(" [✔] %5d/%s is open (took %dms)\n", r.Port, r.Proto, r.Elapsed)
		}
	}
	fmt.Println("\n--- Scan Complete. Thanks for using Netscan! ---\n")
}

func writeJSON(path string, res []ScanResult) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
