package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type ClusterStats struct {
	ClusterName string `json:"cluster_name"`
	Status      string `json:"status"`
	Indices     struct {
		Count  int `json:"count"`
		Shards struct {
			Total int `json:"total"`
		} `json:"shards"`
		Docs struct {
			Count int `json:"count"`
		} `json:"docs"`
		Store struct {
			SizeInBytes      int64 `json:"size_in_bytes"`
			TotalSizeInBytes int64 `json:"total_size_in_bytes"`
		} `json:"store"`
	} `json:"indices"`
	Nodes struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Failed     int `json:"failed"`
	} `json:"_nodes"`
	Process struct {
		CPU struct {
			Percent int `json:"percent"`
		} `json:"cpu"`
		OpenFileDescriptors struct {
			Min int `json:"min"`
			Max int `json:"max"`
			Avg int `json:"avg"`
		} `json:"open_file_descriptors"`
	} `json:"process"`
	Snapshots struct {
		Count int `json:"count"`
	} `json:"snapshots"`
}

type NodesInfo struct {
	Nodes map[string]struct {
		Name             string   `json:"name"`
		TransportAddress string   `json:"transport_address"`
		Version          string   `json:"version"`
		Roles            []string `json:"roles"`
		OS               struct {
			AvailableProcessors int    `json:"available_processors"`
			Name                string `json:"name"`
			Arch                string `json:"arch"`
			Version             string `json:"version"`
			PrettyName          string `json:"pretty_name"`
		} `json:"os"`
		Process struct {
			ID int `json:"id"`
		} `json:"process"`
	} `json:"nodes"`
}

type IndexStats []struct {
	Index     string `json:"index"`
	Health    string `json:"health"`
	DocsCount string `json:"docs.count"`
	StoreSize string `json:"store.size"`
	PriShards string `json:"pri"`
	Replicas  string `json:"rep"`
}

type IndexActivity struct {
	LastDocsCount    int
	InitialDocsCount int
	StartTime        time.Time
}

type IndexWriteStats struct {
	Indices map[string]struct {
		Total struct {
			Indexing struct {
				IndexTotal int64 `json:"index_total"`
			} `json:"indexing"`
		} `json:"total"`
	} `json:"indices"`
}

type ClusterHealth struct {
	ActiveShards                int     `json:"active_shards"`
	ActivePrimaryShards         int     `json:"active_primary_shards"`
	RelocatingShards            int     `json:"relocating_shards"`
	InitializingShards          int     `json:"initializing_shards"`
	UnassignedShards            int     `json:"unassigned_shards"`
	DelayedUnassignedShards     int     `json:"delayed_unassigned_shards"`
	NumberOfPendingTasks        int     `json:"number_of_pending_tasks"`
	TaskMaxWaitingTime          string  `json:"task_max_waiting_time"`
	ActiveShardsPercentAsNumber float64 `json:"active_shards_percent_as_number"`
}

type NodesStats struct {
	Nodes map[string]struct {
		Indices struct {
			Store struct {
				SizeInBytes int64 `json:"size_in_bytes"`
			} `json:"store"`
			Search struct {
				QueryTotal        int64 `json:"query_total"`
				QueryTimeInMillis int64 `json:"query_time_in_millis"`
			} `json:"search"`
			Indexing struct {
				IndexTotal        int64 `json:"index_total"`
				IndexTimeInMillis int64 `json:"index_time_in_millis"`
			} `json:"indexing"`
			Segments struct {
				Count int64 `json:"count"`
			} `json:"segments"`
		} `json:"indices"`
		OS struct {
			CPU struct {
				Percent int `json:"percent"`
			} `json:"cpu"`
			Memory struct {
				UsedInBytes  int64 `json:"used_in_bytes"`
				FreeInBytes  int64 `json:"free_in_bytes"`
				TotalInBytes int64 `json:"total_in_bytes"`
			} `json:"mem"`
			LoadAverage map[string]float64 `json:"load_average"`
		} `json:"os"`
		JVM struct {
			Memory struct {
				HeapUsedInBytes int64 `json:"heap_used_in_bytes"`
				HeapMaxInBytes  int64 `json:"heap_max_in_bytes"`
			} `json:"mem"`
			GC struct {
				Collectors struct {
					Young struct {
						CollectionCount        int64 `json:"collection_count"`
						CollectionTimeInMillis int64 `json:"collection_time_in_millis"`
					} `json:"young"`
					Old struct {
						CollectionCount        int64 `json:"collection_count"`
						CollectionTimeInMillis int64 `json:"collection_time_in_millis"`
					} `json:"old"`
				} `json:"collectors"`
			} `json:"gc"`
			UptimeInMillis int64 `json:"uptime_in_millis"`
		} `json:"jvm"`
		Transport struct {
			RxSizeInBytes int64 `json:"rx_size_in_bytes"`
			TxSizeInBytes int64 `json:"tx_size_in_bytes"`
			RxCount       int64 `json:"rx_count"`
			TxCount       int64 `json:"tx_count"`
		} `json:"transport"`
		HTTP struct {
			CurrentOpen int64 `json:"current_open"`
		} `json:"http"`
		Process struct {
			OpenFileDescriptors int64 `json:"open_file_descriptors"`
		} `json:"process"`
		FS struct {
			DiskReads  int64 `json:"disk_reads"`
			DiskWrites int64 `json:"disk_writes"`
			Total      struct {
				TotalInBytes     int64 `json:"total_in_bytes"`
				FreeInBytes      int64 `json:"free_in_bytes"`
				AvailableInBytes int64 `json:"available_in_bytes"`
			} `json:"total"`
			Data []struct {
				Path             string `json:"path"`
				TotalInBytes     int64  `json:"total_in_bytes"`
				FreeInBytes      int64  `json:"free_in_bytes"`
				AvailableInBytes int64  `json:"available_in_bytes"`
			} `json:"data"`
		} `json:"fs"`
	} `json:"nodes"`
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
}

// SecurityAlerts represents the response from security alerts aggregation query
type SecurityAlerts struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
	} `json:"hits"`
	Aggregations struct {
		BySeverity struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int    `json:"doc_count"`
			} `json:"buckets"`
		} `json:"by_severity"`
		ByHost struct {
			Buckets []struct {
				Key      string `json:"key"`
				DocCount int    `json:"doc_count"`
				HostInfo struct {
					Hits struct {
						Hits []struct {
							Source struct {
								Host struct {
									Name string `json:"name"`
									OS   struct {
										Type string `json:"type"`
									} `json:"os"`
								} `json:"host"`
							} `json:"_source"`
						} `json:"hits"`
					} `json:"hits"`
				} `json:"host_info"`
				BySeverity struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"by_severity"`
				ByUser struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"by_user"`
			} `json:"buckets"`
		} `json:"by_host"`
		ByRule struct {
			Buckets []struct {
				Key          string `json:"key"`
				DocCount     int    `json:"doc_count"`
				RuleSeverity struct {
					Buckets []struct {
						Key      string `json:"key"`
						DocCount int    `json:"doc_count"`
					} `json:"buckets"`
				} `json:"rule_severity"`
			} `json:"buckets"`
		} `json:"by_rule"`
	} `json:"aggregations"`
}

var (
	latestVersion string
	versionCache  time.Time
)

var indexActivities = make(map[string]*IndexActivity)

var (
	showNodes         = true
	showRoles         = true
	showIndices       = true
	showMetrics       = true
	showSecurity      = true
	showHiddenIndices = false
)

var (
	header                *tview.TextView
	nodesPanelContainer   *tview.Flex
	rolesPanel            *tview.TextView
	indicesPanelContainer *tview.Flex
	indicesPanel          *tview.TextView
	indicesSummary        *tview.TextView
	metricsPanel          *tview.TextView
	securityPanel         *tview.TextView
)

// MetricsHistory stores historical data points for sparklines
type MetricsHistory struct {
	CPU       []float64
	Memory    []float64
	Heap      []float64
	QueryRate []float64
	IndexRate []float64
	MaxPoints int
}

var metricsHistory = &MetricsHistory{MaxPoints: 60}

func (h *MetricsHistory) AddPoint(cpu, mem, heap, qRate, iRate float64) {
	h.CPU = append(h.CPU, cpu)
	h.Memory = append(h.Memory, mem)
	h.Heap = append(h.Heap, heap)
	h.QueryRate = append(h.QueryRate, qRate)
	h.IndexRate = append(h.IndexRate, iRate)

	// Trim to MaxPoints
	if len(h.CPU) > h.MaxPoints {
		h.CPU = h.CPU[1:]
	}
	if len(h.Memory) > h.MaxPoints {
		h.Memory = h.Memory[1:]
	}
	if len(h.Heap) > h.MaxPoints {
		h.Heap = h.Heap[1:]
	}
	if len(h.QueryRate) > h.MaxPoints {
		h.QueryRate = h.QueryRate[1:]
	}
	if len(h.IndexRate) > h.MaxPoints {
		h.IndexRate = h.IndexRate[1:]
	}
}

// renderSparkline converts data points to ASCII sparkline characters
func renderSparkline(data []float64, width int, color string) string {
	if len(data) == 0 {
		return strings.Repeat(" ", width)
	}

	blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	// Find min and max for scaling
	minVal, maxVal := data[0], data[0]
	for _, v := range data {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	// Avoid division by zero
	valRange := maxVal - minVal
	if valRange == 0 {
		valRange = 1
	}

	// Take the last 'width' points or pad if fewer
	startIdx := 0
	if len(data) > width {
		startIdx = len(data) - width
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("[%s]", color))

	// Pad with spaces if we have fewer points than width
	if len(data) < width {
		for i := 0; i < width-len(data); i++ {
			result.WriteRune(' ')
		}
	}

	for i := startIdx; i < len(data); i++ {
		// Normalize to 0-7 range
		normalized := int((data[i] - minVal) / valRange * 7)
		if normalized > 7 {
			normalized = 7
		}
		if normalized < 0 {
			normalized = 0
		}
		result.WriteRune(blocks[normalized])
	}
	result.WriteString("[white]")

	return result.String()
}

type DataStreamResponse struct {
	DataStreams []DataStream `json:"data_streams"`
}

type DataStream struct {
	Name      string `json:"name"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
	Template  string `json:"template"`
}

var (
	apiKey string
)

type CatNodesStats struct {
	Load1m string `json:"load_1m"`
	Name   string `json:"name"`
}

func bytesToHuman(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	units := []string{"B", "K", "M", "G", "T", "P", "E", "Z"}
	exp := 0
	val := float64(bytes)

	for val >= unit && exp < len(units)-1 {
		val /= unit
		exp++
	}

	return fmt.Sprintf("%.1f%s", val, units[exp])
}

func formatNumber(n int) string {
	str := fmt.Sprintf("%d", n)

	var result []rune
	for i, r := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, r)
	}
	return string(result)
}

// formatCompactNumber formats a number in compact form (1.2K, 1.2M, 1.2B)
func formatCompactNumber(n int) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func convertSizeFormat(sizeStr string) string {
	var size float64
	var unit string
	fmt.Sscanf(sizeStr, "%f%s", &size, &unit)

	unit = strings.ToUpper(strings.TrimSuffix(unit, "b"))

	return fmt.Sprintf("%d%s", int(size), unit)
}

// parseSizeToBytes converts a size string like "10gb" or "200mb" to bytes
func parseSizeToBytes(sizeStr string) int64 {
	var size float64
	var unit string
	fmt.Sscanf(sizeStr, "%f%s", &size, &unit)

	unit = strings.ToLower(strings.TrimSuffix(unit, "b"))

	multiplier := int64(1)
	switch unit {
	case "k", "kb":
		multiplier = 1024
	case "m", "mb":
		multiplier = 1024 * 1024
	case "g", "gb":
		multiplier = 1024 * 1024 * 1024
	case "t", "tb":
		multiplier = 1024 * 1024 * 1024 * 1024
	}

	return int64(size * float64(multiplier))
}

func getPercentageColor(percent float64) string {
	switch {
	case percent < 30:
		return "green"
	case percent < 70:
		return "#00ffff" // cyan
	case percent < 85:
		return "#ffff00" // yellow
	default:
		return "#ff5555" // light red
	}
}

func getLatestVersion() string {
	// Only fetch every hour
	if time.Since(versionCache) < time.Hour && latestVersion != "" {
		return latestVersion
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/elastic/elasticsearch/releases/latest")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return ""
	}

	latestVersion = strings.TrimPrefix(release.TagName, "v")
	versionCache = time.Now()
	return latestVersion
}

func compareVersions(current, latest string) bool {
	if latest == "" {
		return true
	}

	// Clean up version strings
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	// Split versions into parts
	currentParts := strings.Split(current, ".")
	latestParts := strings.Split(latest, ".")

	// Compare each part
	for i := 0; i < len(currentParts) && i < len(latestParts); i++ {
		curr, _ := strconv.Atoi(currentParts[i])
		lat, _ := strconv.Atoi(latestParts[i])
		if curr != lat {
			return curr >= lat
		}
	}
	return len(currentParts) >= len(latestParts)
}

var roleColors = map[string]string{
	"master":                "#ff5555", // red
	"data":                  "#50fa7b", // green
	"data_content":          "#8be9fd", // cyan
	"data_hot":              "#ffb86c", // orange
	"data_warm":             "#bd93f9", // purple
	"data_cold":             "#f1fa8c", // yellow
	"data_frozen":           "#ff79c6", // pink
	"ingest":                "#87cefa", // light sky blue
	"ml":                    "#6272a4", // blue gray
	"remote_cluster_client": "#dda0dd", // plum
	"transform":             "#689d6a", // forest green
	"voting_only":           "#458588", // teal
	"coordinating_only":     "#d65d0e", // burnt orange
}

var legendLabels = map[string]string{
	"master":                "Master",
	"data":                  "Data",
	"data_content":          "Data Content",
	"data_hot":              "Data Hot",
	"data_warm":             "Data Warm",
	"data_cold":             "Data Cold",
	"data_frozen":           "Data Frozen",
	"ingest":                "Ingest",
	"ml":                    "Machine Learning",
	"remote_cluster_client": "Remote Cluster Client",
	"transform":             "Transform",
	"voting_only":           "Voting Only",
	"coordinating_only":     "Coordinating Only",
}

func formatNodeRoles(roles []string) string {
	// Define all possible roles and their letters in the desired order
	roleMap := map[string]string{
		"master":                "M",
		"data":                  "D",
		"data_content":          "C",
		"data_hot":              "H",
		"data_warm":             "W",
		"data_cold":             "K",
		"data_frozen":           "F",
		"ingest":                "I",
		"ml":                    "L",
		"remote_cluster_client": "R",
		"transform":             "T",
		"voting_only":           "V",
		"coordinating_only":     "O",
	}

	// Create a map of the node's roles for quick lookup
	nodeRoles := make(map[string]bool)
	for _, role := range roles {
		nodeRoles[role] = true
	}

	// Create ordered list of role keys based on their letters
	orderedRoles := []string{
		"data_content",          // C
		"data",                  // D
		"data_frozen",           // F
		"data_hot",              // H
		"ingest",                // I
		"data_cold",             // K
		"ml",                    // L
		"master",                // M
		"coordinating_only",     // O
		"remote_cluster_client", // R
		"transform",             // T
		"voting_only",           // V
		"data_warm",             // W
	}

	result := ""
	for _, role := range orderedRoles {
		letter := roleMap[role]
		if nodeRoles[role] {
			// Node has this role - use the role's color
			result += fmt.Sprintf("[%s]%s[white]", roleColors[role], letter)
		} else {
			// Node doesn't have this role - use dark grey
			result += fmt.Sprintf("[#444444]%s[white]", letter)
		}
	}

	return result
}

// formatNodeRolesCompact shows only active roles (compact display for cards)
func formatNodeRolesCompact(roles []string) string {
	roleMap := map[string]string{
		"master":                "M",
		"data":                  "D",
		"data_content":          "C",
		"data_hot":              "H",
		"data_warm":             "W",
		"data_cold":             "K",
		"data_frozen":           "F",
		"ingest":                "I",
		"ml":                    "L",
		"remote_cluster_client": "R",
		"transform":             "T",
		"voting_only":           "V",
		"coordinating_only":     "O",
	}

	var result strings.Builder
	for _, role := range roles {
		if letter, ok := roleMap[role]; ok {
			color := roleColors[role]
			result.WriteString(fmt.Sprintf("[%s]%s", color, letter))
		}
	}
	result.WriteString("[white]")
	return result.String()
}

// truncateString truncates a string to maxLen, adding ".." if truncated
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func getHealthColor(health string) string {
	switch health {
	case "green":
		return "green"
	case "yellow":
		return "#ffff00" // yellow
	case "red":
		return "#ff5555" // light red
	default:
		return "white"
	}
}

type indexInfo struct {
	index        string
	health       string
	docs         int
	storeSize    string
	priShards    string
	replicas     string
	writeOps     int64
	indexingRate float64
}

// securityContentHeight holds the calculated height for the security panel
var securityContentHeight = 9 // default minimum

func updateGridLayout(grid *tview.Grid, showRoles, showIndices, showMetrics, showSecurity bool) {
	// Start with clean grid
	grid.Clear()

	visiblePanels := 0
	if showRoles {
		visiblePanels++
	}
	if showIndices {
		visiblePanels++
	}
	if showMetrics {
		visiblePanels++
	}

	// When only nodes panel is visible (and maybe security), use a single column layout
	if showNodes && visiblePanels == 0 && !showSecurity {
		grid.SetRows(3, 0) // Header and nodes only
		grid.SetColumns(0) // Single full-width column

		grid.AddItem(header, 0, 0, 1, 1, 0, 0, false)
		grid.AddItem(nodesPanelContainer, 1, 0, 1, 1, 0, 0, false)
		return
	}

	// Security panel height is calculated dynamically based on content
	securityPanelHeight := securityContentHeight

	if showNodes && visiblePanels == 0 && showSecurity {
		grid.SetRows(3, 0, securityPanelHeight) // Header, nodes, security (fixed)
		grid.SetColumns(0)

		grid.AddItem(header, 0, 0, 1, 1, 0, 0, false)
		grid.AddItem(nodesPanelContainer, 1, 0, 1, 1, 0, 0, false)
		grid.AddItem(securityPanel, 2, 0, 1, 1, 0, 0, false)
		return
	}

	// Configure rows based on what's visible
	// Row 0: Header (3 lines)
	// Row 1: Nodes (if visible)
	// Row 2: Bottom panels (roles/indices/metrics)
	// Row 3: Security (if visible) - fixed height
	if showNodes && showSecurity {
		grid.SetRows(3, 0, 0, securityPanelHeight) // Header, nodes, bottom panels, security
	} else if showNodes {
		grid.SetRows(3, 0, 0) // Header, nodes, bottom panels
	} else if showSecurity {
		grid.SetRows(3, 0, securityPanelHeight) // Header, bottom panels, security
	} else {
		grid.SetRows(3, 0) // Just header and bottom panels
	}

	// Configure columns based on visible panels
	colCount := visiblePanels
	if colCount == 0 {
		colCount = 1
	}
	switch {
	case visiblePanels == 3:
		if showRoles {
			grid.SetColumns(30, -2, -1)
		}
	case visiblePanels == 2:
		if showRoles {
			grid.SetColumns(30, 0)
		} else {
			grid.SetColumns(-1, -1)
		}
	case visiblePanels == 1:
		grid.SetColumns(0)
	case visiblePanels == 0:
		grid.SetColumns(0)
	}

	// Always show header at top spanning all columns
	grid.AddItem(header, 0, 0, 1, colCount, 0, 0, false)

	// Add nodes panel if visible, spanning all columns
	if showNodes {
		grid.AddItem(nodesPanelContainer, 1, 0, 1, colCount, 0, 0, false)
	}

	// Add bottom panels in their respective positions
	col := 0
	bottomRow := 1
	if showNodes {
		bottomRow = 2
	}

	if showRoles {
		grid.AddItem(rolesPanel, bottomRow, col, 1, 1, 0, 0, false)
		col++
	}
	if showIndices {
		grid.AddItem(indicesPanelContainer, bottomRow, col, 1, 1, 0, 0, false)
		col++
	}
	if showMetrics {
		grid.AddItem(metricsPanel, bottomRow, col, 1, 1, 0, 0, false)
	}

	// Add security panel on its own row at the bottom, spanning all columns
	if showSecurity {
		securityRow := bottomRow + 1
		if visiblePanels == 0 {
			securityRow = bottomRow
		}
		grid.AddItem(securityPanel, securityRow, 0, 1, colCount, 0, 0, false)
	}
}

func main() {
	host := flag.String("host", "http://localhost", "Elasticsearch host URL (e.g., http://localhost or https://example.com)")
	port := flag.Int("port", 9200, "Elasticsearch port")
	user := flag.String("user", os.Getenv("ES_USER"), "Elasticsearch username")
	password := flag.String("password", os.Getenv("ES_PASSWORD"), "Elasticsearch password")
	flag.StringVar(&apiKey, "apikey", os.Getenv("ES_API_KEY"), "Elasticsearch API key")

	// Add new certificate-related flags
	certFile := flag.String("cert", "", "Path to client certificate file")
	keyFile := flag.String("key", "", "Path to client private key file")
	caFile := flag.String("ca", "", "Path to CA certificate file")
	skipVerify := flag.Bool("insecure", false, "Skip TLS certificate verification")

	flag.Parse()

	// Validate and process the host URL
	if !strings.HasPrefix(*host, "http://") && !strings.HasPrefix(*host, "https://") {
		fmt.Fprintf(os.Stderr, "Error: host must start with http:// or https://\n")
		os.Exit(1)
	}

	// Validate authentication methods - only one should be used
	authMethods := 0
	if apiKey != "" {
		authMethods++
	}
	if *user != "" || *password != "" {
		authMethods++
	}
	if *certFile != "" || *keyFile != "" {
		authMethods++
	}
	if authMethods > 1 {
		fmt.Fprintf(os.Stderr, "Error: Cannot use multiple authentication methods simultaneously (API key, username/password, or certificates)\n")
		os.Exit(1)
	}

	// Validate certificate files if specified
	if (*certFile != "" && *keyFile == "") || (*certFile == "" && *keyFile != "") {
		fmt.Fprintf(os.Stderr, "Error: Both certificate and key files must be specified together\n")
		os.Exit(1)
	}

	// Strip any trailing slash from the host
	*host = strings.TrimRight(*host, "/")

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: *skipVerify,
	}

	// Load client certificates if specified
	if *certFile != "" && *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading client certificates: %v\n", err)
			os.Exit(1)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if specified
	if *caFile != "" {
		caCert, err := os.ReadFile(*caFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA certificate: %v\n", err)
			os.Exit(1)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			fmt.Fprintf(os.Stderr, "Error parsing CA certificate\n")
			os.Exit(1)
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Create custom HTTP client with SSL configuration
	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 10,
	}

	app := tview.NewApplication()

	// Update the grid layout to use proportional columns
	grid := tview.NewGrid().
		SetRows(3, 0, 0).       // Three rows: header, nodes, bottom panels
		SetColumns(-1, -2, -1). // Three columns for bottom row: roles (1), indices (2), metrics (1)
		SetBorders(true)

	// Initialize the panels (move initialization to package level)
	header = tview.NewTextView().
		SetDynamicColors(true).
		SetTextAlign(tview.AlignLeft)

	nodesPanelContainer = tview.NewFlex().
		SetDirection(tview.FlexRow)

	rolesPanel = tview.NewTextView(). // New panel for roles
						SetDynamicColors(true)

	indicesPanel = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)

	indicesSummary = tview.NewTextView().
		SetDynamicColors(true)

	indicesPanelContainer = tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(indicesPanel, 0, 1, false).  // Scrollable indices list (takes remaining space)
		AddItem(indicesSummary, 3, 0, false) // Fixed 3-line summary at bottom

	metricsPanel = tview.NewTextView().
		SetDynamicColors(true)

	securityPanel = tview.NewTextView().
		SetDynamicColors(true).
		SetScrollable(true)

	// Initial layout
	updateGridLayout(grid, showRoles, showIndices, showMetrics, showSecurity)

	// Add panels to grid
	grid.AddItem(header, 0, 0, 1, 3, 0, 0, false). // Header spans all columns
							AddItem(nodesPanelContainer, 1, 0, 1, 3, 0, 0, false). // Nodes panel spans all columns
							AddItem(rolesPanel, 2, 0, 1, 1, 0, 0, false).   // Roles panel in left column
							AddItem(indicesPanelContainer, 2, 1, 1, 1, 0, 0, false). // Indices panel in middle column
							AddItem(metricsPanel, 2, 2, 1, 1, 0, 0, false). // Metrics panel in right column
						AddItem(securityPanel, 3, 0, 1, 3, 0, 0, false) // Security panel spans all columns

	// Update function
	update := func() {
		baseURL := fmt.Sprintf("%s:%d", *host, *port)

		// Helper function for ES requests
		makeRequest := func(path string, target interface{}) error {
			req, err := http.NewRequest("GET", baseURL+path, nil)
			if err != nil {
				return err
			}

			// Set authentication
			if apiKey != "" {
				req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", apiKey))
			} else if *user != "" && *password != "" {
				req.SetBasicAuth(*user, *password)
			}

			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			return json.Unmarshal(body, target)
		}

		// Helper function for POST requests (used for search queries)
		makePostRequest := func(path string, requestBody []byte, target interface{}) error {
			req, err := http.NewRequest("POST", baseURL+path, bytes.NewReader(requestBody))
			if err != nil {
				return err
			}

			req.Header.Set("Content-Type", "application/json")

			// Set authentication
			if apiKey != "" {
				req.Header.Set("Authorization", fmt.Sprintf("ApiKey %s", apiKey))
			} else if *user != "" && *password != "" {
				req.SetBasicAuth(*user, *password)
			}

			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			return json.Unmarshal(body, target)
		}

		// Get cluster stats
		var clusterStats ClusterStats
		if err := makeRequest("/_cluster/stats", &clusterStats); err != nil {
			header.SetText(fmt.Sprintf("[red]Error: %v", err))
			return
		}

		// Get nodes info
		var nodesInfo NodesInfo
		if err := makeRequest("/_nodes", &nodesInfo); err != nil {
			header.SetText(fmt.Sprintf("[red]Error getting nodes info: %v", err))
			return
		}

		// Get indices stats
		var indicesStats IndexStats
		if err := makeRequest("/_cat/indices?format=json", &indicesStats); err != nil {
			indicesPanel.SetText(fmt.Sprintf("[red]Error: %v", err))
			return
		}

		// Get cluster health
		var clusterHealth ClusterHealth
		if err := makeRequest("/_cluster/health", &clusterHealth); err != nil {
			indicesPanel.SetText(fmt.Sprintf("[red]Error: %v", err))
			return
		}

		// Get nodes stats
		var nodesStats NodesStats
		if err := makeRequest("/_nodes/stats", &nodesStats); err != nil {
			indicesPanel.SetText(fmt.Sprintf("[red]Error: %v", err))
			return
		}

		// Get index write stats
		var indexWriteStats IndexWriteStats
		if err := makeRequest("/_stats", &indexWriteStats); err != nil {
			indicesPanel.SetText(fmt.Sprintf("[red]Error getting write stats: %v", err))
			return
		}

		// Query and indexing metrics
		var (
			totalQueries   int64
			totalQueryTime int64
			totalIndexing  int64
			totalIndexTime int64
			totalSegments  int64
		)

		for _, node := range nodesStats.Nodes {
			totalQueries += node.Indices.Search.QueryTotal
			totalQueryTime += node.Indices.Search.QueryTimeInMillis
			totalIndexing += node.Indices.Indexing.IndexTotal
			totalIndexTime += node.Indices.Indexing.IndexTimeInMillis
			totalSegments += node.Indices.Segments.Count
		}

		queryRate := float64(totalQueries) / float64(totalQueryTime) * 1000  // queries per second
		indexRate := float64(totalIndexing) / float64(totalIndexTime) * 1000 // docs per second

		// GC metrics
		var (
			totalGCCollections int64
			totalGCTime        int64
		)

		for _, node := range nodesStats.Nodes {
			totalGCCollections += node.JVM.GC.Collectors.Young.CollectionCount + node.JVM.GC.Collectors.Old.CollectionCount
			totalGCTime += node.JVM.GC.Collectors.Young.CollectionTimeInMillis + node.JVM.GC.Collectors.Old.CollectionTimeInMillis
		}

		// Update header
		statusColor := map[string]string{
			"green":  "green",
			"yellow": "yellow",
			"red":    "red",
		}[clusterStats.Status]

		// Get max lengths after fetching node and index info
		maxNodeNameLen, _, _, _ := getMaxLengths(nodesInfo, indicesStats)

		// Update header with dynamic padding
		header.Clear()
		latestVer := getLatestVersion()
		padding := 0
		if maxNodeNameLen > len(clusterStats.ClusterName) {
			padding = maxNodeNameLen - len(clusterStats.ClusterName)
		}
		fmt.Fprintf(header, "[#00ffff]Cluster :[white] %s [#666666]([%s]%s[-]%s[#666666]) [#00ffff]Latest: [white]%s\n",
			clusterStats.ClusterName,
			statusColor,
			strings.ToUpper(clusterStats.Status),
			strings.Repeat(" ", padding),
			latestVer)
		fmt.Fprintf(header, "[#00ffff]Nodes   :[white] %d Total, [green]%d[white] Successful, [#ff5555]%d[white] Failed\n",
			clusterStats.Nodes.Total,
			clusterStats.Nodes.Successful,
			clusterStats.Nodes.Failed)
		fmt.Fprintf(header, "[#666666]Press 2-6 to toggle panels, 'h' to toggle hidden indices, 'q' to quit[white]\n")

		// Update nodes panel with card-based layout
		updateNodesPanel(nodesPanelContainer, nodesInfo, nodesStats, latestVer, app)

		// Get data streams info
		var dataStreamResp DataStreamResponse
		if err := makeRequest("/_data_stream", &dataStreamResp); err != nil {
			indicesPanel.SetText(fmt.Sprintf("[red]Error getting data streams: %v", err))
			return
		}

		// Update indices panel with dynamic width
		indicesPanel.Clear()
		fmt.Fprintf(indicesPanel, "[::b][#00ffff][[#ff5555]4[#00ffff]] Indices Information[::-]\n\n")
		fmt.Fprint(indicesPanel, getIndicesPanelHeader())

		// Update index entries with dynamic width
		var indices []indexInfo
		var totalDocs int
		var totalSize int64

		// Collect index information
		for _, index := range indicesStats {
			// Skip hidden indices unless showHiddenIndices is true
			if (!showHiddenIndices && strings.HasPrefix(index.Index, ".")) || index.DocsCount == "0" {
				continue
			}
			docs := 0
			fmt.Sscanf(index.DocsCount, "%d", &docs)
			totalDocs += docs

			// Track document changes
			activity, exists := indexActivities[index.Index]
			if !exists {
				indexActivities[index.Index] = &IndexActivity{
					LastDocsCount:    docs,
					InitialDocsCount: docs,
					StartTime:        time.Now(),
				}
			} else {
				activity.LastDocsCount = docs
			}

			// Get write operations count and calculate rate
			writeOps := int64(0)
			indexingRate := float64(0)
			if stats, exists := indexWriteStats.Indices[index.Index]; exists {
				writeOps = stats.Total.Indexing.IndexTotal
				if activity, ok := indexActivities[index.Index]; ok {
					timeDiff := time.Since(activity.StartTime).Seconds()
					if timeDiff > 0 {
						indexingRate = float64(docs-activity.InitialDocsCount) / timeDiff
					}
				}
			}

			indices = append(indices, indexInfo{
				index:        index.Index,
				health:       index.Health,
				docs:         docs,
				storeSize:    index.StoreSize,
				priShards:    index.PriShards,
				replicas:     index.Replicas,
				writeOps:     writeOps,
				indexingRate: indexingRate,
			})
		}

		// Calculate total size from index store sizes
		for _, idx := range indices {
			totalSize += parseSizeToBytes(idx.storeSize)
		}

		// Sort indices - active ones first, then alphabetically within each group
		sort.Slice(indices, func(i, j int) bool {
			// Non-hidden indices first (those not starting with ".")
			iHidden := strings.HasPrefix(indices[i].index, ".")
			jHidden := strings.HasPrefix(indices[j].index, ".")
			if iHidden != jHidden {
				return !iHidden // non-hidden comes first
			}
			// Within hidden/non-hidden, active indices first
			iActive := indices[i].indexingRate > 0
			jActive := indices[j].indexingRate > 0
			if iActive != jActive {
				return iActive // active comes first
			}
			// Within same activity status, sort by indexing rate (highest first)
			return indices[i].indexingRate > indices[j].indexingRate
		})

		// Update index entries with compact format
		for _, idx := range indices {
			writeIcon := "[#444444]⚪"
			if idx.indexingRate > 0 {
				writeIcon = "[#5555ff]⚫"
			}

			// Add data stream indicator
			streamIndicator := " "
			if isDataStream(idx.index, dataStreamResp) {
				streamIndicator = "[#bd93f9]⚫"
			}

			// Format indexing rate (right-aligned, padding applied before color)
			var rateVal string
			var rateColor string
			if idx.indexingRate > 0 {
				rateColor = "#50fa7b"
				if idx.indexingRate >= 1000 {
					rateVal = fmt.Sprintf("%.1fk/s", idx.indexingRate/1000)
				} else {
					rateVal = fmt.Sprintf("%.1f/s", idx.indexingRate)
				}
			} else {
				rateColor = "#444444"
				rateVal = "0/s"
			}
			rateStr := fmt.Sprintf("[%s]%7s", rateColor, rateVal)

			// Convert the size format before display
			sizeStr := convertSizeFormat(idx.storeSize)

			// Combined shards/replicas
			prStr := fmt.Sprintf("%s/%s", idx.priShards, idx.replicas)

			// Truncate index name to 18 chars max
			displayName := truncateString(idx.index, 18)

			fmt.Fprintf(indicesPanel, "%s%s [%s]%-18s[white] %6s %5s %5s %s\n",
				writeIcon,
				streamIndicator,
				getHealthColor(idx.health),
				displayName,
				formatCompactNumber(idx.docs),
				sizeStr,
				prStr,
				rateStr)
		}

		// Calculate total indexing rate for the cluster
		totalIndexingRate := float64(0)
		for _, idx := range indices {
			totalIndexingRate += idx.indexingRate
		}

		// Format cluster indexing rate
		clusterRateStr := ""
		if totalIndexingRate > 0 {
			if totalIndexingRate >= 1000000 {
				clusterRateStr = fmt.Sprintf("[#50fa7b]%.1fM/s", totalIndexingRate/1000000)
			} else if totalIndexingRate >= 1000 {
				clusterRateStr = fmt.Sprintf("[#50fa7b]%.1fK/s", totalIndexingRate/1000)
			} else {
				clusterRateStr = fmt.Sprintf("[#50fa7b]%.1f/s", totalIndexingRate)
			}
		} else {
			clusterRateStr = "[#444444]0/s"
		}

		// Display the totals with indexing rate in the fixed summary panel
		indicesSummary.Clear()
		fmt.Fprintf(indicesSummary, "[#00ffff]Total:[white] %s docs, %s, %s\n",
			formatNumber(totalDocs),
			bytesToHuman(totalSize),
			clusterRateStr)

		// Shard stats in summary panel
		fmt.Fprintf(indicesSummary, "[#00ffff]Shards:[white] %d active (%.0f%%), %d primary, %d reloc, %d init, %d unassigned\n",
			clusterHealth.ActiveShards,
			clusterHealth.ActiveShardsPercentAsNumber,
			clusterHealth.ActivePrimaryShards,
			clusterHealth.RelocatingShards,
			clusterHealth.InitializingShards,
			clusterHealth.UnassignedShards)

		// Calculate metrics for display and history
		totalProcessors := 0
		for _, node := range nodesInfo.Nodes {
			totalProcessors += node.OS.AvailableProcessors
		}
		cpuPercent := float64(clusterStats.Process.CPU.Percent)

		diskUsed := getTotalSize(nodesStats)
		diskTotal := getTotalDiskSpace(nodesStats)
		diskPercent := float64(diskUsed) / float64(diskTotal) * 100

		var (
			totalHeapUsed    int64
			totalHeapMax     int64
			totalMemoryUsed  int64
			totalMemoryTotal int64
		)
		for _, node := range nodesStats.Nodes {
			totalHeapUsed += node.JVM.Memory.HeapUsedInBytes
			totalHeapMax += node.JVM.Memory.HeapMaxInBytes
			totalMemoryUsed += node.OS.Memory.UsedInBytes
			totalMemoryTotal += node.OS.Memory.TotalInBytes
		}
		heapPercent := float64(totalHeapUsed) / float64(totalHeapMax) * 100
		memoryPercent := float64(totalMemoryUsed) / float64(totalMemoryTotal) * 100

		// Add data points to history
		metricsHistory.AddPoint(cpuPercent, memoryPercent, heapPercent, queryRate, indexRate)

		// Rebuild metrics panel with ASCII sparklines
		metricsPanel.Clear()
		fmt.Fprintf(metricsPanel, "[::b][#00ffff][[#ff5555]5[#00ffff]] Cluster Metrics[::-]\n\n")

		// Calculate available width for sparklines and centering
		_, _, metricsPanelWidth, _ := metricsPanel.GetInnerRect()
		labelValueWidth := 28 // approximate width of label + value portion
		sparklineWidth := metricsPanelWidth - labelValueWidth
		if sparklineWidth < 5 {
			sparklineWidth = 0 // hide sparklines if too narrow
		} else if sparklineWidth > 30 {
			sparklineWidth = 30 // cap at reasonable max
		}

		// Fixed width for the label+value portion (before sparkline)
		fixedLabelValueWidth := 28

		// Helper to format a metric line with fixed width and optional sparkline
		formatMetricLine := func(label, value string, data []float64, color string) string {
			// Remove tview color tags for length calculation
			inTag := false
			visibleLen := 0
			for _, r := range value {
				if r == '[' {
					inTag = true
				} else if r == ']' && inTag {
					inTag = false
				} else if !inTag {
					visibleLen++
				}
			}

			// Calculate padding needed after value to reach fixed width
			labelLen := len(label) + 1 // +1 for colon
			valuePadding := fixedLabelValueWidth - labelLen - visibleLen
			if valuePadding < 1 {
				valuePadding = 1
			}

			line := fmt.Sprintf("[#00ffff]%s:[white]%s%s",
				label, strings.Repeat(" ", valuePadding), value)

			// Add sparkline if we have data and width
			if sparklineWidth > 0 && data != nil {
				line += " " + renderSparkline(data, sparklineWidth, color)
			}

			return line + "\n"
		}

		// CPU with sparkline
		cpuValue := fmt.Sprintf("[%s]%5.1f%%[white] (%d proc)", getPercentageColor(cpuPercent), cpuPercent, totalProcessors)
		fmt.Fprint(metricsPanel, formatMetricLine("CPU", cpuValue, metricsHistory.CPU, "green"))

		// Memory with sparkline
		memValue := fmt.Sprintf("%s / %s [%s]%3.0f%%[white]",
			bytesToHuman(totalMemoryUsed), bytesToHuman(totalMemoryTotal),
			getPercentageColor(memoryPercent), memoryPercent)
		fmt.Fprint(metricsPanel, formatMetricLine("Memory", memValue, metricsHistory.Memory, "#00ffff"))

		// Heap with sparkline
		heapValue := fmt.Sprintf("%s / %s [%s]%3.0f%%[white]",
			bytesToHuman(totalHeapUsed), bytesToHuman(totalHeapMax),
			getPercentageColor(heapPercent), heapPercent)
		fmt.Fprint(metricsPanel, formatMetricLine("Heap", heapValue, metricsHistory.Heap, "yellow"))

		// Disk (no sparkline)
		diskValue := fmt.Sprintf("%s / %s [%s]%3.0f%%[white]",
			bytesToHuman(diskUsed), bytesToHuman(diskTotal),
			getPercentageColor(diskPercent), diskPercent)
		fmt.Fprint(metricsPanel, formatMetricLine("Disk", diskValue, nil, ""))

		// Network TX/RX (no sparkline)
		netValue := fmt.Sprintf("%s / %s",
			bytesToHuman(getTotalNetworkTX(nodesStats)), bytesToHuman(getTotalNetworkRX(nodesStats)))
		fmt.Fprint(metricsPanel, formatMetricLine("Net TX/RX", netValue, nil, ""))

		// HTTP Connections (no sparkline)
		httpValue := formatNumber(int(getTotalHTTPConnections(nodesStats)))
		fmt.Fprint(metricsPanel, formatMetricLine("HTTP Conn", httpValue, nil, ""))

		// Query Rate with sparkline
		queryValue := fmt.Sprintf("%s/s", formatNumber(int(queryRate)))
		fmt.Fprint(metricsPanel, formatMetricLine("Query", queryValue, metricsHistory.QueryRate, "#50fa7b"))

		// Index Rate with sparkline
		indexValue := fmt.Sprintf("%s/s", formatNumber(int(indexRate)))
		fmt.Fprint(metricsPanel, formatMetricLine("Index", indexValue, metricsHistory.IndexRate, "#ff79c6"))

		// Snapshots (no sparkline)
		snapshotValue := formatNumber(clusterStats.Snapshots.Count)
		fmt.Fprint(metricsPanel, formatMetricLine("Snapshots", snapshotValue, nil, ""))

		if showRoles {
			updateRolesPanel(rolesPanel, nodesInfo)
		}

		// Update security panel if visible
		if showSecurity {
			// Security alerts aggregation query
			// Note: must_not excludes building block alerts (BBR) to match Kibana Security UI default view
			securityQuery := []byte(`{
				"size": 0,
				"query": {
					"bool": {
						"filter": [
							{ "term": { "kibana.alert.workflow_status": "open" } }
						],
						"must_not": [
							{ "exists": { "field": "kibana.alert.building_block_type" } }
						]
					}
				},
				"aggs": {
					"by_severity": {
						"terms": { "field": "kibana.alert.severity", "size": 10 }
					},
					"by_host": {
						"terms": { "field": "host.name", "size": 5 },
						"aggs": {
							"host_info": {
								"top_hits": {
									"size": 1,
									"_source": ["host.os.type"]
								}
							},
							"by_severity": {
								"terms": { "field": "kibana.alert.severity", "size": 10 }
							},
							"by_user": {
								"terms": { "field": "user.name", "size": 5 }
							}
						}
					},
					"by_rule": {
						"terms": { "field": "kibana.alert.rule.name", "size": 5 },
						"aggs": {
							"rule_severity": {
								"terms": { "field": "kibana.alert.severity", "size": 1 }
							}
						}
					}
				}
			}`)

			var securityAlerts SecurityAlerts
			err := makePostRequest("/.alerts-security.alerts-*/_search", securityQuery, &securityAlerts)
			if err != nil {
				// Show error in security panel but don't fail the entire update
				securityPanel.Clear()
				fmt.Fprintf(securityPanel, "[::b][#00ffff][[#ff5555]6[#00ffff]] Security Alerts[::-]\n\n")
				fmt.Fprintf(securityPanel, "[#666666]Unable to fetch security alerts: %v[white]\n", err)
			} else {
				if updateSecurityPanel(securityPanel, &securityAlerts) {
					// Height changed, update grid layout
					updateGridLayout(grid, showRoles, showIndices, showMetrics, showSecurity)
				}
			}
		}
	}

	// Set up periodic updates
	go func() {
		for {
			app.QueueUpdateDraw(func() {
				update()
			})
			time.Sleep(5 * time.Second)
		}
	}()

	// Handle quit
	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEsc:
			app.Stop()
		case tcell.KeyRune:
			switch event.Rune() {
			case 'q':
				app.Stop()
			case '2':
				showNodes = !showNodes
				updateGridLayout(grid, showRoles, showIndices, showMetrics, showSecurity)
			case '3':
				showRoles = !showRoles
				updateGridLayout(grid, showRoles, showIndices, showMetrics, showSecurity)
			case '4':
				showIndices = !showIndices
				updateGridLayout(grid, showRoles, showIndices, showMetrics, showSecurity)
			case '5':
				showMetrics = !showMetrics
				updateGridLayout(grid, showRoles, showIndices, showMetrics, showSecurity)
			case '6':
				showSecurity = !showSecurity
				updateGridLayout(grid, showRoles, showIndices, showMetrics, showSecurity)
			case 'h':
				showHiddenIndices = !showHiddenIndices
				// Let the regular update cycle handle it
			}
		}
		return event
	})

	if err := app.SetRoot(grid, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}

func getTotalNetworkTX(stats NodesStats) int64 {
	var total int64
	for _, node := range stats.Nodes {
		total += node.Transport.TxSizeInBytes
	}
	return total
}

func getTotalNetworkRX(stats NodesStats) int64 {
	var total int64
	for _, node := range stats.Nodes {
		total += node.Transport.RxSizeInBytes
	}
	return total
}

func getMaxLengths(nodesInfo NodesInfo, indicesStats IndexStats) (int, int, int, int) {
	maxNodeNameLen := 0
	maxIndexNameLen := 0
	maxTransportLen := 0
	maxIngestedLen := 8 // Start with "Ingested" header length

	// Get max node name and transport address length
	for _, nodeInfo := range nodesInfo.Nodes {
		if len(nodeInfo.Name) > maxNodeNameLen {
			maxNodeNameLen = len(nodeInfo.Name)
		}
		if len(nodeInfo.TransportAddress) > maxTransportLen {
			maxTransportLen = len(nodeInfo.TransportAddress)
		}
	}

	// Get max index name length and calculate max ingested length
	for _, index := range indicesStats {
		if (showHiddenIndices || !strings.HasPrefix(index.Index, ".")) && index.DocsCount != "0" {
			if len(index.Index) > maxIndexNameLen {
				maxIndexNameLen = len(index.Index)
			}

			docs := 0
			fmt.Sscanf(index.DocsCount, "%d", &docs)
			if activity := indexActivities[index.Index]; activity != nil {
				if activity.InitialDocsCount < docs {
					docChange := docs - activity.InitialDocsCount
					ingestedStr := fmt.Sprintf("+%s", formatNumber(docChange))
					if len(ingestedStr) > maxIngestedLen {
						maxIngestedLen = len(ingestedStr)
					}
				}
			}
		}
	}

	// Add padding
	maxNodeNameLen += 2
	maxIndexNameLen += 1 // Changed from 2 to 1 for minimal padding
	maxTransportLen += 2
	maxIngestedLen += 1 // Minimal padding for ingested column

	return maxNodeNameLen, maxIndexNameLen, maxTransportLen, maxIngestedLen
}

func getNodesPanelHeader(maxNodeNameLen, maxTransportLen int) string {
	return fmt.Sprintf("[::b]%-*s [#444444]│[#00ffff] %-13s [#444444]│[#00ffff] %*s [#444444]│[#00ffff] %-7s [#444444]│[#00ffff] %-9s [#444444]│[#00ffff] %-16s [#444444]│[#00ffff] %-16s [#444444]│[#00ffff] %-16s [#444444]│[#00ffff] %-6s [#444444]│[#00ffff] %-25s[white]\n",
		maxNodeNameLen,
		"Node Name",
		"Roles",
		maxTransportLen,
		"Transport Address",
		"Version",
		"CPU",
		"Memory",
		"Heap",
		"Disk",
		"Uptime",
		"OS")
}

func getIndicesPanelHeader() string {
	return fmt.Sprintf("   [::b][#00ffff]%-18s %6s %5s %5s %7s[white]\n",
		"Index",
		"Docs",
		"Size",
		"P/R",
		"Rate")
}

func isDataStream(name string, dataStreams DataStreamResponse) bool {
	for _, ds := range dataStreams.DataStreams {
		if ds.Name == name {
			return true
		}
	}
	return false
}

func getTotalSize(stats NodesStats) int64 {
	var total int64
	for _, node := range stats.Nodes {
		if len(node.FS.Data) > 0 {
			total += node.FS.Data[0].TotalInBytes - node.FS.Data[0].AvailableInBytes
		}
	}
	return total
}

func getTotalDiskSpace(stats NodesStats) int64 {
	var total int64
	for _, node := range stats.Nodes {
		if len(node.FS.Data) > 0 {
			total += node.FS.Data[0].TotalInBytes
		}
	}
	return total
}

func formatUptime(uptimeMillis int64) string {
	uptime := time.Duration(uptimeMillis) * time.Millisecond
	days := int(uptime.Hours() / 24)
	hours := int(uptime.Hours()) % 24
	minutes := int(uptime.Minutes()) % 60

	var result string
	if days > 0 {
		result = fmt.Sprintf("%d[#ff99cc]d[white]%d[#ff99cc]h[white]", days, hours)
	} else if hours > 0 {
		result = fmt.Sprintf("%d[#ff99cc]h[white]%d[#ff99cc]m[white]", hours, minutes)
	} else {
		result = fmt.Sprintf("%d[#ff99cc]m[white]", minutes)
	}

	// Calculate the actual display length by removing all color codes in one pass
	displayLen := len(strings.NewReplacer(
		"[#ff99cc]", "",
		"[white]", "",
	).Replace(result))

	// Add padding to make all uptime strings align (6 chars for display)
	padding := 6 - displayLen
	if padding > 0 {
		result = strings.TrimRight(result, " ") + strings.Repeat(" ", padding)
	}

	return result
}

func getTotalHTTPConnections(stats NodesStats) int64 {
	var total int64
	for _, node := range stats.Nodes {
		total += node.HTTP.CurrentOpen
	}
	return total
}

func updateRolesPanel(rolesPanel *tview.TextView, nodesInfo NodesInfo) {
	rolesPanel.Clear()
	fmt.Fprintf(rolesPanel, "[::b][#00ffff][[#ff5555]3[#00ffff]] Legend[::-]\n\n")

	// Add Node Roles title in cyan
	fmt.Fprintf(rolesPanel, "[::b][#00ffff]Node Roles[::-]\n")

	// Define role letters (same as in formatNodeRoles)
	roleMap := map[string]string{
		"master":                "M",
		"data":                  "D",
		"data_content":          "C",
		"data_hot":              "H",
		"data_warm":             "W",
		"data_cold":             "K",
		"data_frozen":           "F",
		"ingest":                "I",
		"ml":                    "L",
		"remote_cluster_client": "R",
		"transform":             "T",
		"voting_only":           "V",
		"coordinating_only":     "O",
	}

	// Create a map of active roles in the cluster
	activeRoles := make(map[string]bool)
	for _, node := range nodesInfo.Nodes {
		for _, role := range node.Roles {
			activeRoles[role] = true
		}
	}

	// Sort roles alphabetically by their letters
	var roles []string
	for role := range legendLabels {
		roles = append(roles, role)
	}
	sort.Slice(roles, func(i, j int) bool {
		return roleMap[roles[i]] < roleMap[roles[j]]
	})

	// Display each role with its color and description
	for _, role := range roles {
		color := roleColors[role]
		label := legendLabels[role]
		letter := roleMap[role]

		// If role is not active in cluster, use grey color for the label
		labelColor := "[white]"
		if !activeRoles[role] {
			labelColor = "[#444444]"
		}

		fmt.Fprintf(rolesPanel, "[%s]%s[white] %s%s\n", color, letter, labelColor, label)
	}

	// Add version status information
	fmt.Fprintf(rolesPanel, "\n[::b][#00ffff]Version Status[::-]\n")
	fmt.Fprintf(rolesPanel, "[green]⚫[white] Up to date\n")
	fmt.Fprintf(rolesPanel, "[yellow]⚫[white] Outdated\n")

	// Add index health status information
	fmt.Fprintf(rolesPanel, "\n[::b][#00ffff]Index Health[::-]\n")
	fmt.Fprintf(rolesPanel, "[green]⚫[white] All shards allocated\n")
	fmt.Fprintf(rolesPanel, "[#ffff00]⚫[white] Replica shards unallocated\n")
	fmt.Fprintf(rolesPanel, "[#ff5555]⚫[white] Primary shards unallocated\n")

	// Add index status indicators
	fmt.Fprintf(rolesPanel, "\n[::b][#00ffff]Index Status[::-]\n")
	fmt.Fprintf(rolesPanel, "[#5555ff]⚫[white] Active indexing\n")
	fmt.Fprintf(rolesPanel, "[#444444]⚪[white] No indexing\n")
	fmt.Fprintf(rolesPanel, "[#bd93f9]⚫[white] Data stream\n")

	// Add alert severity indicators
	fmt.Fprintf(rolesPanel, "\n[::b][#00ffff]Alert Severity[::-]\n")
	fmt.Fprintf(rolesPanel, "[#ff5555]●[white] Critical\n")
	fmt.Fprintf(rolesPanel, "[#ffb86c]●[white] High\n")
	fmt.Fprintf(rolesPanel, "[#f1fa8c]●[white] Medium\n")
	fmt.Fprintf(rolesPanel, "[#8be9fd]●[white] Low\n")
}

func formatResourceSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%4d B", bytes)
	}

	units := []string{"B", "K", "M", "G", "T", "P"}
	exp := 0
	val := float64(bytes)

	for val >= unit && exp < len(units)-1 {
		val /= unit
		exp++
	}

	return fmt.Sprintf("%3d%s", int(val), units[exp])
}

// NodeCardData holds the data needed to create a node card
type NodeCardData struct {
	Name             string
	TransportAddress string
	Version          string
	Roles            []string
	CPUPercent       int
	AvailableProcs   int
	MemUsed          int64
	MemTotal         int64
	HeapUsed         int64
	HeapMax          int64
	DiskUsed         int64
	DiskTotal        int64
	UptimeMillis     int64
	OSPrettyName     string
}

// createNodeCard creates a single node card with all node information
func createNodeCard(data NodeCardData, latestVer string) *tview.TextView {
	card := tview.NewTextView().SetDynamicColors(true)
	card.SetBorder(true).SetTitle(" " + data.Name + " ").SetTitleColor(tcell.GetColor("#ff5555"))
	card.SetBorderColor(tcell.GetColor("#ff5555"))

	// Calculate percentages
	memPercent := float64(0)
	if data.MemTotal > 0 {
		memPercent = float64(data.MemUsed) / float64(data.MemTotal) * 100
	}
	heapPercent := float64(0)
	if data.HeapMax > 0 {
		heapPercent = float64(data.HeapUsed) / float64(data.HeapMax) * 100
	}
	diskPercent := float64(0)
	if data.DiskTotal > 0 {
		diskPercent = float64(data.DiskUsed) / float64(data.DiskTotal) * 100
	}

	// Version color
	versionColor := "yellow"
	if compareVersions(data.Version, latestVer) {
		versionColor = "green"
	}

	// Build card content (7 lines)
	// Line 1: Roles, Version, Transport Address
	fmt.Fprintf(card, "%s [%s]%s[white] %s\n",
		formatNodeRolesCompact(data.Roles),
		versionColor, data.Version,
		data.TransportAddress)

	// Line 2: CPU
	fmt.Fprintf(card, "[#00ffff]CPU:[white]    [%s]%3d%%[white] (%d cores)\n",
		getPercentageColor(float64(data.CPUPercent)), data.CPUPercent, data.AvailableProcs)

	// Line 3: Memory
	fmt.Fprintf(card, "[#00ffff]Memory:[white] %4s / %4s [%s]%3d%%[white]\n",
		formatResourceSize(data.MemUsed),
		formatResourceSize(data.MemTotal),
		getPercentageColor(memPercent), int(memPercent))

	// Line 4: Heap
	fmt.Fprintf(card, "[#00ffff]Heap:[white]   %4s / %4s [%s]%3d%%[white]\n",
		formatResourceSize(data.HeapUsed),
		formatResourceSize(data.HeapMax),
		getPercentageColor(heapPercent), int(heapPercent))

	// Line 5: Disk
	fmt.Fprintf(card, "[#00ffff]Disk:[white]   %4s / %4s [%s]%3d%%[white]\n",
		formatResourceSize(data.DiskUsed),
		formatResourceSize(data.DiskTotal),
		getPercentageColor(diskPercent), int(diskPercent))

	// Line 6: Uptime
	fmt.Fprintf(card, "[#00ffff]Uptime:[white] %s\n",
		formatUptime(data.UptimeMillis))

	// Line 7: OS
	fmt.Fprintf(card, "[#00ffff]OS:[white]     [#bd93f9]%s[white]\n",
		data.OSPrettyName)

	return card
}

// updateNodesPanel updates the nodes panel with card-based layout
func updateNodesPanel(
	container *tview.Flex,
	nodesInfo NodesInfo,
	nodesStats NodesStats,
	latestVer string,
	app *tview.Application,
) {
	container.Clear()

	// Add title row
	titleRow := tview.NewFlex().SetDirection(tview.FlexColumn)
	title := tview.NewTextView().SetDynamicColors(true)
	fmt.Fprintf(title, "[::b][#00ffff][[#ff5555]2[#00ffff]] Nodes Information[::-]")
	titleRow.AddItem(title, 0, 1, false)
	container.AddItem(titleRow, 1, 0, false)

	// Sort nodes by name
	var nodeIDs []string
	for id := range nodesInfo.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Slice(nodeIDs, func(i, j int) bool {
		return nodesInfo.Nodes[nodeIDs[i]].Name < nodesInfo.Nodes[nodeIDs[j]].Name
	})

	// Calculate cards per row based on container width
	// Card dimensions: min width ~40 chars, height 9 lines (7 content + 2 border)
	const cardMinWidth = 40
	const cardHeight = 9

	_, _, width, _ := container.GetRect()
	if width <= 0 {
		width = 120 // default
	}

	cardsPerRow := width / cardMinWidth
	if cardsPerRow < 1 {
		cardsPerRow = 1
	}

	// Limit cards per row to total node count for better distribution
	nodeCount := len(nodeIDs)
	if cardsPerRow > nodeCount {
		cardsPerRow = nodeCount
	}

	// Create cards and arrange in rows
	var currentRow *tview.Flex
	cardCount := 0

	for _, id := range nodeIDs {
		nodeInfo := nodesInfo.Nodes[id]
		nodeStatsData, exists := nodesStats.Nodes[id]
		if !exists {
			continue
		}

		// Calculate disk usage
		diskTotal := int64(0)
		diskAvailable := int64(0)
		if len(nodeStatsData.FS.Data) > 0 {
			diskTotal = nodeStatsData.FS.Data[0].TotalInBytes
			diskAvailable = nodeStatsData.FS.Data[0].AvailableInBytes
		} else {
			diskTotal = nodeStatsData.FS.Total.TotalInBytes
			diskAvailable = nodeStatsData.FS.Total.AvailableInBytes
		}
		diskUsed := diskTotal - diskAvailable

		// Build card data
		cardData := NodeCardData{
			Name:             nodeInfo.Name,
			TransportAddress: nodeInfo.TransportAddress,
			Version:          nodeInfo.Version,
			Roles:            nodeInfo.Roles,
			CPUPercent:       nodeStatsData.OS.CPU.Percent,
			AvailableProcs:   nodeInfo.OS.AvailableProcessors,
			MemUsed:          nodeStatsData.OS.Memory.UsedInBytes,
			MemTotal:         nodeStatsData.OS.Memory.TotalInBytes,
			HeapUsed:         nodeStatsData.JVM.Memory.HeapUsedInBytes,
			HeapMax:          nodeStatsData.JVM.Memory.HeapMaxInBytes,
			DiskUsed:         diskUsed,
			DiskTotal:        diskTotal,
			UptimeMillis:     nodeStatsData.JVM.UptimeInMillis,
			OSPrettyName:     nodeInfo.OS.PrettyName,
		}

		// Start a new row if needed
		if cardCount%cardsPerRow == 0 {
			currentRow = tview.NewFlex().SetDirection(tview.FlexColumn)
			container.AddItem(currentRow, cardHeight, 0, false)
		}

		// Create and add card - uses proportional width (0, 1) so cards expand to fill row
		card := createNodeCard(cardData, latestVer)
		currentRow.AddItem(card, 0, 1, false)
		cardCount++
	}
}

// updateSecurityPanel renders the security alerts panel and returns true if height changed
func updateSecurityPanel(panel *tview.TextView, alerts *SecurityAlerts) bool {
	panel.Clear()

	// Get severity counts
	severityCounts := make(map[string]int)
	for _, bucket := range alerts.Aggregations.BySeverity.Buckets {
		severityCounts[bucket.Key] = bucket.DocCount
	}

	// Color mapping for severities
	severityColors := map[string]string{
		"critical": "#ff5555", // red
		"high":     "#ffb86c", // orange
		"medium":   "#f1fa8c", // yellow
		"low":      "#8be9fd", // cyan
	}

	// Build header with Open summary on same line
	headerLine := fmt.Sprintf("[::b][#00ffff][[#ff5555]6[#00ffff]] Security Alerts[::-] - [#00ffff]Open:[white] %d total   ", alerts.Hits.Total.Value)
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		count := severityCounts[sev]
		if count > 0 {
			color := severityColors[sev]
			headerLine += fmt.Sprintf("[%s]●[white] %s: %d  ", color, strings.Title(sev), count)
		}
	}
	fmt.Fprintf(panel, "%s\n\n", headerLine)

	// Collect host data
	type hostData struct {
		hostname       string
		os             string
		user           string
		severityCounts map[string]int
	}
	var hosts []hostData
	for i, bucket := range alerts.Aggregations.ByHost.Buckets {
		if i >= 5 {
			break
		}
		h := hostData{
			hostname:       bucket.Key,
			os:             "-",
			user:           "-",
			severityCounts: make(map[string]int),
		}
		// Get OS from host_info top_hits
		if len(bucket.HostInfo.Hits.Hits) > 0 {
			hit := bucket.HostInfo.Hits.Hits[0]
			if hit.Source.Host.OS.Type != "" {
				h.os = hit.Source.Host.OS.Type
			}
		}
		// Get user from by_user aggregation (shows most common user, or count if multiple)
		if len(bucket.ByUser.Buckets) > 0 {
			if len(bucket.ByUser.Buckets) == 1 {
				h.user = bucket.ByUser.Buckets[0].Key
			} else {
				// Multiple users - show top user with count indicator
				h.user = fmt.Sprintf("%s +%d", bucket.ByUser.Buckets[0].Key, len(bucket.ByUser.Buckets)-1)
			}
		}
		// Get severity counts for this host
		for _, sevBucket := range bucket.BySeverity.Buckets {
			h.severityCounts[sevBucket.Key] = sevBucket.DocCount
		}
		// Truncate
		if len(h.hostname) > 18 {
			h.hostname = h.hostname[:15] + "..."
		}
		if len(h.os) > 8 {
			h.os = h.os[:8]
		}
		if len(h.user) > 12 {
			h.user = h.user[:9] + "..."
		}
		hosts = append(hosts, h)
	}

	// Collect rule data
	type ruleData struct {
		name     string
		count    int
		severity string
	}
	var rules []ruleData
	for i, bucket := range alerts.Aggregations.ByRule.Buckets {
		if i >= 5 {
			break
		}
		r := ruleData{
			name:     bucket.Key,
			count:    bucket.DocCount,
			severity: "low", // default
		}
		// Get severity from rule_severity aggregation (first bucket = most common severity for this rule)
		if len(bucket.RuleSeverity.Buckets) > 0 {
			r.severity = bucket.RuleSeverity.Buckets[0].Key
		}
		if len(r.name) > 42 {
			r.name = r.name[:39] + "..."
		}
		rules = append(rules, r)
	}

	// Build left column lines (Top Hosts)
	var leftLines []string

	// Top Hosts header and column labels
	leftLines = append(leftLines, "[::b][#00ffff]Top Hosts[::-]")
	leftLines = append(leftLines, fmt.Sprintf("[#666666]  %-18s %-8s %-12s %s[white]", "Host", "OS", "User", "Alerts"))

	// Host data rows
	if len(hosts) == 0 {
		leftLines = append(leftLines, "  [#666666]No host data[white]")
	} else {
		for _, h := range hosts {
			// Build severity count string with colors (only show non-zero counts)
			var sevParts []string
			for _, sev := range []string{"critical", "high", "medium", "low"} {
				if count := h.severityCounts[sev]; count > 0 {
					color := severityColors[sev]
					sevParts = append(sevParts, fmt.Sprintf("[%s]%d[white]", color, count))
				}
			}
			sevStr := strings.Join(sevParts, "[#666666],[white] ")
			if sevStr == "" {
				sevStr = "[#666666]0[white]"
			}

			leftLines = append(leftLines, fmt.Sprintf("  %-18s [#bd93f9]%-8s[white] %-12s %s",
				h.hostname, h.os, h.user, sevStr))
		}
	}

	// Build right column lines (Top Rules)
	var rightLines []string

	// Top Rules header - starts at same row as Open
	rightLines = append(rightLines, "[::b][#00ffff]Top Rules[::-]")
	rightLines = append(rightLines, fmt.Sprintf("[#666666]  %-45s %5s[white]", "Rule Name", "Count"))

	// Rule data rows
	if len(rules) == 0 {
		rightLines = append(rightLines, "  [#666666]No rule data[white]")
	} else {
		for _, r := range rules {
			// Get color for severity
			sevColor := severityColors[r.severity]
			if sevColor == "" {
				sevColor = "#666666"
			}
			rightLines = append(rightLines, fmt.Sprintf("  [%s]●[white] %-42s %5d", sevColor, r.name, r.count))
		}
	}

	// Pad to same length
	for len(leftLines) < len(rightLines) {
		leftLines = append(leftLines, "")
	}
	for len(rightLines) < len(leftLines) {
		rightLines = append(rightLines, "")
	}

	// Print side by side
	const leftColWidth = 55
	for i := 0; i < len(leftLines); i++ {
		leftPart := leftLines[i]
		rightPart := rightLines[i]

		// Calculate visible length of leftPart for padding
		visibleLen := 0
		inTag := false
		for _, ch := range leftPart {
			if ch == '[' {
				inTag = true
			} else if ch == ']' && inTag {
				inTag = false
			} else if !inTag {
				visibleLen++
			}
		}

		// Pad left part to fixed width
		padding := leftColWidth - visibleLen
		if padding < 0 {
			padding = 0
		}

		fmt.Fprintf(panel, "%s%s     %s\n", leftPart, strings.Repeat(" ", padding), rightPart)
	}

	// Calculate new content height: title (2 lines) + body lines
	// Note: The last line doesn't need a trailing newline for display
	newHeight := 2 + len(leftLines)
	heightChanged := newHeight != securityContentHeight
	if heightChanged {
		securityContentHeight = newHeight
	}
	return heightChanged
}
