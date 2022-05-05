package nmap

import (
	"encoding/xml"
)

// nmap xml result => struct
// https://svn.nmap.org/nmap/docs/nmap.dtd.
type (
	PortProtocol string
	//see output.c:output_xml_scaninfo_records for scan types
	ScanType     string
	HostState    string
	HostnameType string

	// Service detection confidence level (portlist.h:struct serviceDeductions
	// Confidence is a number from 0 (least confident) to 10 (most
	// confident) expressing how accurate the service detection is
	// likely to be.
	ServiceConf int
	PortState   PortStatus
)

const (
	HostStateUp      HostState = "up"
	HostStateDown    HostState = "down"
	HostStateUnknown HostState = "unknown"
	HostStateSkipped HostState = "skipped"

	HostnameTypeUser HostnameType = "user"
	HostnameTypePTR  HostnameType = "PTR"

	ScanTypeSyn            ScanType = "syn"
	ScanTypeAck            ScanType = "ack"
	ScanTypeBounce         ScanType = "bounce"
	ScanTypeConnect        ScanType = "connect"
	ScanTypeNull           ScanType = "null"
	ScanTypeXmas           ScanType = "xmas"
	ScanTypeWindow         ScanType = "window"
	ScanTypeMaimon         ScanType = "maimon"
	ScanTypeFin            ScanType = "fin"
	ScanTypeUdp            ScanType = "udp"
	ScanTypeSctpInit       ScanType = "sctpinit"
	ScanTypeSctpCookieEcho ScanType = "sctpcookieecho"
	ScanTypeIpproto        ScanType = "ipproto"

	PortProtocolIp       PortProtocol = "ip"
	PortProtocolTcp      PortProtocol = "tcp"
	PortProtocolUdpProto PortProtocol = "udp"
	PortProtocolSctp     PortProtocol = "sctp"

	Confidence0 ServiceConf = iota
	Confidence1
	Confidence2
	Confidence3
	Confidence4
	Confidence5
	Confidence6
	Confidence7
	Confidence8
	Confidence9
	Confidence10
)

type ScanInfo struct {
	Type        ScanType     `json:"type" xml:"type,attr"`
	ScanFlags   string       `json:"scanflags" xml:"scanflags,attr"`
	Protocol    PortProtocol `json:"protocol" xml:"protocol,attr"`
	NumServices int          `json:"numservices" xml:"numservices,attr"`
	Services    string       `json:"services" xml:"services,attr"`
}
type Verbose struct {
	Level int `json:"level" xml:"level,attr"`
}
type Debugging Verbose
type Target struct {
	Specification string `json:"specification" xml:"specification,attr"`
	Status        string `json:"status" xml:"status,attr"`
	Reason        string `json:"reason" xml:"reason,attr"`
}
type Task struct {
	Task      string `json:"task" xml:"task,attr"`
	Time      int64  `json:"time" xml:"time,attr"`
	ExtraInfo string `json:"extrainfo" xml:"extrainfo,attr"`
}
type TaskBegin Task
type TaskEnd Task
type TaskProgress struct {
	Task      string  `json:"task" xml:"task,attr"`
	Time      int64   `json:"time" xml:"time,attr"`
	Percent   float32 `json:"percent" xml:"percent,attr"`
	Remaining int     `json:"remaining" xml:"remaining,attr"`
	Etc       int64   `json:"etc" xml:"etc,attr"`
}
type Status struct {
	State     HostState `json:"state" xml:"state,attr"`
	Reason    string    `json:"reason" xml:"reason,attr"`
	ReasonTTl int       `json:"reasonttl" xml:"reason_ttl,attr"`
}
type Smurf struct {
	Responses int `json:"responses" xml:"responses,attr"`
}
type ExtraReasons struct {
	Reason string       `json:"reason" xml:"reason,attr"`
	Count  string       `json:"count" xml:"count,attr"`
	Proto  PortProtocol `json:"proto" xml:"proto,attr"`
	Ports  string       `json:"ports" xml:"ports,attr"`
}
type ExtraPorts struct {
	State        PortState      `json:"state" xml:"state,attr"`
	Count        int            `json:"count" xml:"count,attr"`
	ExtraReasons []ExtraReasons `json:"extrareasons" xml:"extrareasons"`
}
type State struct {
	State     PortState `json:"state" xml:"state,attr"`
	Reason    string    `json:"reason" xml:"reason,attr"`
	ReasonTTL int       `json:"reasonttl" xml:"reason_ttl,attr"`
	ReasonIp  string    `json:"reasonip" xml:"reason_ip,attr"`
}
type Owner struct {
	Name string `json:"name" xml:"name,attr"`
}
type Service struct {
	Name string      `json:"name" xml:"name,attr"`
	Conf ServiceConf `json:"conf" xml:"conf,attr"`
	//method          (table|probed)
	Method     string   `json:"method" xml:"method,attr"`
	Version    string   `json:"version" xml:"version,attr"`
	Product    string   `json:"product" xml:"product,attr"`
	ExtraInfo  string   `json:"extrainfo" xml:"extrainfo,attr"`
	Tunnel     string   `json:"tunnel" xml:"tunnel,attr"`
	Proto      string   `json:"proto" xml:"proto,attr"`
	RPCNum     int      `json:"rpcnum" xml:"rpcnum,attr"`
	LowVer     int      `json:"lowver" xml:"lowver,attr"`
	HighVer    int      `json:"highver" xml:"highver,attr"`
	Hostname   string   `json:"hostname" xml:"hostname,attr"`
	OSType     string   `json:"ostype" xml:"ostype,attr"`
	DeviceType string   `json:"devicetype" xml:"devicetype,attr"`
	ServiceFp  string   `json:"servicefp" xml:"servicefp,attr"`
	CPE        []string `json:"cpe" xml:"cpe"`
}
type Elem struct {
	Key  string `json:"key,omitempty" xml:"key,attr,omitempty"`
	Text string `json:"text" xml:",innerxml"`
}
type Table struct {
	Key   string `json:"key,omitempty" xml:"key,attr,omitempty"`
	Table []Elem `json:"table,omitempty" xml:"table,omitempty"`
	Elem  []Elem `json:"elem,omitempty" xml:"elem,omitempty"`
}
type Script struct {
	Id     string `json:"id" xml:"id,attr"`
	Output string `json:"output" xml:"output,attr"`
	//Text   string `json:"text" xml:"text,attr"`
	Table []Table `json:"table,omitempty" xml:"table,omitempty"`
	Elem  []Elem  `json:"elem,omitempty" xml:"elem,omitempty"`
}
type Port struct {
	Protocol PortProtocol `json:"protocol" xml:"protocol,attr"`
	PortId   uint16       `json:"portid" xml:"portid,attr"`
	State    State        `json:"state" xml:"state"`
	Owner    Owner        `json:"owner" xml:"owner"`
	Service  Service      `json:"service" xml:"service"`
	Script   []Script     `json:"script" xml:"script"`
}
type Ports struct {
	ExtraPorts []ExtraPorts `json:"extraports" xml:"extraports"`
	Port       []Port       `json:"port" xml:"port"`
}
type PortUsed struct {
	State  PortState    `json:"state" xml:"state,attr"`
	Proto  PortProtocol `json:"proto" xml:"proto,attr"`
	PortId uint16       `json:"portid" xml:"portid,attr"`
}
type OSClass struct {
	Vendor   string   `json:"vendor" xml:"vendor,attr"`
	OSGen    string   `json:"osgen" xml:"osgen,attr"`
	Type     string   `json:"type" xml:"type,attr"`
	Accuracy string   `json:"accuracy" xml:"accuracy,attr"`
	OSFamily string   `json:"osfamily" xml:"osfamily,attr"`
	CPE      []string `json:"cpe" xml:"cpe"`
}
type OSMatch struct {
	Name     string    `json:"name" xml:"name,attr"`
	Accuracy int       `json:"accuracy" xml:"accuracy,attr"`
	Line     int       `json:"line" xml:"line,attr"`
	OSClass  []OSClass `json:"osclass" xml:"osclass"`
}
type OSFingerPrint struct {
	Fingerprint string `json:"fingerprint" xml:"fingerprint,attr"`
}
type OS struct {
	PortUsed      []PortUsed      `json:"portused" xml:"portused"`
	OSMatch       []OSMatch       `json:"osmatch" xml:"osmatch"`
	OSFingerPrint []OSFingerPrint `json:"osfingerprint" xml:"osfingerprint"`
}
type Distance struct {
	Value int `json:"value" xml:"value,attr"`
}
type Uptime struct {
	Seconds  int    `json:"seconds" xml:"seconds,attr"`
	LastBoot string `json:"lastboot" xml:"lastboot,attr"`
}
type TCPSequence struct {
	Index      int    `json:"index"  xml:"index,attr"`
	Difficulty string `json:"difficulty" xml:"difficulty,attr"`
	Values     string `json:"values" xml:"values,attr"`
}
type IpIdSequence struct {
	Values string `json:"values" xml:"values,attr"`
}
type TCPTSSequence struct {
	Values string `json:"values" xml:"values,attr"`
}
type Hop struct {
	TTL    int    `json:"ttl" xml:"ttl,attr"`
	RTT    string `json:"rtt" xml:"rtt,attr"`
	Ipaddr string `json:"ipaddr" xml:"ipaddr,attr"`
	Host   string `json:"host" xml:"host,attr"`
}
type Trace struct {
	Proto string `json:"proto" xml:"proto,attr"`
	Port  string `json:"port" xml:"port,attr"`
	Hop   []Hop  `json:"hop" xml:"hop"`
}
type Times struct {
	SRTT   string `json:"srtt" xml:"srtt,attr"`
	RTTVar string `json:"rttvar" xml:"rttvar,attr"`
	To     string `json:"to" xml:"to,attr"`
}
type Host struct {
	StartTime int64      `json:"starttime" xml:"starttime,attr,omitempty"`
	EndTime   int64      `json:"endtime" xml:"endtime,attr,omitempty"`
	TimedOut  bool       `json:"timedout" xml:"timedout,attr"`
	Comment   string     `json:"comment" xml:"comment,attr"`
	Status    Status     `json:"status" xml:"status"`
	Address   []Address  `json:"address" xml:"address"`
	Hostnames []Hostname `json:"hostnames" xml:"hostnames>hostname"`
	//this element is written by output.c:write_host_status()
	Smurf         []Smurf         `json:"smurf" xml:"smurf"`
	Ports         []Ports         `json:"ports" xml:"ports"`
	OS            []OS            `json:"os" xml:"os"`
	Distance      []Distance      `json:"distance" xml:"distance"`
	Uptime        []Uptime        `json:"uptime" xml:"uptime"`
	TCPSequence   []TCPSequence   `json:"tcpsequence" xml:"tcpsequence"`
	IpIdSequence  []IpIdSequence  `json:"ipidsequence" xml:"ipidsequence"`
	TCPTSSequence []TCPTSSequence `json:"tcptssequence" xml:"tcptssequence"`
	HostScript    []Script        `json:"hostscript" xml:"hostscript"`
	Trace         []Trace         `json:"trace" xml:"trace"`
	Times         Times           `json:"times" xml:"times"`
}
type Address struct {
	Addr     string `json:"addr" xml:"addr,attr"`
	AddrType string `json:"addrtype" xml:"addrtype,attr"`
	Vendor   string `json:"vendor" xml:"vendor,attr"`
}
type Hostname struct {
	Name string       `json:"name" xml:"name,attr"`
	Type HostnameType `json:"type" xml:"type,attr"`
}
type HostHint struct {
	Status    Status     `json:"status" xml:"status"`
	Address   Address    `json:"address" xml:"address"`
	Hostnames []Hostname `json:"hostnames" xml:"hostnames>hostname"`
}

type Output struct {
	Type string `json:"type" xml:"type,attr"`
	Text string `json:"text" xml:"text,attr"`
}
type Hosts struct {
	Up    int `json:"up" xml:"up,attr"`
	Down  int `json:"down" xml:"down,attr"`
	Total int `json:"total" xml:"total,attr"`
}

type Finished struct {
	Time     int64   `json:"time" xml:"time,attr"`
	TimeStr  string  `json:"timestr" xml:"timestr,attr"`
	Elapsed  float32 `json:"elapsed" xml:"elapsed,attr"`
	Summary  string  `json:"summary" xml:"summary,attr"`
	Exit     string  `json:"exit" xml:"exit,attr"`
	ErrorMsg string  `json:"errormsg" xml:"errormsg,attr"`
}
type RunStats struct {
	Finished Finished `json:"finished" xml:"finished"`
	Hosts    Hosts    `json:"hosts" xml:"hosts"`
}
type NmapXMLResult struct {
	XMLName xml.Name `json:"nmaprun" xml:"nmaprun"`
	//nmap默认为nmap
	Scanner string `json:"scanner" xml:"scanner,attr"`
	//参数
	Args string `json:"args" xml:"args,attr"`
	//开始时间
	Start int64 `json:"start" xml:"start,attr"`
	//开始时间
	StartStr string `json:"startstr" xml:"startstr,attr"`
	//版本
	Version          string         `json:"version" xml:"version,attr"`
	ProfileName      string         `json:"profilename" xml:"profile_name,attr"`
	XMLOutputVersion string         `json:"xmloutputversion" xml:"xmloutputversion,attr"`
	ScanInfo         []ScanInfo     `json:"scaninfo" xml:"scaninfo"`
	Verbose          Verbose        `json:"verbose" xml:"verbose"`
	Debugging        Debugging      `json:"debugging" xml:"debugging"`
	Target           []Target       `json:"target" xml:"target"`
	TaskBegin        []TaskBegin    `json:"taskbegin" xml:"taskbegin"`
	TaskProgress     []TaskProgress `json:"taskprogress" xml:"taskprogress"`
	TaskEnd          []TaskEnd      `json:"taskend" xml:"taskend"`
	//各个host的ip/hostname，端口信息
	Host []Host `json:"host" xml:"host"`
	//扫描目标的状态、ip、hostname
	HostHint   []HostHint `json:"hosthint" xml:"hosthint"`
	Prescript  []Script   `json:"prescript" xml:"prescript>script"`
	Postscript []Script   `json:"postscript" xml:"postscript>scriptd"`
	Output     Output     `json:"output" xml:"output"`
	RunStats   RunStats   `json:"runstats" xml:"runstats"`
}
