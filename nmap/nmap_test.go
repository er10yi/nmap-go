package nmap

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestNewNmap(t *testing.T) {
	path := os.Getenv("PATH")
	_ = os.Setenv("PATH", "")
	n := NewNmap()
	result := n.Run()
	if result != nil {
		t.Errorf("Expected nmap not installed, but got nmap is not null")
	}

	_ = os.Setenv("PATH", path)

}

//test case
func TestAddArgs(t *testing.T) {
	cases := []struct {
		methodName     string
		nmap           *nmap
		args, Expected []string
	}{
		//Target Specification
		//https://nmap.org/book/man-target-specification.html
		{"AddTargets", NewNmap(), []string{"127.0.0.1 nmap.org"}, []string{"127.0.0.1 nmap.org"}},
		{"AddiL", NewNmap(), []string{"target.txt"}, []string{"-iL", "target.txt"}},
		{"AddiR", NewNmap(), []string{"3"}, []string{"-iR", "3"}},
		{"Addexclude", NewNmap(), []string{"192.168.1.0/24"}, []string{"--exclude", "192.168.1.0/24"}},
		{"Addexcludefile", NewNmap(), []string{"192.168.1.0/24"}, []string{"--excludefile", "192.168.1.0/24"}},
		{"Addresolveall", NewNmap(), nil, []string{"--resolve-all"}},
		{"Addunique", NewNmap(), nil, []string{"--unique"}},

		//Host Discovery
		//https://nmap.org/book/man-host-discovery.html
		{"AddsL", NewNmap(), nil, []string{"-sL"}},
		{"Addsn", NewNmap(), nil, []string{"-sn"}},
		{"AddPn", NewNmap(), nil, []string{"-Pn"}},
		{"AddPS", NewNmap(), []string{"80,8081"}, []string{"-PS", "80,8081"}},
		{"AddPA", NewNmap(), []string{"80"}, []string{"-PA", "80"}},
		{"AddPU", NewNmap(), []string{"80"}, []string{"-PU", "80"}},
		{"AddPY", NewNmap(), []string{"80"}, []string{"-PY", "80"}},
		{"AddPE", NewNmap(), nil, []string{"-PE"}},
		{"AddPP", NewNmap(), nil, []string{"-PP"}},
		{"AddPM", NewNmap(), nil, []string{"-PM"}},
		{"AddPO", NewNmap(), []string{"80"}, []string{"-PO", "80"}},
		{"Adddisablearpping", NewNmap(), nil, []string{"--disable-arp-ping"}},
		{"Addtraceroute", NewNmap(), nil, []string{"--traceroute"}},
		{"Addn", NewNmap(), nil, []string{"-n"}},
		{"AddR", NewNmap(), nil, []string{"-R"}},
		{"Adddnsservers", NewNmap(), []string{"8.8.8.8,114.114.114.114"}, []string{"--dns-servers", "8.8.8.8,114.114.114.114"}},
		{"Addsystemdns", NewNmap(), nil, []string{"--system-dns"}},

		//Port Scanning Techniques
		//https://nmap.org/book/man-port-scanning-techniques.html
		{"AddsS", NewNmap(), nil, []string{"-sS"}},
		{"AddsT", NewNmap(), nil, []string{"-sT"}},
		{"AddsA", NewNmap(), nil, []string{"-sA"}},
		{"AddsW", NewNmap(), nil, []string{"-sW"}},
		{"AddsM", NewNmap(), nil, []string{"-sM"}},
		{"AddsU", NewNmap(), nil, []string{"-sU"}},
		{"AddsN", NewNmap(), nil, []string{"-sN"}},
		{"AddsF", NewNmap(), nil, []string{"-sF"}},
		{"AddsX", NewNmap(), nil, []string{"-sX"}},
		{"Addscanflags", NewNmap(), []string{"URGACKPSHRSTSYNFIN"}, []string{"--scanflags", "URGACKPSHRSTSYNFIN"}},
		{"AddsI", NewNmap(), []string{"127.0.0.2:88"}, []string{"-sI", "127.0.0.2:88"}},
		{"AddsY", NewNmap(), nil, []string{"-sY"}},
		{"AddsZ", NewNmap(), nil, []string{"-sZ"}},
		{"AddsO", NewNmap(), nil, []string{"-sO"}},
		{"Addb", NewNmap(), []string{"127.0.0.2"}, []string{"-b", "127.0.0.2"}},

		//Port Specification and Scan Order
		//https://nmap.org/book/man-port-specification.html
		{"Addp", NewNmap(), []string{"80,443"}, []string{"-p", "80,443"}},
		{"Addexcludeports", NewNmap(), []string{"80"}, []string{"--exclude-ports", "80"}},
		{"AddF", NewNmap(), nil, []string{"-F"}},
		{"Addr", NewNmap(), nil, []string{"-r"}},
		{"Addtopports", NewNmap(), []string{"10"}, []string{"--top-ports", "10"}},
		{"Addportratio", NewNmap(), []string{"0.3"}, []string{"--port-ratio", "0.3"}},

		//Service and Version Detection
		//https://nmap.org/book/man-version-detection.html
		{"AddsV", NewNmap(), nil, []string{"-sV"}},
		{"Addallports", NewNmap(), nil, []string{"--allports"}},
		{"Addversionintensity", NewNmap(), []string{"8"}, []string{"--version-intensity", "8"}},
		{"Addversionlight", NewNmap(), nil, []string{"--version-light"}},
		{"Addversionall", NewNmap(), nil, []string{"--version-all"}},
		{"Addversiontrace", NewNmap(), nil, []string{"--version-trace"}},

		//OS Detection
		//https://nmap.org/book/man-os-detection.html
		{"AddO", NewNmap(), nil, []string{"-O"}},
		{"Addosscanlimit", NewNmap(), nil, []string{"--osscan-limit"}},
		{"Addosscanguess", NewNmap(), nil, []string{"--osscan-guess"}},
		{"Addmaxostries", NewNmap(), []string{"3"}, []string{"--max-os-tries", "3"}},

		//Nmap Scripting Engine (NSE)
		//https://nmap.org/book/man-nse.html
		{"AddsC", NewNmap(), nil, []string{"-sC"}},
		{"Addscript", NewNmap(), []string{"redis-info,redis-brute"}, []string{"--script", "redis-info,redis-brute"}},
		{"Addscriptargs", NewNmap(), []string{"user=foo,pass="}, []string{"--script-args", "user=foo,pass="}},
		{"Addscriptargsfile", NewNmap(), []string{"payload.txt"}, []string{"--script-args-file", "payload.txt"}},
		{"Addscripttrace", NewNmap(), nil, []string{"--script-trace"}},
		{"Addscriptupdatedb", NewNmap(), nil, []string{"--script-updatedb"}},
		{"Addscripthelp", NewNmap(), []string{"redis-info"}, []string{"--script-help", "redis-info"}},

		//Timing and Performance
		//https://nmap.org/book/man-performance.html
		{"Addmaxhostgroup", NewNmap(), []string{"30"}, []string{"--max-hostgroup", "30"}},
		{"Addminhostgroup", NewNmap(), []string{"30"}, []string{"--min-hostgroup", "30"}},
		{"Addminparallelism", NewNmap(), []string{"5"}, []string{"--min-parallelism", "5"}},
		{"Addmaxparallelism", NewNmap(), []string{"5"}, []string{"--max-parallelism", "5"}},
		{"Addminrtttimeout", NewNmap(), []string{"10"}, []string{"--min-rtt-timeout", "10"}},
		{"Addmaxrtttimeout", NewNmap(), []string{"10"}, []string{"--max-rtt-timeout", "10"}},
		{"Addinitialrtttimeout", NewNmap(), []string{"10"}, []string{"--initial-rtt-timeout", "10"}},
		{"Addmaxretries", NewNmap(), []string{"5"}, []string{"--max-retries", "5"}},
		{"Addhosttimeout", NewNmap(), []string{"5"}, []string{"--host-timeout", "5"}},
		{"Addscripttimeout", NewNmap(), []string{"5"}, []string{"--script-timeout", "5"}},
		{"Addscandelay", NewNmap(), []string{"5"}, []string{"--scan-delay", "5"}},
		{"Addmaxscandelay", NewNmap(), []string{"5"}, []string{"--max-scan-delay", "5"}},
		{"Addminrate", NewNmap(), []string{"5"}, []string{"--min-rate", "5"}},
		{"Addmaxrate", NewNmap(), []string{"5"}, []string{"--max-rate", "5"}},
		{"Adddefeatrstratelimit", NewNmap(), nil, []string{"--defeat-rst-ratelimit"}},
		{"Adddefeaticmpratelimit", NewNmap(), nil, []string{"--defeat-icmp-ratelimit"}},
		{"Addnsockengine", NewNmap(), nil, []string{"--nsock-engine"}},
		{"AddT", NewNmap(), []string{"0"}, []string{"-T", "0"}},

		//Firewall/IDS Evasion and Spoofing
		//https://nmap.org/book/man-bypass-firewalls-ids.html
		{"Addf", NewNmap(), nil, []string{"-f"}},
		{"Addmtu", NewNmap(), nil, []string{"--mtu"}},
		{"AddD", NewNmap(), []string{"decoy1"}, []string{"-D", "decoy1"}},
		{"AddS", NewNmap(), []string{"127.0.0.2"}, []string{"-S", "127.0.0.2"}},
		{"Adde", NewNmap(), []string{"80"}, []string{"-e", "80"}},
		{"Addg", NewNmap(), []string{"80"}, []string{"-g", "80"}},
		{"Addsourceport", NewNmap(), []string{"80"}, []string{"--source-port", "80"}},
		{"Adddata", NewNmap(), []string{"data"}, []string{"--data", "data"}},
		{"Adddatastring", NewNmap(), []string{"data"}, []string{"--data-string", "data"}},
		{"Adddatalength", NewNmap(), []string{"2"}, []string{"--data-length", "2"}},
		{"Addipoptions", NewNmap(), []string{"options"}, []string{"--ip-options", "options"}},
		{"Addttl", NewNmap(), []string{"64"}, []string{"--ttl", "64"}},
		{"Addrandomizehosts", NewNmap(), nil, []string{"--randomize-hosts"}},
		{"Addspoofmac", NewNmap(), []string{"mac address"}, []string{"--spoof-mac", "mac address"}},
		{"Addproxies", NewNmap(), []string{"http://127.0.0.2:82,http://127.0.0.3:83"}, []string{"--proxies", "http://127.0.0.2:82,http://127.0.0.3:83"}},
		{"Addbadsum", NewNmap(), nil, []string{"--badsum"}},
		{"Addadler32", NewNmap(), nil, []string{"--adler32"}},

		//Output
		//https://nmap.org/book/man-output.html
		{"AddoN", NewNmap(), []string{"resultFile"}, []string{"-oN", "resultFile"}},
		{"AddoX", NewNmap(), []string{"resultFile"}, []string{"-oX", "resultFile"}},
		{"AddoS", NewNmap(), []string{"resultFile"}, []string{"-oS", "resultFile"}},
		{"AddoG", NewNmap(), []string{"resultFile"}, []string{"-oG", "resultFile"}},
		{"AddoA", NewNmap(), []string{"resultFile"}, []string{"-oA", "resultFile"}},
		{"Addv", NewNmap(), []string{"9"}, []string{"-vvvvvvvvv"}},
		{"Addd", NewNmap(), []string{"9"}, []string{"-ddddddddd"}},

		{"Addreason", NewNmap(), nil, []string{"--reason"}},
		{"Addstatsevery", NewNmap(), []string{"10s"}, []string{"--stats-every", "10s"}},
		{"Addpackettrace", NewNmap(), nil, []string{"--packet-trace"}},
		{"Addopen", NewNmap(), nil, []string{"--open"}},
		//TODO
		//{"Addiflist", NewNmap(), nil, []string{"--iflist"}},
		{"Addappendoutput", NewNmap(), nil, []string{"--append-output"}},
		{"Addresume", NewNmap(), []string{"resumeFilename"}, []string{"--resume", "resumeFilename"}},
		{"Addnoninteractive", NewNmap(), nil, []string{"--noninteractive"}},
		{"Addstylesheet", NewNmap(), []string{"pathOrUrl"}, []string{"--stylesheet", "pathOrUrl"}},
		{"Addwebxml", NewNmap(), nil, []string{"--webxml"}},
		{"Addnostylesheet", NewNmap(), nil, []string{"--no-stylesheet"}},

		////Miscellaneous Options
		//https://nmap.org/book/man-misc-options.html
		{"Add6", NewNmap(), nil, []string{"-6"}},
		{"AddA", NewNmap(), nil, []string{"-A"}},
		{"Adddatadir", NewNmap(), []string{"dirname"}, []string{"--datadir", "dirname"}},
		{"Addservicedb", NewNmap(), []string{"nmap-service"}, []string{"--servicedb", "nmap-service"}},
		{"Addversiondb", NewNmap(), []string{"nmap-version"}, []string{"--versiondb", "nmap-version"}},
		{"Addsendeth", NewNmap(), nil, []string{"--send-eth"}},
		{"Addsendip", NewNmap(), nil, []string{"--send-ip"}},
		{"Addprivileged", NewNmap(), nil, []string{"--privileged"}},
		{"Addunprivileged", NewNmap(), nil, []string{"--unprivileged"}},
		{"Addreleasememory", NewNmap(), nil, []string{"--release-memory"}},
		{"AddV", NewNmap(), nil, []string{"-V"}},
		{"Addh", NewNmap(), nil, []string{"-h"}},
		{"Addreleasememory", NewNmap(), nil, []string{"--release-memory"}},
	}

	for _, c := range cases {
		t.Run(c.methodName, func(t *testing.T) {
			n1 := reflect.ValueOf(c.nmap)
			addFunc := n1.MethodByName(c.methodName)
			if !addFunc.IsValid() {
				t.Errorf("%s is not method of nmap", c.methodName)
				return
			}
			parameterCount := addFunc.Type().NumIn()
			var res []reflect.Value
			// none parameter
			if parameterCount == 0 {
				res = addFunc.Call([]reflect.Value{})
			}
			if parameterCount == 1 {
				var para reflect.Value
				vType := addFunc.Type().In(0).Kind()
				switch vType {
				case reflect.Uint8:
					v, err := strconv.ParseUint(c.args[0], 10, 8)
					if err != nil {
						t.Errorf("parameter %s is not int", c.args)
					}
					para = reflect.ValueOf(uint8(v))
				case reflect.Uint16:
					v, err := strconv.ParseUint(c.args[0], 10, 16)
					if err != nil {
						t.Errorf("parameter %s is not int", c.args)
					}
					para = reflect.ValueOf(uint16(v))
				case reflect.Int:
					v, err := strconv.Atoi(c.args[0])
					if err != nil {
						t.Errorf("parameter %s is not int", c.args)
					}
					para = reflect.ValueOf(v)
				case reflect.Float32:
					v, err := strconv.ParseFloat(c.args[0], 32)
					if err != nil {
						t.Errorf("parameter %s is not float32", c.args)
					}
					para = reflect.ValueOf(float32(v))
				default:
					para = reflect.ValueOf(strings.Join(c.args, ""))
				}
				res = addFunc.Call([]reflect.Value{para})
			}
			n2 := res[0].Interface().(*nmap)
			equal := reflect.DeepEqual(n2.Args, c.Expected)
			if !equal {
				t.Errorf("expected %s, but got return %s", c.Expected, n2.Args)
			}
		})
	}
}
