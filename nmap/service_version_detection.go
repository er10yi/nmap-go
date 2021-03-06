package nmap

import (
	"strconv"
)

/*
* REMINDER:
https://nmap.org/book/man-version-detection.html
Service and Version Detection
Point Nmap at a remote machine and it might tell you that ports 25/tcp, 80/tcp, and 53/udp are open. Using its nmap-services database of about 2,200 well-known services, Nmap would report that those ports probably correspond to a mail server (SMTP), web server (HTTP), and name server (DNS) respectively. This lookup is usually accurate—the vast majority of daemons listening on TCP port 25 are, in fact, mail servers. However, you should not bet your security on this! People can and do run services on strange ports.
Even if Nmap is right, and the hypothetical server above is running SMTP, HTTP, and DNS servers, that is not a lot of information. When doing vulnerability assessments (or even simple network inventories) of your companies or clients, you really want to know which mail and DNS servers and versions are running. Having an accurate version number helps dramatically in determining which exploits a server is vulnerable to. Version detection helps you obtain this information.
After TCP and/or UDP ports are discovered using one of the other scan methods, version detection interrogates those ports to determine more about what is actually running. The nmap-service-probes database contains probes for querying various services and match expressions to recognize and parse responses. Nmap tries to determine the service protocol (e.g. FTP, SSH, Telnet, HTTP), the application name (e.g. ISC BIND, Apache httpd, Solaris telnetd), the version number, hostname, device type (e.g. printer, router), the OS family (e.g. Windows, Linux). When possible, Nmap also gets the Common Platform Enumeration (CPE) representation of this information. Sometimes miscellaneous details like whether an X server is open to connections, the SSH protocol version, or the KaZaA user name, are available. Of course, most services don't provide all of this information. If Nmap was compiled with OpenSSL support, it will connect to SSL servers to deduce the service listening behind that encryption layer. Some UDP ports are left in the open|filtered state after a UDP port scan is unable to determine whether the port is open or filtered. Version detection will try to elicit a response from these ports (just as it does with open ports), and change the state to open if it succeeds. open|filtered TCP ports are treated the same way. Note that the Nmap -A nmap enables version detection among other things. Version detection is described in detail in Chapter 7, Service and Application Version Detection.
When RPC services are discovered, the Nmap RPC grinder is automatically used to determine the RPC program and version numbers. It takes all the TCP/UDP ports detected as RPC and floods them with SunRPC program NULL commands in an attempt to determine whether they are RPC ports, and if so, what program and version number they serve up. Thus you can effectively obtain the same info as rpcinfo -p even if the target's portmapper is behind a firewall (or protected by TCP wrappers). Decoys do not currently work with RPC scan.
When Nmap receives responses from a service but cannot match them to its database, it prints out a special fingerprint and a URL for you to submit it to if you know for sure what is running on the port. Please take a couple minutes to make the submission so that your find can benefit everyone. Thanks to these submissions, Nmap has about 6,500 pattern matches for more than 650 protocols such as SMTP, FTP, HTTP, etc.
Version detection is enabled and controlled with the following options:
* 2022-04-14 21:00
*
* */

//AddsV -sV: Probe open ports to determine service/version info
//
// -sV (Version detection)
//
// Enables version detection, as discussed above. Alternatively, you can use -A, which enables version detection among other things.
//
// -sR is an alias for -sV. Prior to March 2011, it was used to active the RPC grinder separately from version detection, but now these options are always combined.
func (receiver *nmap) AddsV() *nmap {
	return AddArgs(receiver, "-sV")
}

//Addallports --allports (Don't exclude any ports from version detection)
//
//By default, Nmap version detection skips TCP port 9100 because some printers simply print anything sent to that port, leading to dozens of pages of HTTP GET requests, binary SSL session requests, etc. This behavior can be changed by modifying or removing the Exclude directive in nmap-service-probes, or you can specify --allports to scan all ports regardless of any Exclude directive.
func (receiver *nmap) Addallports() *nmap {
	return AddArgs(receiver, "--allports")
}

//Addversionintensity --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
//
// --version-intensity <intensity> (Set version scan intensity)
//
//When performing a version scan (-sV), Nmap sends a series of probes, each of which is assigned a rarity value between one and nine. The lower-numbered probes are effective against a wide variety of common services, while the higher-numbered ones are rarely useful. The intensity level specifies which probes should be applied. The higher the number, the more likely it is the service will be correctly identified. However, high intensity scans take longer. The intensity must be between 0 and 9. The default is 7. When a probe is registered to the target port via the nmap-service-probes ports directive, that probe is tried regardless of intensity level. This ensures that the DNS probes will always be attempted against any open port 53, the SSL probe will be done against 443, etc.
func (receiver *nmap) Addversionintensity(level int) *nmap {
	if level < 0 || level > 9 {
		panic("level scope: 1[0-9]")
	}
	return AddArgs(receiver, "--version-intensity", strconv.Itoa(level))
}

//Addversionlight --version-light: Limit to most likely probes (intensity 2)
//
// --version-light (Enable light mode)
//
//This is a convenience alias for --version-intensity 2. This light mode makes version scanning much faster, but it is slightly less likely to identify services.
func (receiver *nmap) Addversionlight() *nmap {
	return AddArgs(receiver, "--version-light")
}

//Addversionall --version-all: Try every single probe (intensity 9)
//
//--version-all (Try every single probe)
//
//An alias for --version-intensity 9, ensuring that every single probe is attempted against each port.
func (receiver *nmap) Addversionall() *nmap {
	return AddArgs(receiver, "--version-all")
}

//Addversiontrace --version-trace: Show detailed version scan activity (for debugging)
//
//--version-trace (Trace version scan activity)
//
//This causes Nmap to print out extensive debugging info about what version scanning is doing. It is a subset of what you get with --packet-trace.
func (receiver *nmap) Addversiontrace() *nmap {
	return AddArgs(receiver, "--version-trace")
}
