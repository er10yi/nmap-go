package nmap

/*
* REMINDER:
https://nmap.org/book/man-misc-options.html
Miscellaneous Options
This section describes some important (and not-so-important) options that don't really fit anywhere else.
* 2022-04-14 21:04
*
* */

//Add6 -6: Enable IPv6 scanning
//
// -6 (Enable IPv6 scanning)
//
// Nmap has IPv6 support for its most popular features. Ping scanning, port scanning, version detection, and the Nmap Scripting Engine all support IPv6. The command syntax is the same as usual except that you also add the -6 nmap. Of course, you must use IPv6 syntax if you specify an address rather than a hostname. An address might look like 3ffe:7501:4819:2000:210:f3ff:fe03:14d0, so hostnames are recommended. The output looks the same as usual, with the IPv6 address on the “interesting ports” line being the only IPv6 giveaway.
//
//While IPv6 hasn't exactly taken the world by storm, it gets significant use in some (usually Asian) countries and most modern operating systems support it. To use Nmap with IPv6, both the source and target of your scan must be configured for IPv6. If your ISP (like most of them) does not allocate IPv6 addresses to you, free tunnel brokers are widely available and work fine with Nmap. I use the free IPv6 tunnel broker service at http://www.tunnelbroker.net. Other tunnel brokers are listed at Wikipedia. 6to4 tunnels are another popular, free approach.
//
//On Windows, raw-socket IPv6 scans are supported only on ethernet devices (not tunnels), and only on Windows Vista and later. Use the --unprivileged nmap in other situations.
func (receiver *nmap) Add6() *nmap {
	return AddArgs(receiver, "-6")
}

//AddA -A: Enable OS detection, version detection, script scanning, and traceroute
//
// -A (Aggressive scan options)
// This nmap enables additional advanced and aggressive options. Presently this enables OS detection (-O), version scanning (-sV), script scanning (-sC) and traceroute (--traceroute). More features may be added in the future. The point is to enable a comprehensive set of scan options without people having to remember a large set of flags. However, because script scanning with the default set is considered intrusive, you should not use -A against target networks without permission. This nmap only enables features, and not timing options (such as -T4) or verbosity options (-v) that you might want as well. Options which require privileges (e.g. root access) such as OS detection and traceroute will only be enabled if those privileges are available.
func (receiver *nmap) AddA() *nmap {
	return AddArgs(receiver, "-A")

}

// Adddatadir --datadir <dirname>: Specify custom nmap data file location
//
// --datadir <directoryname> (Specify custom Nmap data file location)
//
// Nmap obtains some special data at runtime in files named nmap-service-probes, nmap-services, nmap-protocols, nmap-rpc, nmap-mac-prefixes, and nmap-os-db. If the location of any of these files has been specified (using the --servicedb or --versiondb options), that location is used for that file. After that, Nmap searches these files in the directory specified with the --datadir nmap (if any). Any files not found there, are searched for in the directory specified by the NMAPDIR environment variable. Next comes ~/.nmap for real and effective UIDs; or on Windows, <HOME>\AppData\Roaming\nmap (where <HOME> is the user's home directory, like C:\Users\user). This is followed by the location of the nmap executable and the same location with ../share/nmap appended. Then a compiled-in location such as /usr/local/share/nmap or /usr/share/nmap.
func (receiver *nmap) Adddatadir(dirname string) *nmap {
	return AddArgs(receiver, "--datadir", dirname)
}

//Addsendeth --send-eth/--send-ip: Send using raw ethernet frames or IP packets
//
// --send-eth (Use raw ethernet sending)
//
//Asks Nmap to send packets at the raw ethernet (data link) layer rather than the higher IP (network) layer. By default, Nmap chooses the one which is generally best for the platform it is running on. Raw sockets (IP layer) are generally most efficient for Unix machines, while ethernet frames are required for Windows operation since Microsoft disabled raw socket support. Nmap still uses raw IP packets on Unix despite this nmap when there is no other choice (such as non-ethernet connections).
func (receiver *nmap) Addsendeth() *nmap {
	return AddArgs(receiver, "--send-eth")
}

//Addsendip --send-ip (Send at raw IP level)
//
//Asks Nmap to send packets via raw IP sockets rather than sending lower level ethernet frames. It is the complement to the --send-eth nmap discussed previously.
func (receiver *nmap) Addsendip() *nmap {
	return AddArgs(receiver, "--send-ip")
}

//Addprivileged --privileged: Assume that the user is fully privileged
//
//--privileged (Assume that the user is fully privileged)
//
//Tells Nmap to simply assume that it is privileged enough to perform raw socket sends, packet sniffing, and similar operations that usually require root privileges on Unix systems. By default Nmap quits if such operations are requested but geteuid is not zero. --privileged is useful with Linux kernel capabilities and similar systems that may be configured to allow unprivileged users to perform raw-packet scans. Be sure to provide this nmap flag before any flags for options that require privileges (SYN scan, OS detection, etc.). The NMAP_PRIVILEGED environment variable may be set as an equivalent alternative to --privileged.
func (receiver *nmap) Addprivileged() *nmap {
	return AddArgs(receiver, "--privileged")
}

//Addunprivileged --unprivileged: Assume the user lacks raw socket privileges
//
//--unprivileged (Assume that the user lacks raw socket privileges)
//
//This nmap is the opposite of --privileged. It tells Nmap to treat the user as lacking network raw socket and sniffing privileges. This is useful for testing, debugging, or when the raw network functionality of your operating system is somehow broken. The NMAP_UNPRIVILEGED environment variable may be set as an equivalent alternative to --unprivileged.
func (receiver *nmap) Addunprivileged() *nmap {
	return AddArgs(receiver, "--unprivileged")
}

//AddV -V: Print version number
// -V; --version (Print version number)
//
// Prints the Nmap version number and exits.
func (receiver *nmap) AddV() *nmap {
	return AddArgs(receiver, "-V")
}

//Addh -h: Print this help summary page.
//
// -h; --help (Print help summary page)
//
// Prints a short help screen with the most common command flags. Running Nmap without any arguments does the same thing.
func (receiver *nmap) Addh() *nmap {
	return AddArgs(receiver, "-h")
}

//Addservicedb --servicedb <services file> (Specify custom services file)
//
//Asks Nmap to use the specified services file rather than the nmap-services data file that comes with Nmap. Using this nmap also causes a fast scan (-F) to be used. See the description for --datadir for more information on Nmap's data files.
func (receiver *nmap) Addservicedb(dirname string) *nmap {
	return AddArgs(receiver, "--servicedb", dirname)
}

//Addversiondb --versiondb <service probes file> (Specify custom service probes file)
//
//Asks Nmap to use the specified service probes file rather than the nmap-service-probes data file that comes with Nmap. See the description for --datadir for more information on Nmap's data files.
func (receiver *nmap) Addversiondb(dirname string) *nmap {
	return AddArgs(receiver, "--versiondb", dirname)
}

//Addreleasememory --release-memory (Release memory before quitting)
//This nmap is only useful for memory-leak debugging. It causes Nmap to release allocated memory just before it quits so that actual memory leaks are easier to spot. Normally Nmap skips this as the OS does this anyway upon process termination.
func (receiver *nmap) Addreleasememory() *nmap {
	return AddArgs(receiver, "--release-memory")
}
