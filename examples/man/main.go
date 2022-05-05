package main

import (
	"github.com/er10yi/nmap-go/nmap"
)

func main() {
	newNmap := nmap.NewNmap()
	//输出所有中文帮助信息（官方中文文档）
	newNmap.ManZh()

	// ManBriefOptions 选项概要
	newNmap.ManBriefOptions()

	// ManTargetSpecification 目标说明
	newNmap.ManTargetSpecification()

	// ManHostDiscovery 主机发现
	newNmap.ManHostDiscovery()

	// ManPortScanningBasics 端口扫描基础
	newNmap.ManPortScanningBasics()

	// ManPortScanningTechniquessics 端口扫描技术
	newNmap.ManPortScanningTechniquessics()

	// ManPortSpecification 端口说明和扫描顺序
	newNmap.ManPortSpecification()

	// ManVersionDetection 服务和版本探测
	newNmap.ManVersionDetection()

	// ManOsDetection 操作系统探测
	newNmap.ManOsDetection()

	// ManPerformance 时间和性能
	newNmap.ManPerformance()

	// ManBypassFirewallsIds 防火墙/IDS躲避和哄骗
	newNmap.ManBypassFirewallsIds()

	// ManOutput 输出
	newNmap.ManOutput()

	// ManMiscOptions 其它选项
	newNmap.ManMiscOptions()

	// ManRuntimeInteraction 运行时的交互
	newNmap.ManRuntimeInteraction()

	// ManExamples 实例
	newNmap.ManExamples()

	// ManBugs Bugs
	newNmap.ManBugs()

	// ManAuthor 作者
	newNmap.ManAuthor()

	// ManLegal 法律事项(版权、许可证、担保(缺)、出口限制)
	newNmap.ManLegal()

}
