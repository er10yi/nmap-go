package main

import (
	"fmt"
	"github.com/er10yi/nmap-go/nmap"
	"log"
)

// nmap基础扫描
func main() {
	//通过NewNmap()创建nmap
	//AddTargets增加目标，Addp增加端口范围，其他选项类似，如：-sV =》 AddsV()，-Pn => AddPn()
	scanner := nmap.NewNmap().AddTargets("127.0.0.1").Addp("1-65535")

	//Run运行
	runResult := scanner.Run()

	//获取警告信息
	warn := runResult.WarnOut
	if warn != "" {
		fmt.Printf("warn:\n%s", warn)
	}
	//获取错误信息
	err := runResult.ErrOut
	if err != nil {
		log.Fatal("error: ", err)
	}
	//获取运行的xml结果
	result := runResult.Result

	//解析xml结果
	parseResult := scanner.ParseXmlResult(result)
	if err != nil {
		log.Fatal(err)
	}
	xmlResult := parseResult.(*nmap.NmapXMLResult)

	//格式化输出xml结果
	scanner.PrettyResult(xmlResult)

	//导出xml结果到Excel
	scanner.ExportResult(xmlResult)

	//导出xml结果到txt，用于导入魔方
	scanner.ExportTxtResult(xmlResult)
}
