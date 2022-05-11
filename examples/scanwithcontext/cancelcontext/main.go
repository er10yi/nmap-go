package main

import (
	"context"
	"fmt"
	"github.com/er10yi/nmap-go/nmap"
	"log"
)

// nmap 指定timeout context 扫描
func main() {
	//通过NewNmap()创建nmap
	//AddTargets增加目标，AddsV增加（-sV）选项，所有的nmap选项都可以通过Add来添加
	scanner := nmap.NewNmap().AddTargets("127.0.0.1").AddPn().Addn()

	//指定cancel context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	//Run运行
	runResult := scanner.Run(ctx)

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
	//scanner.ExportResult(xmlResult)
}
