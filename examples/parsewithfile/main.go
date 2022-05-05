package main

import (
	"github.com/er10yi/nmap-go/nmap"
	"io/ioutil"
	"log"
)

// nmap 解析xml结果
func main() {
	//创建配置
	config := nmap.NewConfig()
	//导出的Excel结果中不合并行
	config.MergeRow = true

	//通过NewNmap()创建nmap ，并使用config配置
	scanner := nmap.NewNmap(config)

	//通过传入string的result，不需要run
	result, err := ioutil.ReadFile("examples/parsewithfile/nmap_example.xml")
	//解析xml结果
	parseResult := scanner.ParseXmlResult(string(result))
	if err != nil {
		log.Fatal(err)
	}
	xmlResult := parseResult.(*nmap.NmapXMLResult)

	//格式化输出xml结果
	scanner.PrettyResult(xmlResult)

	//导出xml结果到Excel
	scanner.ExportResult(xmlResult, "Result")
}
