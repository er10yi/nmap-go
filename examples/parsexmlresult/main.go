package main

import (
	"flag"
	"fmt"
	"github.com/er10yi/nmap-go/nmap"
	"io/ioutil"
	"log"
	"os"
)

// 编译成bin后，通过命令行指定xml的nmap结果，解析成Excel
func main() {

	var (
		target, resultName                           string
		show, showhost, showport, mergerow, addtable bool
	)
	flag.StringVar(&target, "target", "", "目标，待解析的nmap xml结果")
	flag.StringVar(&resultName, "result", "Result", "结果，Excel文件名称")
	flag.BoolVar(&showhost, "showhost", true, "打印解析后的hosthint结果")
	flag.BoolVar(&showport, "showport", true, "打印解析后的host port等结果")
	flag.BoolVar(&mergerow, "mergerow", true, "导出的Excel合并行")
	flag.BoolVar(&addtable, "addtable", true, "导出的Excel增加table")
	flag.BoolVar(&show, "show", true, "打印解析后的结果")
	flag.Parse()

	if len(os.Args) == 1 {
		fmt.Println("将nmap xml结果解析成Excel")
		fmt.Println("用法")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if target == "" {
		log.Fatal("请输入目标xml")
	}
	_, err := os.Stat(target)
	if err != nil {
		log.Fatalf("%s 不存在", target)
	}

	//创建配置
	config := nmap.NewConfig()
	config.ShowHosthint = showhost
	config.ShowHostPort = showport
	config.MergeRow = mergerow
	config.AddTable = addtable

	//通过NewNmap()创建nmap ，并使用config配置
	scanner := nmap.NewNmap(config)

	//通过传入string的result，解析xml结果
	result, err := ioutil.ReadFile(target)
	parseResult := scanner.ParseXmlResult(string(result))
	if err != nil {
		log.Fatal(err)
	}
	xmlResult := parseResult.(*nmap.NmapXMLResult)

	//格式化输出xml结果
	if show {
		scanner.PrettyResult(xmlResult)
	}

	//导出xml结果到Excel
	scanner.ExportResult(xmlResult)

	//导出xml结果到txt，用于导入魔方
	scanner.ExportTxtResult(xmlResult)
}
