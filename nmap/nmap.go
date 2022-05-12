package nmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"github.com/pkg/errors"
	"github.com/xuri/excelize/v2"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type nmap struct {
	Result       string   `json:"result"`
	Args         []string `json:"args"`
	BinPath      string   `json:"binPath"`
	outputType   string
	ErrOut       error  `json:"errOut"`
	WarnOut      string `json:"warnOut"`
	exportOption config
}

// Run 通过指定context或使用默认context 运行nmap
func (receiver *nmap) Run(pctx ...context.Context) *nmap {
	var (
		stdout, stderr bytes.Buffer
		err            error
	)
	ctx := checkCtx(pctx)
	err = checkEnvNmap(receiver)
	if err != nil {
		return nil
	}
	//未指定输出，使用默认的-oX -
	if receiver.outputType == "" {
		receiver.Args = append(append(receiver.Args, "-oX"), "-")
	}
	cmd := exec.CommandContext(ctx, receiver.BinPath, receiver.Args...)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	done := make(chan error)
	go func() {
		defer close(done)
		err := cmd.Start()
		if err != nil {
			log.Fatal(err)
		}
		err = cmd.Wait()
		if err != nil {
			//log.Println("waiting on nmap:", err)
			done <- err
		}
	}()
	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		receiver.ErrOut = errors.New("timeout exceed")
	case <-done:
		outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
		//默认的xml输出格式
		if receiver.outputType == "" {
			result := &NmapXMLResult{}
			err = xml.Unmarshal(stdout.Bytes(), &result)
			// xml解析出错
			if err != nil {
				receiver.ErrOut = err
				return receiver
			}
			//cmd stderr 作为提示信息
			errorMsg := result.RunStats.Finished.ErrorMsg
			//运行错误信息
			if len(errorMsg) != 0 {
				receiver.ErrOut = errors.New(errorMsg)
				return receiver
			}
		}
		if len(errStr) != 0 {
			receiver.WarnOut = errStr
		}
		if len(outStr) != 0 {
			receiver.Result = outStr
			if receiver.exportOption.SaveXmlRaw {
				var resultName = receiver.exportOption.ResultName
				if receiver.outputType == "" {
					resultName = receiver.exportOption.ResultName + ".xml"
				}
				content := []byte(receiver.Result)
				err := ioutil.WriteFile(resultName, content, 0644)
				if err != nil {
					receiver.ErrOut = err
				}
			}
			return receiver
		}
	}
	return receiver
}

// PrettyResult 格式化xml结果到输出
func (receiver *nmap) PrettyResult(result *NmapXMLResult) {
	var hosthintResult []any
	var noHostHint bool
	if receiver.exportOption.ShowHosthint {
		for _, hosthint := range result.HostHint {
			hosthintResult = append(hosthintResult, fmt.Sprintf("\t%s %s ", hosthint.Address.Addr, hosthint.Status.State))
			for _, hostname := range hosthint.Hostnames {
				hosthintResult = append(hosthintResult, fmt.Sprintf("%s", hostname.Name))
			}
			hosthintResult = append(hosthintResult, "\n")
		}
	}
	if len(hosthintResult) == 0 {
		noHostHint = true
	}
	formateHeader := "\t%-9s" + //port/protocol
		"\t\t%-10s" + //state
		"\t%-20s" + //service
		"\t%-25s" + //product version
		"\t%s" + //cpe
		"\t%s" + //confidence
		"\t%s" +
		"\t%s\n"
	formateBody := "\t%d/%-9s" + //port/protocol
		"\t%-10s" + //state
		"\t%-20s" + //service
		"\t%s %-25s" + //product version
		"\t%-20s" + //cpe
		"\t%-2d" + //confidence
		"\t%s" +
		"\t\t\t%s\n"

	var outResult []any
	if receiver.exportOption.ShowHostPort || receiver.exportOption.ShowHosthint {
		for _, host := range result.Host {
			if noHostHint && receiver.exportOption.ShowHosthint {
				for _, addr := range host.Address {
					hosthintResult = append(append(hosthintResult, addr.Addr), " ")
				}
				hosthintResult = append(append(hosthintResult, string(host.Status.State)), " ")
				for _, hostname := range host.Hostnames {
					hosthintResult = append(append(hosthintResult, hostname.Name), " ")
				}
				hosthintResult = append(hosthintResult, "\n")
			}
			for _, addr := range host.Address {
				outResult = append(append(outResult, addr.Addr), " ")
			}
			outResult = append(append(outResult, string(host.Status.State)), " ")
			for _, hostname := range host.Hostnames {
				outResult = append(append(outResult, hostname.Name), " ")
			}
			outResult = append(outResult, "\n")
			if len(host.Ports) != 0 {
				outResult = append(outResult,
					fmt.Sprintf(formateHeader, "port", "state", "service", "version", "cpe", "confidence", "reason", "nseresult"))
				for _, ports := range host.Ports {
					for _, port := range ports.Port {
						nseOutput := make([]string, 0)
						for _, script := range port.Script {
							//fmt.Print(script.Id, " >>>")
							//fmt.Println(script.Output)
							nseOutput = append(append(append(nseOutput, script.Id), script.Output), " &&&& ")
						}
						nse := strings.Join(nseOutput, "\n")
						nse = strings.ReplaceAll(nse, "\n", "")
						nse = strings.TrimSuffix(nse, " &&&& ")
						outResult = append(outResult,
							fmt.Sprintf(formateBody, port.PortId, port.Protocol, port.State.State, port.Service.Name, port.Service.Product,
								port.Service.Version, port.Service.CPE, port.Service.Conf, port.State.Reason, nse))
					}

				}

				//for _, os := range host.OS {
				//	fmt.Println(os.PortUsed)
				//	fmt.Println(os.OSMatch)
				//	fmt.Println(os.OSFingerPrint)
				//
				//}
			}
		}
		if len(hosthintResult) != 0 && receiver.exportOption.ShowHosthint {
			fmt.Println("hosthint:")
			for _, r := range hosthintResult {
				fmt.Print(r)
			}
		}
		if len(outResult) != 0 && receiver.exportOption.ShowHostPort {
			fmt.Println("host and port:")
			for _, r := range outResult {
				fmt.Print(r)
			}
		}
	}
	fmt.Println(result.RunStats.Finished.Summary)
}

// ParseXmlResult 解析xml结果到NmapXMLResult结构体
func (receiver *nmap) ParseXmlResult(result any) any {
	b := []byte(result.(string))
	nmapXMLResult := &NmapXMLResult{}
	err := xml.Unmarshal(b, &nmapXMLResult)
	if err != nil {
		log.Fatal("Unsupported result format: ", err)
	}
	return nmapXMLResult
}

// ExportResult 解析xml结果到Excel文件中
func (receiver *nmap) ExportResult(result *NmapXMLResult) {
	target := receiver.exportOption.ResultName + ".xlsx"
	_, err := os.Stat(target)
	if err == nil {
		os.Remove(target)
	}
	file := excelize.NewFile()
	sheet1Name := "Sheet1"
	sheet2Name := "Sheet2"
	_ = file.NewSheet(sheet2Name)

	streamWriter, _ := file.NewStreamWriter(sheet1Name)
	streamWriter2, _ := file.NewStreamWriter(sheet2Name)
	setColWidth(streamWriter, 20, 1, 4)
	setColWidth(streamWriter, 30, 2)
	setColWidth(streamWriter, 10, 3)

	setColWidth(streamWriter2, 15, 1, 4, 8, 9, 10)
	setColWidth(streamWriter2, 30, 2, 11, 14)
	setColWidth(streamWriter2, 10, 3, 12, 13)

	header1 := []string{"address", "hostnames", "state", "reason"}
	writeHeader(streamWriter, header1)
	header2 := []string{"address", "hostnames", "_state", "_reason", "port", "protocol", "state", "service", "product", "version", "cpe", "confidence", "reason", "nseresult"}
	writeHeader(streamWriter2, header2)
	var noHostHint bool
	//hosthint
	for i, hosthint := range result.HostHint {
		row := make([]any, 4)
		if len(hosthint.Hostnames) != 0 {
			host := make([]string, 0)
			for _, hostname := range hosthint.Hostnames {
				host = append(host, hostname.Name)
			}
			row[1] = strings.Join(host, "\n")
		}
		row[0] = hosthint.Address.Addr
		row[2] = hosthint.Status.State
		row[3] = hosthint.Status.Reason
		index := i + 2
		writeValue(streamWriter, index, row)
	}
	if len(result.HostHint) == 0 {
		noHostHint = true
	}

	//host and ports
	i := 0
	mergeSlice := make([]int, 0)
	for j, host := range result.Host {
		if noHostHint {
			row := make([]any, 4)
			if len(host.Address) != 0 {
				addrTemp := make([]string, 0)
				for _, addr := range host.Address {
					addrTemp = append(addrTemp, addr.Addr)
				}
				row[0] = strings.Join(addrTemp, "\n")
			}
			if len(host.Hostnames) != 0 {
				hostTemp := make([]string, 0)
				for _, hostname := range host.Hostnames {
					hostTemp = append(hostTemp, hostname.Name)
				}
				row[1] = strings.Join(hostTemp, "\n")
			}
			row[2] = host.Status.State
			row[3] = host.Status.Reason
			index := j + 2
			writeValue(streamWriter, index, row)
		}
		row := make([]any, 14)
		if len(host.Address) != 0 {
			addrTemp := make([]string, 0)
			for _, addr := range host.Address {
				addrTemp = append(addrTemp, addr.Addr)
			}
			row[0] = strings.Join(addrTemp, "\n")
		}
		if len(host.Hostnames) != 0 {
			hostTemp := make([]string, 0)
			for _, hostname := range host.Hostnames {
				hostTemp = append(hostTemp, hostname.Name)
			}
			row[1] = strings.Join(hostTemp, "\n")
		}
		row[2] = host.Status.State
		row[3] = host.Status.Reason

		if len(host.Ports) == 0 {
			writeValue(streamWriter2, i+2, row)
			i++
		} else {
			for _, ports := range host.Ports {
				for _, port := range ports.Port {
					//row := make([]any, 13)
					//if len(host.Address) != 0 {
					//	addrTemp := make([]string, 0)
					//	for _, addr := range host.Address {
					//		addrTemp = append(addrTemp, addr.Addr)
					//	}
					//	row[0] = strings.Join(addrTemp, "\n")
					//}
					//
					//if len(host.Hostnames) != 0 {
					//	hostTemp := make([]string, 0)
					//	for _, hostname := range host.Hostnames {
					//		hostTemp = append(hostTemp, hostname.methodName)
					//	}
					//	row[1] = strings.Join(hostTemp, "\n")
					//}
					//row[2] = host.Status.State
					//row[3] = host.Status.Reason
					row[4] = port.PortId
					row[5] = port.Protocol
					row[6] = port.State.State
					row[7] = port.Service.Name
					row[8] = port.Service.Product
					row[9] = port.Service.Version
					if len(port.Service.CPE) != 0 {
						cpe := make([]string, 0)
						for _, s := range port.Service.CPE {
							cpe = append(cpe, s)
						}
						row[10] = strings.Join(cpe, "\n")
					}
					row[11] = port.Service.Conf
					row[12] = port.State.Reason
					nseOutput := make([]string, 0)
					for _, script := range port.Script {
						//fmt.Print(script.Id, " >>>")
						//fmt.Println(script.Output)
						nseOutput = append(append(append(nseOutput, script.Id), script.Output), strings.Repeat("&", 20))
					}
					nse := strings.Join(nseOutput, "\n")
					nse = strings.TrimSuffix(nse, strings.Repeat("&", 20))
					row[13] = nse

					index := i + 2
					writeValue(streamWriter2, index, row)
					i++
				}
			}
			mergeSlice = append(mergeSlice, i+1)
		}

	}

	if receiver.exportOption.MergeRow {
		start := 2
		end := 0
		for _, v := range mergeSlice {
			end = v
			streamWriter2.MergeCell("A"+strconv.Itoa(start), "A"+strconv.Itoa(end))
			streamWriter2.MergeCell("B"+strconv.Itoa(start), "B"+strconv.Itoa(end))
			streamWriter2.MergeCell("C"+strconv.Itoa(start), "C"+strconv.Itoa(end))
			streamWriter2.MergeCell("D"+strconv.Itoa(start), "D"+strconv.Itoa(end))
			start = v + 1
		}
	}
	if receiver.exportOption.AddTable {
		tableFormat := `{
		   "table_name": "table",
		   "table_style": "TableStyleMedium2",
		   "show_first_column": true,
		   "show_last_column": true,
		   "show_row_stripes": false,
		   "show_column_stripes": true
		}`
		streamWriter.AddTable("A1", "D"+strconv.Itoa(len(result.Host)+1), tableFormat)
		streamWriter2.AddTable("A1", "N"+strconv.Itoa(i+1), tableFormat)
	}

	file.SetSheetName(sheet2Name, "host And Ports")
	file.SetSheetName(sheet1Name, "hosthint")

	if err := streamWriter.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := streamWriter2.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := file.SaveAs(target); err != nil {
		log.Fatal(err)
	}
}

//ExportTxtResult 导出成txt格式，用于导入魔方资产
func (receiver *nmap) ExportTxtResult(result *NmapXMLResult) {
	target := receiver.exportOption.ResultName + ".txt"
	_, err := os.Stat(target)
	if err == nil {
		os.Remove(target)
	}
	file, err := os.Create(target)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, host := range result.Host {
		for _, addr := range host.Address {
			var outTotal []string
			for _, ports := range host.Ports {
				for _, port := range ports.Port {
					var out []any
					var version = port.Service.Product + port.Service.Version
					if port.Service.Product == "" {
						version = "null"
					}
					out = append(out, fmt.Sprintf("%d,%s,%s,%s,%s", port.PortId, port.Protocol, port.State.State, port.Service.Name, version))
					result := fmt.Sprintf("%s,", out)
					result = strings.TrimRight(result, ",")
					outTotal = append(outTotal, result)
				}
			}
			var total = addr.Addr
			if len(outTotal) != 0 {
				strResult := strings.Join(outTotal, ",")
				total += "[" + strResult + "]"
			}
			fmt.Fprintln(writer, total)
		}
		writer.Flush()
	}
}

func NewNmap(cfg ...*config) *nmap {
	n := &nmap{}
	// export nmap
	option := checkOption(cfg)
	n.exportOption = *option
	return n
}

func checkEnvNmap(receiver *nmap) error {
	if receiver.BinPath == "" {
		path, err := exec.LookPath("nmap")
		if err != nil {
			return err
		} else {
			receiver.BinPath = path
		}
	}
	return nil
}

func checkOption(opt []*config) *config {
	var option *config
	opLen := len(opt)
	switch opLen {
	case 0:
		option = &config{
			ResultName:   "Result",
			ShowHosthint: true,
			ShowHostPort: true,
			MergeRow:     true,
			AddTable:     true,
			SaveXmlRaw:   true,
		}
	case 1:
		option = opt[0]
	default:
		panic("support one nmap only")
	}
	return option
}

func checkCtx(pctx []context.Context) context.Context {
	var ctx context.Context
	pctxLen := len(pctx)
	switch pctxLen {
	case 0:
		ctx, _ = context.WithCancel(context.Background())
	case 1:
		ctx = pctx[0]
	default:
		panic("support one context only")
	}
	return ctx
}

func setColWidth(writer *excelize.StreamWriter, colWidth float64, col ...int) {
	for _, v := range col {
		err := writer.SetColWidth(v, v, colWidth)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func writeValue(writer *excelize.StreamWriter, index int, row []any) {
	cell, _ := excelize.CoordinatesToCellName(1, index)
	if err := writer.SetRow(cell, row); err != nil {
		log.Fatal(err)
	}
}

func writeHeader(writer *excelize.StreamWriter, header1 []string) {
	row := make([]any, len(header1))
	for i, s := range header1 {
		row[i] = s
	}
	cell, _ := excelize.CoordinatesToCellName(1, 1)
	if err := writer.SetRow(cell, row); err != nil {
		log.Fatal(err)
	}
}

// https://svn.nmap.org/nmap/docs/nmap.usage.txt
// https://nmap.org/man/zh/man-briefoptions.html
/*
* REMINDER: 由于方法名需要和nmap参数保持一致，所以有些命名会存在不规范的地方，所有方法都以Add开头，忽略它😄
* 2022-04-06 23:23
* English comments: https://svn.nmap.org/nmap/docs/nmap.usage.txt
* 中文注释来源: https://nmap.org/man/zh/man-briefoptions.html
* 仅搬运官方文档，详细使用可以结合文档（使用Man方法）
* */

// AddArgs 添加一个或多个参数
func AddArgs(receiver *nmap, args ...string) *nmap {
	for _, arg := range args {
		receiver.Args = append(receiver.Args, arg)
	}
	return receiver
}
