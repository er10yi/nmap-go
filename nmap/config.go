package nmap

type config struct {
	//结果文件的名称
	ResultName string `json:"result_name"`
	//打印的结果中显示Hosthint
	ShowHosthint bool
	//打印的结果中显示host 和 port 信息
	ShowHostPort bool
	//导出的Excel结果中合并行
	MergeRow bool
	//导出的Excel结果中增加表格
	AddTable bool
	//保存xml结果
	SaveXmlRaw bool `json:"save_xml_raw"`
}

func NewConfig() *config {
	cfg := &config{
		ResultName:   "Result",
		ShowHosthint: true,
		ShowHostPort: true,
		MergeRow:     true,
		AddTable:     true,
		SaveXmlRaw:   true,
	}
	return cfg
}
