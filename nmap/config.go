package nmap

type config struct {
	//打印的结果中显示Hosthint
	ShowHosthint bool
	//打印的结果中显示host 和 port 信息
	ShowHostPort bool
	//导出的Excel结果中合并行
	MergeRow bool
	//导出的Excel结果中增加表格
	AddTable bool
}

func NewConfig() *config {
	cfg := &config{
		ShowHosthint: true,
		ShowHostPort: true,
		MergeRow:     true,
		AddTable:     true,
	}
	return cfg
}
