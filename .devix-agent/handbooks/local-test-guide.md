1. 执行precmd `go mod vendor`
2. 在根目录执行 `go test -tags XDP_DISABLED ./...`
3. 通过输出获取运行结果，分析结果原因
4. 特别注意，有一些用例依赖运行环境，没有通过是正常的，分析结果原因时需要注意
