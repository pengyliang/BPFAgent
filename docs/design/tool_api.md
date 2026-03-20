name: kernel_profile
描述:采集内核版本, 内核支持的eBPF相关信息
输入:无
输出:kernel_profile.json, 包含BTF信息, kernel ebpf feature

名字: static_checker
描述: 读取源码.bpf.c, 做AST分析解析helper函数, 对比kernel_profile.json确定所使用的helper函数和attach point是否支持.
输入: prog.bpf.c源码, kernel_profile.json
输出: static_check.json, 包含error_count, warning_count, 和具体的issue

名字: compiler
描述: 编译通过static_checker检查的ebpf代码, 生成.bpf.o文件
输入: prog.bpf.c
输出: prog.bpf.o和compile_result.json, 包含编译结果, 编译参数, 错误信息

名字: load_attacher
描述: 将编译通过的prog.bpf.o load并attach
输入: prog.bpf.o
输出: load_result.json, attach_result.json

名字: tester
描述: 测试正确attach的ebpf程序
输入: test case name
输出: test_result