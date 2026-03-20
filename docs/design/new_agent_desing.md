重新设计workflow

一共设计4个agent, 分别为:
- Analyzer
- Repairer
- Checker
- Inspector
每个agent都有专门的提示词.

设置全局变量
- has_repaired, 初始值为false, 如果Repair进行了修复, 则设为true
- fixed_time, 初始为0, 记录修复次数.
- max_fix_time, 初始为2, 最大修复次数阈值
- last_node, 初始为空, 记录当前node的上一个node

知识库:
- error_repair_knowledge.yaml知识库, 包含<known_error_type>:<repair_method>键值对

## deploy_tool

将static_check/compile/load/attach/test阶段作为一个整体Tool, 记为deploy_tool, 负责部署测试代码.
设置变量如下:
- deploy_state, 初始值为false,  若最终成功通过部署和测试, 设为true. 
- failed_stage, 可选值[static_check/compile/load/attach/test], 当某个stage失败时, 设置为当前阶段stage

输入为.bpf.c测试用例
输出为deploy_state, failed_stage_result(后者在失败时才需要添加内容).
- 下一步: 
    - 若success且has_repaired不为真, 直接结束
    - 若success且has_repaired为真, 则进入Refiner
    - 若deploy_state为false且fixed_time超过阈值, 进入Refiner
    - 若deploy_state为false且fixed_time未超过阈值, 进入Analyzer

跳转的逻辑规则可以通过一个函数实现.

# Analyzer
Analyzer:
- 功能: 分析deploy结果, 判断是否能通过修改源代码解决, 如果可以, 给出具体错误类型和修复建议; 如果不行, 则进入Refiner
- 变量: can_fix
- 输入: failed_stage_result, 源代码
- 输出: analysis_report, repair_action
- 下一步: 
    - 若can_fix = false, 不能通过修改源代码解决(如环境不支持), 进入Refiner
    - 若can_fix = true,  进入Repairer
- 提示词: 提示词中加入error_repair_knowledge知识

# Repairer
Repairer:
- 功能: 根据分析结果和意见, 修改代码
- 输入: 源代码, analysis_report(包括error_type和repair_method)
- 输出: 修改后的代码
- 出边: 进入Inspector
- 其他操作: 当last_node == Analyzer, fixed_time += 1

# Inspector
- 功能: 检查修改后的代码和源代码是否保持相同语义 (大致功能相同, 没有明显错误即可)
- 输入: 源代码, 修改后代码
- 输出: 检查结果, 给出修改建议
- 下一步:
    - 如果结果相同, 则进入deploy_tool
    - 检查结果不同, 给出检查结果, 进入Repaier重新修改(此时Repair的源代码应该是它刚刚生成的代码)

# Refiner
- 功能: 总结修复过程中的经验, 更新到知识库
- 输入: deploy_state
- 输出: 简要总结修复经验, 按照格式更新error_repair_knowledge.yaml
- 函数: 
    get_entire_repair_process() -> 获取修复过程
    update_knowledge() -> 更新知识库
