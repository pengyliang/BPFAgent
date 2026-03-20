# eBPF Agent：跨内核版本自动化部署系统
### 项目实现计划 v1.0

---

## 项目概述

eBPF Agent 是一套面向生产环境的智能化部署框架，旨在解决 eBPF 程序跨内核版本（4.x ~ 6.x）兼容性部署难题。通过规则引擎、LLM Agent 分析、自动化验证闭环三层架构，实现"一次编写、多版本自动适配"的目标，并在失败时提供可供工程师直接阅读的结构化诊断报告。

**核心挑战：**
- **Helper 函数不支持**：部分 helper 在低版本内核不存在，需寻找等价替代
- **Verifier 限制**：不同版本 verifier 在指令复杂度、循环、内存访问等方面规则各异
- **内核结构体差异**：字段偏移、字段存在性因内核版本不同而变化
- **特性支持差异**：BTF、CO-RE、ring buffer 等新特性在旧版本不可用

**解决策略：**
- 构建 helper 替代规则库，自动映射不兼容 helper 到等价调用序列
- 解析 verifier 错误输出，LLM Agent 定向修改代码结构
- 优先 CO-RE + vmlinux.h 方案，降级时使用字段偏移静态注入
- 特性检测 + 代码生成降级路径（如 ring buffer → perf event array）

---

## 1. 系统整体架构

### 1.1 架构分层

系统采用三层架构设计，各层职责清晰，通过标准接口耦合。

| 层级 | 职责说明 |
|------|---------|
| **接入与解析层** | eBPF 源码读取、内核信息采集（uname、/proc/config.gz、BTF 可用性）、AST 解析（基于 clang LibTooling 或 LLVM IR） |
| **分析与决策层** | 规则库引擎（静态规则）+ eBPF Agent LLM（动态推理）+ RAG 知识库（历史修复案例、内核文档） |
| **执行与反馈层** | bpftool prog load 执行、verifier 输出捕获、结构化错误分类、循环重试控制器 |

### 1.2 核心数据流

```
① 读取 eBPF 源码
        │
        ▼
② 内核信息采集（KernelProfile JSON）
        │
        ▼
③ 规则库匹配与替换（静态规则，确定性问题）
        │
        ▼
④ eBPF Agent 前置分析（LLM + RAG，模糊场景）
        │
        ▼
⑤ bpftool 编译 + 部署
        │
   ┌────┴────┐
  成功      失败
   │         │
  结束       ▼
         ⑥ Verifier 输出解析 + 错误分类
                  │
            ┌─────┴─────┐
          可修复      超过重试上限
            │              │
         回到 ④           ▼
                    ⑦ 结构化错误报告输出
```
> 当步骤 4 分析后认为代码没有问题，可直接进入步骤5的编译和部署。

> 步骤 ⑤ 成功则流程结束；失败则进入 ⑥ Verifier 分析，重新触发 ④ Agent，最多重试 **N 次**（可配置，默认 5）后进入 ⑦ 错误总结输出。


---

## 2. 核心模块详细设计

### 2.1 eBPF 源码解析模块

**功能目标：** 将输入的 eBPF C 代码解析为结构化表示，供后续分析使用。

**实施要点：**

- **AST 解析**：使用 `clang -ast-dump` 或 LibClang Python 绑定，提取所有 bpf_helper 调用点、struct 字段访问路径、map 操作序列
- **Section 识别**：识别 `SEC("xxx")` 标注的程序类型（kprobe/tracepoint/xdp 等），用于后续 helper 白名单过滤
- **依赖图构建**：建立函数调用图，识别 tail call、inline 函数，为 verifier 复杂度预估提供基础
- **符号表提取**：收集全局变量、map 定义、BTF 注解信息，生成结构化 JSON 摘要

---

### 2.2 内核信息采集模块

**功能目标：** 全面采集目标主机的内核能力信息，构建「内核能力画像」，作为规则引擎和 Agent 的输入上下文。

| 采集项 | 采集方式 / 说明 |
|--------|----------------|
| **内核版本** | `uname -r`，解析 major.minor.patch 及发行版后缀（RHEL/Ubuntu 内核差异） |
| **编译选项** | `/proc/config.gz` 或 `/boot/config-$(uname -r)`，提取 `CONFIG_BPF_*` 开关 |
| **BTF 可用性** | 检测 `/sys/kernel/btf/vmlinux` 文件存在性及大小 |
| **Helper 白名单** | `bpftool feature probe` 输出解析，生成当前内核支持的 helper 列表 |
| **Map 类型支持** | `bpftool feature probe` 输出 `map_type` 字段，识别 ring buffer 等高版本特性 |
| **Verifier 限制** | 推断：内核 < 5.2 无 bounded loops；< 5.8 无 bpf_ringbuf；< 5.3 stack 上限 512B |
| **LLVM/clang 版本** | `clang --version`，影响 CO-RE 编译能力判断 |

**输出格式：** 采集结果序列化为 `KernelProfile JSON`，包含版本号、特性开关 map、helper 支持列表三部分，作为 Agent context 的固定前缀。

---

### 2.3 规则库引擎（静态规则）

**设计原则：** 规则库处理「有确定性答案」的兼容性问题，追求零误判、高覆盖、可维护。LLM 处理规则库未覆盖的模糊场景。

**规则分类：**

| 规则类型 | 规则内容示例 |
|---------|------------|
| **Helper 替换规则** | `bpf_get_ns_current_pid_tgid` → 组合 `bpf_get_current_pid_tgid` + ns 检查；`bpf_ringbuf_submit` → `perf_event_output` 等价逻辑 |
| **结构体字段规则** | `sk_buff->tstamp` 在 < 4.14 不存在，替换为 `ktime_get_ns()`；`task_struct->recent_used_cpu` 在 < 5.x 需 CO-RE 或 `BPF_CORE_READ` 宏 |
| **Map 降级规则** | `BPF_MAP_TYPE_RINGBUF` → `BPF_MAP_TYPE_PERF_EVENT_ARRAY`（含读写 API 同步替换） |
| **特性开关规则** | CO-RE 可用时优先 `BPF_CORE_READ`；不可用时注入 `bpf_probe_read_kernel` 替代 |
| **循环改写规则** | < 5.2 内核不支持 bounded loop，自动展开或替换为 `#pragma unroll` |
| **栈大小规则** | 检测局部变量总大小，> 480B 时警告并建议改为 per-cpu map 存储 |

**规则存储格式：** 采用 YAML 文件描述，每条规则包含：

```yaml
rule:
  id: "helper_ringbuf_fallback"
  match_condition:
    kernel_version: "< 5.8"
    pattern: "bpf_ringbuf_submit|bpf_ringbuf_output"
  transform:
    type: "ast_replace"
    target: "perf_event_output"
    extra_map_inject: true
  priority: 10
  test_case: "tests/helper/ringbuf_fallback.c"
```

规则文件版本控制，支持在线热更新。

---

### 2.4 eBPF Agent（LLM 推理层）

**Agent 定位：** 处理规则库无法覆盖的场景——复杂的跨字段依赖修改、verifier 语义错误的代码重构、需要理解业务逻辑的特性降级方案。

#### 两阶段工作模式

**阶段一：前置分析（Pre-deploy Analysis）**

- 输入：eBPF 源码 AST 摘要 + KernelProfile + RAG 检索结果
- 任务：预测可能的兼容性风险，输出「风险清单」及修改建议
- 输出：修改后的 eBPF 代码（Patch 形式）+ 修改说明

**阶段二：Verifier 错误分析（Post-failure Analysis）**

- 输入：verifier 完整日志 + 当前代码 + 前置修改历史 + KernelProfile
- 任务：解析 verifier 报错类型，定位出错行，生成针对性修复代码
- 约束：每次修改必须附带「错误类型标注」，便于循环中去重防止重复修复
- 循环控制：相同错误类型出现 2 次以上则标记为「难以自动修复」，提前终止

#### RAG 知识库内容

| 知识来源 | 内容说明 |
|---------|---------|
| **内核 helper 文档** | `linux/Documentation/bpf/`，每个 helper 的版本引入记录、参数限制 |
| **Verifier 错误模式库** | 历史 verifier 错误信息 + 对应修复 patch（来自 bpf mailing list） |
| **CO-RE 使用指南** | libbpf CO-RE 宏使用规范，常见 struct 的 CO-RE 适配模式 |
| **内核版本特性矩阵** | 每个重要特性的最低内核版本要求，格式化为结构化表格 |
| **修复案例库** | 历史部署失败 → 成功的案例，含问题描述、根因、修复 diff |

#### Prompt 工程要点

- SystemPrompt 固定注入 KernelProfile，避免 Agent 遗忘内核上下文
- 每次修改要求 Agent 以 JSON 格式输出：`{error_type, root_cause, patch, confidence}`
- 多轮对话保留完整修改历史，防止 Agent 在循环中重复相同错误修改
- 设置「修改保守性」指令：优先最小化改动，避免重写业务逻辑

---

### 2.5 部署执行与 Verifier 反馈模块

**部署流程：**

1. **编译阶段**：`clang -O2 -target bpf -c ebpf.c -o ebpf.o`（自动检测 clang 版本，选择合适 `-mcpu` 参数）
2. **加载阶段**：`bpftool prog load ebpf.o /sys/fs/bpf/prog`，捕获 stdout + stderr
3. **验证阶段**：检查退出码；失败时解析 verifier 日志（`--log_level 2` 获取详细输出）
4. **清理阶段**：失败时自动 unpin 已挂载的 map，保证环境干净

**Verifier 错误分类器：**

在送入 Agent 前，先经过结构化分类器对错误类型进行标注，提升 Agent 推理准确率：

| 错误类型 | 处置方向 |
|---------|---------|
| `invalid_mem_access` | 非法内存访问；检查 map value 读写越界、PTR_TO_STACK 越界 |
| `unbounded_loop` | 无界循环；添加循环计数器或 `#pragma unroll` |
| `unknown_func` | 调用了不存在的 helper；触发 helper 替换规则 |
| `reg_type_mismatch` | 寄存器类型不匹配；通常需要补充 NULL 检查 |
| `stack_depth_exceeded` | 栈超限（512B）；改用 per-cpu array map 中转数据 |
| `invalid_map_type` | 使用了不支持的 map 类型；触发 map 降级规则 |
| `unreachable_insn` | 不可达指令；简化控制流或去除冗余分支 |
| `insn_limit_exceeded` | 指令数超限（旧版本 4096 条）；拆分程序为 tail call |

---

### 2.6 循环控制与终止策略

| 控制项 | 策略说明 |
|--------|---------|
| **最大重试次数** | 默认 5 次，可通过配置项 `max_retry` 调整 |
| **重复错误检测** | 同一 `error_type` 出现 ≥ 2 次，标记为不可自动修复，跳出循环 |
| **修改差量检测** | 连续两次 patch diff 为空，视为 Agent 陷入死循环，强制终止 |
| **置信度阈值** | Agent 输出 `confidence < 0.4`，建议人工介入而非继续重试 |
| **超时控制** | 单次编译 + 加载总超时 60s；整体 Agent 循环超时 10min |

---

## 3. 错误报告与诊断输出

当 Agent 无法在最大重试次数内成功部署时，系统输出结构化诊断报告，供工程师快速定位问题。

### 3.1 报告结构

| 字段 | 内容说明 |
|------|---------|
| `deploy_summary` | 目标内核版本、程序类型、总重试次数、最终结论（失败原因分类） |
| `error_timeline` | 每轮重试的错误类型、Agent 修复操作、修复前后 diff，时序排列 |
| `root_cause_analysis` | 最终根因推断：是 helper 缺失 / 内核太旧 / 代码设计问题 / 规则库缺失 |
| `manual_hints` | 人工修复建议：最小内核版本要求、推荐替代方案、相关内核文档链接 |
| `unresolved_errors` | 未解决的 verifier 错误原文 + 标注的错误类型，便于直接搜索 |

### 3.2 报告示例

```json
{
  "deploy_summary": {
    "kernel": "5.4.0-generic",
    "program_type": "kprobe",
    "total_retries": 5,
    "result": "failed"
  },
  "root_cause_analysis": {
    "type": "unsupported_map_type",
    "description": "bpf_ringbuf_submit 在 kernel 5.4 不支持（需 >= 5.8），map 降级规则执行失败：ring buffer 事件结构体含可变长字段，无法直接映射到 perf_event_array"
  },
  "manual_hints": {
    "min_kernel_required": "5.8.0",
    "suggestion": "建议升级至 kernel >= 5.8，或重构事件结构体为固定长度后启用 perf_event_array 降级路径",
    "reference": "https://www.kernel.org/doc/html/latest/bpf/ringbuf.html"
  }
}
```

---

## 4. 分阶段实施计划

### Phase 1：基础框架 + 规则引擎（Week 1–3）

> 内核信息采集、AST 解析、规则库 MVP

- **Week 1**：内核信息采集模块开发，输出 KernelProfile JSON；bpftool feature 解析脚本
- **Week 2**：LibClang AST 解析器，提取 helper 调用、struct 访问、map 定义摘要
- **Week 3**：规则引擎核心（YAML 规则加载、AST 替换执行、规则优先级调度）；编写初版 helper 替换规则 20 条

**交付物：** 可对已知 helper 兼容性问题执行静态规则替换，通过 5 个端到端测试用例

---

### Phase 2：Agent 集成 + RAG 构建（Week 4–7）

> LLM Agent 接入、知识库构建、两阶段分析流水线

- **Week 4**：构建 RAG 知识库——抓取 `linux/Documentation/bpf`、libbpf 文档、bpf mailing list 历史 patch，向量化存储
- **Week 5**：eBPF Agent 前置分析接入：Prompt 设计、KernelProfile 上下文注入、JSON 输出解析
- **Week 6**：部署执行模块：clang 编译封装、bpftool 加载、verifier 日志捕获与结构化
- **Week 7**：Verifier 错误分类器开发；Agent 后置分析接入；循环控制器实现

**交付物：** 完整闭环流水线可运行，支持 5 类主要 verifier 错误的自动修复

---

### Phase 3：规则库扩充 + 稳定性（Week 8–10）

> 规则扩充、测试矩阵、性能优化

- **Week 8**：规则库扩充至 80+ 条；补充 CO-RE / vmlinux.h 相关规则；map 降级规则完整实现
- **Week 9**：跨版本测试矩阵（kernel 4.15 / 5.4 / 5.10 / 5.15 / 6.1）在 QEMU 环境自动化执行
- **Week 10**：错误报告模块完善；Agent 循环稳定性优化（去重、幂等性保证）；文档与 API 定义

**交付物：** 通过 20+ 真实 eBPF 程序的跨版本部署测试；输出工程可用的错误诊断报告

---

## 5. 关键技术选型

| 组件 | 选型说明 |
|------|---------|
| **AST 解析** | LibClang（Python 绑定）或 `clang -ast-dump` JSON 模式；可选 LLVM IR 分析 |
| **规则引擎** | Python 自研 YAML 规则加载器 + AST 变换器；不引入外部规则框架保持可控 |
| **LLM Agent** | Anthropic Claude API（claude-sonnet 系列），支持长上下文注入 verifier 日志 |
| **RAG** | LlamaIndex + ChromaDB（本地向量库），支持离线部署 |
| **编译工具链** | clang/llvm 10+（支持 BPF target）；libbpf 0.5+ 提供 CO-RE 支持 |
| **部署工具** | bpftool（linux-tools）；支持 libbpf skeleton 模式作为备选 |
| **测试环境** | QEMU + virtme 快速启动多版本内核虚拟机；GitHub Actions 矩阵测试 |
| **配置管理** | TOML 配置文件；规则库 Git 仓库版本控制；支持规则热更新 API |

---

## 6. 风险识别与应对

| 风险项 | 应对措施 |
|--------|---------|
| **LLM 修复幻觉** | Agent 生成语法正确但语义错误的代码 → 编译 + verifier 双重验证兜底；循环重复错误检测提前终止 |
| **规则库覆盖不足** | 新内核版本引入新 helper 导致规则缺失 → RAG 动态补充 + 人工 case 反馈闭环更新规则库 |
| **CO-RE 不可用降级** | 旧内核无 BTF 时 CO-RE 方案失效 → 预先检测 BTF 可用性，切换 `bpf_probe_read` 路径 |
| **Verifier 日志不完整** | 部分内核版本 verifier 日志截断 → 使用 `--log_level 2` 最大详细度；日志截断时触发人工介入 |
| **程序逻辑破坏** | 激进修改导致 eBPF 程序语义变化 → 要求 Agent 最小化改动；保留修改前版本供对比 |

---

## 7. 成功衡量指标

| 指标 | 目标值 |
|------|--------|
| **自动部署成功率** | 常见 eBPF 程序在跨 2 个主版本场景下自动成功率 ≥ 80% |
| **平均修复轮次** | Agent 循环平均 ≤ 2.5 轮完成修复 |
| **规则命中率** | 已知兼容性问题中规则库静态修复覆盖率 ≥ 60%（减少 LLM 调用开销） |
| **诊断报告可读性** | 工程师阅读报告后 10 分钟内定位根因（用户调研评分 ≥ 4/5） |
| **误修改率** | Agent 修改导致程序语义变化的概率 < 5%（通过功能测试验证） |

---

*规则库、Prompt 模板、测试矩阵等附件将在各阶段交付时补充更新。*
