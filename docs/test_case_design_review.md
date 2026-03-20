# data/ 下 Test Case 设计检查报告

检查范围：workload、validator 与 BPF 逻辑是否一致，以及设计是否合理。

---

## 一、结论概览

| 分类 | Case 数 | workload/validator 设计 | 需修改 |
|------|--------|---------------------------|--------|
| kernel_struct | 4 | 一致，设计合理 | 仅 field_offset_change 需在 6.6 上核对 offset |
| verifier | 5 | 一致，设计合理 | 无 |
| helper_func | 4 | 一致，设计合理 | 无 |
| feature | 5 | 一致，设计合理 | 2 个为 x86_64 符号名，跨架构需说明 |

所有用例的 **workload 触发次数** 与 **validator 的 map/key/value/type** 均与对应 BPF 程序行为一致，未发现“workload 没触发够”或“validator 期望错误”的硬伤。下面按类说明并标注注意事项。

---

## 二、kernel_struct（4 个）

### 1. field_add_remove
- **程序**：`tracepoint/syscalls/sys_enter_openat`，读 `task_struct.bpf_storage`，条件恒真则 `counter[0]++`。
- **workload**：3 次 `cat /etc/hostname` → 至少 3 次 openat。
- **validator**：`counter`，key=0，min 3。
- **结论**：合理。若内核无 `bpf_storage` 会加载失败，能加载时 3 次 openat 足够达到 ≥3。

### 2. field_offset_change
- **程序**：`tracepoint/syscalls/sys_enter_openat`，用固定 offset 读 `task_struct.tgid`，与 `bpf_get_current_pid_tgid()` 比较，相等则 `counter[0]++`。
- **workload**：3 次 `cat /etc/hostname` → 至少 3 次 openat。
- **validator**：`counter`，key=0，min 3。
- **结论**：设计合理（故意用 6.6 固定 offset 做兼容性测试）。**注意**：`TASK_TGID_OFFSET` 必须与当前 6.6 内核的 `task_struct.tgid` 字节偏移一致，否则计数恒为 0。请在 6.6 虚拟机内用 `scripts/tools/get_task_tgid_offset.py` 取真实 offset 并更新源码中的宏。

### 3. field_type_change
- **程序**：`tracepoint/syscalls/sys_enter_openat`，`BPF_CORE_READ(task, __state)` 读成 u64，条件恒真则 `counter[0]++`。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。

### 4. struct_nesting_or_rename
- **程序**：`tracepoint/syscalls/sys_enter_openat`，`BPF_CORE_READ(task, thread.fsbase)`，条件恒真则 `counter[0]++`。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。

---

## 三、verifier（5 个）

### 1. loop_support
- **程序**：`tracepoint/syscalls/sys_enter_openat`，每次命中执行 `for (i=0;i<4;i++) (*val)++`，即每次 openat 使 counter 增加 4。
- **workload**：1 次 `cat /etc/hostname` → 至少 1 次 openat → counter += 4。
- **validator**：min 4。
- **结论**：合理。

### 2. kfunc_support
- **程序**：`fentry/__x64_sys_execve`，每次 execve 命中则 `counter[0]++`。
- **workload**：`/bin/echo kfunc_support_test > /dev/null` → 1 次 execve。
- **validator**：min 1。
- **结论**：合理。**注意**：节名为 `__x64_sys_execve`，仅在 x86_64 上有效；其他架构需对应符号（如 aarch64 的 `__arm64_sys_execve`）。

### 3. ptr_to_btf_id
- **程序**：`tracepoint/syscalls/sys_enter_execve`，tgid>0 则 `counter[0]++`。
- **workload**：`/bin/echo ptr_to_btf_id_test > /dev/null` → 1 次 execve。
- **validator**：min 1。
- **结论**：合理。

### 4. dynptr_memory_model
- **程序**：`tracepoint/syscalls/sys_enter_write`，ringbuf 提交成功后 `counter[0]++`。
- **workload**：`echo ... > /tmp/...` + `rm -f` → 至少 1 次 write。
- **validator**：min 1。
- **结论**：合理。

### 5. bpf_to_bpf_fault
- **程序**：`tracepoint/syscalls/sys_enter_openat`，通过子程序 `add_one(val)` 使 `counter[0]++`。
- **workload**：1 次 cat → 至少 1 次 openat。
- **validator**：min 1。
- **结论**：合理。

---

## 四、helper_func（4 个）

### 1. helper_absent
- **程序**：`tracepoint/syscalls/sys_enter_openat`，用 `bpf_get_current_task_btf()`，有 task 则 `counter[0]++`。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。老内核无该 helper 会加载失败；能加载时 3 次足够。

### 2. helper_arg_decrease
- **程序**：`tracepoint/syscalls/sys_enter_openat`，用 `bpf_strncmp`，相等则 `counter[0]++`（此处恒相等）。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。

### 3. helper_arg_increase
- **程序**：`tracepoint/syscalls/sys_enter_openat`，用 `bpf_snprintf`，成功则 `counter[0]++`。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。

### 4. helper_renamed
- **程序**：`tracepoint/syscalls/sys_enter_openat`，用 `bpf_probe_read_user_str` 读 filename，成功则 `counter[0]++`。
- **workload**：3 次 `cat /etc/passwd` → 3 次 openat，且 ctx 中有 filename。
- **validator**：min 3。
- **结论**：合理。

---

## 五、feature（5 个）

### 1. attach_type_unsupported
- **程序**：`kprobe/do_sys_openat2`，每次命中 `counter[0]++`。
- **workload**：3 次 cat → 会触发 openat2/openat。
- **validator**：min 3。
- **结论**：合理。

### 2. btf_unsupported
- **程序**：`tracepoint/syscalls/sys_enter_openat`，BTF/CORE_READ 读 tgid，tgid>0 则 `counter[0]++`。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。

### 3. isa_upgrade_incompatible
- **程序**：`tracepoint/syscalls/sys_enter_openat`，pid>0 则 `counter[0]++`（恒真）。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。

### 4. map_type_unsupported
- **程序**：`tracepoint/syscalls/sys_enter_openat`，使用 ringbuf + array，每次命中 `counter[0]++`。
- **workload**：3 次 cat → 3 次 openat。
- **validator**：min 3。
- **结论**：合理。

### 5. program_type_unsupported
- **程序**：`fentry/__x64_sys_execve`，每次 execve 命中 `counter[0]++`。
- **workload**：3 次 `/bin/echo ... > /dev/null` → 3 次 execve。
- **validator**：min 3。
- **结论**：合理。**注意**：与 kfunc_support 相同，依赖 x86_64 符号名，非 x86_64 需改 section 或单独用例。

---

## 六、建议汇总

1. **field_offset_change**  
   - 设计正确，用于“固定 6.6 offset”的兼容性测试。  
   - 在 6.6 内核 VM 中执行 `scripts/tools/get_task_tgid_offset.py`，用得到的字节偏移更新源码中的 `TASK_TGID_OFFSET`（或你使用的 6.6 专用宏），否则 runtime 会因计数为 0 而失败。

2. **x86_64 相关**  
   - **kfunc_support**、**program_type_unsupported** 使用 `fentry/__x64_sys_execve`，仅在 x86_64 上有效。  
   - 若需在 aarch64 等运行，建议在 meta 或 README 中注明“仅 x86_64”，或为其他架构增加对应 fentry section 的用例。

3. **其余 16 个用例**  
   - workload 触发次数与 validator 的 map/key、min 或 eq 期望一致，未发现设计错误；无需修改 workload 或 validator 逻辑。

---

*检查基于当前 data/ 目录下的 workload.sh、validator.yaml 与各 \*.bpf.c，以及 runtime_tester 的 validator 语义（min / eq）。*
