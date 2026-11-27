<!-- Shheeel By Zgod -->

The shared rules are canonical in
`~/.claude/projects/-root-droid-kernel/memory/MEMORY.md` (`~/.memory/` and the
qoder copy are symlinks to it); the workspace state is
`/root/droid-kernel/docs/STATUS.md`
You must read them before any work

<!-- Tag by Zgod, Project manual memory -->

# AGENTS.md — droid-lkm-ins

Head-only LKM loader/remover: binds undefined symbols from `/proc/kallsyms`,
adapts `struct module` layout from BTF, rewrites vermagic once, then calls
`init_module(2)`. Replaces ksud/apd's load/unload only.

## 派发 Action 前的强制本地检查

**规则：没有逐条做完并贴出输出，不许派发。** 未写进提示词的检查等于没做。

1. `make test` 全绿（`lkm_bind_test` + `lkm_insmod_test` + `lkmctl_cli_test.sh`），
   `-Werror` 下无警告。贴尾部输出。
2. **改动了 `Makefile`**：确认 `make test` / `make android` 两个入口都仍然可用，
   且新增目标名与调用处一致。
3. **新增源文件**：确认它被 `Makefile` 的编译行**和**测试目标同时引用，
   不能只加一处（`grep -c <名字> Makefile` 期望等于引用处数量）。
4. **引用脚本**：路径存在、由 `sh`/`bash` 调用（不依赖可执行位）。
5. **产物形态断言**：`make android` 之后要 `file` + `readelf -l | grep INTERP` +
   `readelf -d` 三条一起贴，证明「aarch64 + 无 interpreter + 无动态段」。
6. **派发前 headSha 断言**（若引入了 CI）：`gh run view <run> --json headSha`
   必须包含被测 commit；本地未 push 不许派。
7. **只在功能完成点派发**：一次变更集一次验证；不许一小步一 Action。
8. 失败：先本地定位，修好后最多重试 1 次；不许连发、不许改断言凑绿。

## 功能测试的标准（load/unload 不算测试）

「能加载」不算验证。必须验：

- 适配后的 `.ko` 在**布局不同**的内核上完成真实 `init_module(2)`
- 绑定符号计数与 `dmesg` 无 `Unknown symbol`
- `lsmod` 可见、`rmmod` 后无残留；`[permanent]` 单独记录
- 客户端二进制在目标平台**实跑**（Android bionic 上跑过，才算 bionic 可用）

合成布局差只能证明代码路径，不能证明跨 KMI 能力；用真跨版本构建的模块才算数。

## 状态维护（每步做，不攒到最后）

| 变化 | 更新 |
|---|---|
| 行为 / 参数 / 判定 | `README.md` 对应段落 |
| 新增或删除文件、命令 | `README.md` §Usage / Status |
| 验证结果 | `docs/evidence/<topic>.md`（命令原文、`file`/`readelf` 原文、结论） |

`README.md` 的 `## Status` 必须始终同时有「已验证」与「Not verified」两节。

## Hard constraints

- 不本地安装工具链；本机只能产出静态 aarch64（非 bionic），bionic 必须走 CI
- 不伪造结果；不许把「ELF 形态正确」写成「能在设备运行」
- 不 `--force` 强行加载；布局无法适配时默认拒绝
- 不 reboot 设备；panic 只取当前日志
- Action 限额：3 小时内 ≤9 次、单次 ≤30min

## 读源码要落地

读到内核/上游源码并据此做判断时，先把结论写进 `docs/evidence/` 或 `docs/notes/`：
**语义 + `文件:行号` + 为什么这样决定**。只留在对话里等于没做——下一个人得重读同样的代码。
