# 本地漏洞扫描服务（local-vuln-scan-service）

用**本地清单文件 + 本地规则集**模拟软件成分清单（SCA/SBOM）与漏洞数据的扫描服务。
目标：在多种清单格式、异常输入与并发重复提交下，扫描结论都**一致、可复现、可解释、失败可区分**。

- Java 21 + Spring Boot 3.4，无外部数据库 / 消息队列，内存态任务表
- 提交时对清单做**同步校验**：畸形、缺字段、非法版本、格式不可识别一律拒绝（HTTP 400 + 可区分错误码），绝不当成空清单成功
- 规则匹配在固定线程池内异步执行；单条规则出错只隔离上报，不让整个任务静默失败
- 按内容 SHA-256 指纹幂等；规则集版本 = 规则文件内容哈希，提交时固定，规则集更新后历史结论仍可复现

---

## 1. 支持的清单 / SBOM 格式

格式**完全由内容结构嗅探**（不依赖文件名或调用方声明）。统一归一化到
`Manifest(format, sourceHash, List<Component>)`，`Component(ecosystem, name, rawVersion)`。

| 格式 | 识别标志 | 关键规则 |
| --- | --- | --- |
| `INVENTORY_JSON` 本地自定义 JSON | 顶层是对象且含 `components` 数组（无 `bomFormat`） | `components` 必须为数组；每元素必须是含 `ecosystem/name/version` 三个非空字符串的对象 |
| `CYCLONEDX_JSON` CycloneDX 风格 SBOM | `"bomFormat":"CycloneDX"` | 组件可用 `purl`（`pkg:type/ns/name@ver`，支持 maven/npm/pypi/generic），无 purl 时必须显式给 `ecosystem`、`name`、`version` |
| `SPDX_TAG_VALUE` SPDX 标签值 | 首个有效标签为 `SPDXVersion:` | 每个 `PackageName` 开始一个包；版本来自 `ExternalRef: ... PURL pkg:...@ver` 或 `PackageVersion`；无法识别的标签行 / 无冒号行拒绝 |
| `CSV` | 首行表头恰好为 `ecosystem,name,version`（顺序必须一致） | 支持 RFC4180 风格双引号与 `""` 转义；数据行列数不符、引号未闭合拒绝。**只有表头没有数据行是合法空清单** |

- `ecosystem` 取值：`maven` / `npm` / `pypi` / `generic`（SPDX 标签值在没有 purl 时归一为 `generic`）
- 支持 UTF-8 BOM（嗅探与解析前统一剥离）
- 合法的空清单（可识别格式 + 零组件）与“无法识别的内容”严格区分：后者报 `FORMAT_UNRECOGNIZED`

### 拒绝原因码（`ErrorCode`，全部可区分）

| code | 触发条件 | HTTP |
| --- | --- | --- |
| `EMPTY_CONTENT` | null / 空串 / 全空白 | 400 |
| `FORMAT_UNRECOGNIZED` | 内容无法识别为四种格式之一（含非 CycloneDX 的 `bomFormat`、无结构标记的 `{}`、错序列 CSV 表头等） | 400 |
| `MANIFEST_SYNTAX_INVALID` | 已识别格式但语法损坏（坏 JSON、SPDX 无冒号/未知标签、CSV 坏引号/坏表头） | 400 |
| `MANIFEST_MISSING_FIELD` | 必填字段缺失或为空（components、name、version、SPDX 包版本等） | 400 |
| `MANIFEST_ENTRY_MALFORMED` | 条目结构畸形（非对象、列数错、字段类型错、未知 ecosystem、坏 purl 等） | 400 |
| `MANIFEST_VERSION_INVALID` | 版本号不是合法语义化版本（如 `latest`、`01.2.3`） | 400 |
| `RULESET_SYNTAX_INVALID` / `RULESET_MISSING_FIELD` / `RULE_INVALID_VERSION_RANGE` | 规则集加载期错误（启动失败，快速暴露） | — |
| `RULE_MATCH_FAILED` | 单条规则匹配异常（隔离写入 `ruleErrors`，任务仍 COMPLETED） | 200 体内 |
| `SCAN_INTERNAL_ERROR` | 扫描执行期未归类内部错误（任务 FAILED） | 200 体内 |
| `TASK_NOT_FOUND` | scanId 不存在 | 404 |
| `TASK_ALREADY_FINISHED` | 对 COMPLETED / CANCELLED / FAILED 之外允许的状态做非法操作 | 409 |

---

## 2. 版本匹配规则

### 2.1 版本号（SemVer 2.0 优先级，宽松解析）

- 接受 `1`、`1.2`、`1.2.3`，缺段补 0（`2.4` 等价于 `2.4.0`）
- 预发布段 `-alpha.1` 参与优先级；构建元数据 `+xxx` 不参与
- **禁止前导零**：`01.2.3`、`1.02.3` 拒绝；数字预发布标识符同样禁止前导零
- 优先级（SemVer 2.0）：`1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-alpha.beta
  < 1.0.0-beta < 1.0.0-rc.1 < 1.0.0`；数字标识符 < 非数字标识符
- `v1.2.3`、`1.2.x`、`latest` 等非 SemVer 一律拒绝（`MANIFEST_VERSION_INVALID`），不做静默归一猜测

### 2.2 受影响版本区间

- 表达式 = 比较式的**交集**，比较式之间用空白或逗号分隔
- 运算符：`>=` `>` `<=` `<` `=`；裸版本等价于 `=`。例：`>=2.0.0 <2.17.1`、`>=1.2.0,<=1.4.2`
- **边界**：比较在 SemVer 优先级上进行；含等号为闭边界，不含等号为开边界
  - `>=2.0.0 <2.17.1`：恰好包含 `2.0.0`，恰好不包含 `2.17.1`
  - `<=1.2.3`：包含 `1.2.3`，不包含 `1.2.3-0`（预发布优先级更低）
- **预发布门槛（npm 风格，文档化的确定规则）**：候选为预发布版本时，仅当区间里
  **至少有一个严格边界（`>` 或 `<`，不含等号）与候选版本核心三段相同**才可能命中，
  随后仍需满足全部比较式。稳定版本不受门槛影响。

  | 区间 | 候选 | 结果 | 原因 |
  | --- | --- | --- | --- |
  | `>=1.0.0 <2.0.0` | `1.5.0-beta` | 不命中 | 没有任何严格边界落在 1.5.0 |
  | `>=1.0.0 <2.0.0` | `2.0.0-alpha` | **命中** | 与严格上界同核心，且 `2.0.0-alpha < 2.0.0` |
  | `>=1.5.0 <2.0.0` | `1.5.0-rc1` | 不命中 | 同核心的是闭下界（不发放门槛），且 `rc1 < 1.5.0` |
  | `>1.5.0-beta <=2.0.0` | `1.5.0-rc1` | **命中** | 与严格下界同核心，且 `rc1 > 1.5.0-beta` |

### 2.3 多规则命中的确定性与可解释性

- 组件按清单顺序、规则按 id 排序遍历；结论排序固定为
  **(组件在清单中的位置升序, 严重度 rank 降序, 规则 id 升序)**，相同输入永远得到相同结论
- 每条 `ScanFinding` 带 `rationale`：规则 id、区间表达式、候选版本、是否预发布、
  采用的预发布门槛、比较结果、严重度与描述
- 单条规则（区间解析 / 比较）抛异常 → 捕获为 `RuleError(ruleId, RULE_MATCH_FAILED, message)`，
  其余规则继续；任务仍为 COMPLETED，错误体出现在 `ruleErrors` 中

---

## 3. 规则集与历史可复现

- 规则文件：`src/main/resources/rules/rules.json`，启动时加载一次并缓存
- `ruleSet.version` = 文件内容 SHA-256 的前 12 位，`contentHash` 为完整哈希；
  文件不变版本不变，更新文件后重启即换版本
- 规则在加载期预解析区间：非法区间（`RULE_INVALID_VERSION_RANGE`）、缺字段、
  未知枚举、重复 id 直接使启动失败，不把错误延迟到扫描时
- **每个扫描任务在提交时固定当时的规则集版本**，结果体始终带 `ruleSetVersion`；
  规则集更新后，旧任务的结果仍可按其记录的版本解释复现（重试例外：重试显式采用当前规则集，
  结果体内版本相应更新，scanId 与制品指纹不变）

规则文件结构：

```json
{
  "generatedAt": "2026-10-01T00:00:00Z",
  "rules": [
    {"id": "CVE-2022-0001", "ecosystem": "maven", "packageName": "log4j-core",
     "range": ">=2.0.0 <2.17.1", "severity": "CRITICAL", "description": "Log4Shell 远程代码执行"}
  ]
}
```

---

## 4. 扫描状态与并发语义

### 4.1 生命周期

```
PENDING ──worker领取──▶ RUNNING ──┬──▶ COMPLETED   （findings + ruleErrors 落定）
                                  ├──▶ FAILED      （errorCode + errorMessage；可 retry）
                                  └──▶ CANCELLED   （不写任何结论；终态）
FAILED ──retry──▶ PENDING（同一 scanId，旧错误/旧结论整体清除后重新执行）
```

- `PENDING/RUNNING` 可取消；`COMPLETED/CANCELLED/FAILED` 上再取消报 `TASK_ALREADY_FINISHED`(409)
- 仅 `FAILED` 可重试；工作线程在落结论前再次检查取消标记，被取消任务绝不残留半成品结论
- 提交即同步解析：畸形输入在 HTTP 400 阶段被拒绝，**不创建任务**；
  FAILED 仅覆盖“通过校验后执行期”的故障（内部错误等）

### 4.2 并发与幂等

- 幂等键 = 清单原文 SHA-256；同指纹重复提交（串行或并发）返回**同一个 scanId 与同一结论**。
  登记在 `ConcurrentHashMap.compute` 内原子完成（同 key 串行 + 先占指纹再异步执行），
  32 路并发相同提交只产生 1 个任务、2 条结论，不重复不丢失
- 已取消任务仍占用幂等键：同指纹再次提交返回该 CANCELLED 任务，不会悄悄复活
- 不同指纹产生不同任务（互不阻塞，固定 4 worker 线程池）

---

## 5. HTTP API

`Content-Type: application/json`

| 方法与路径 | 说明 | 成功状态 |
| --- | --- | --- |
| `POST /api/scans` | body `{"content": "<清单原文>"}`；同步校验 + 异步扫描；同指纹幂等 | 202 |
| `GET /api/scans/{scanId}` | 查询当前结果快照（任何状态都可查） | 200 |
| `POST /api/scans/{scanId}/cancel` | 取消 PENDING/RUNNING 任务 | 200 |
| `POST /api/scans/{scanId}/retry` | 重试 FAILED 任务（同一 scanId，采用当前规则集） | 202 |

错误响应统一为 `{"code": "<ERROR_CODE>", "message": "<可读原因>"}`，状态码 400 / 404 / 409 / 500。

结果体 `ScanResult` 关键字段：`scanId, artifactHash, ruleSetVersion, status,
errorCode, errorMessage, manifestFormat, componentCount, findings[], ruleErrors[],
createdAt, startedAt, finishedAt`。

### curl 示例

```bash
# 正常提交
curl -s -X POST localhost:8080/api/scans -H 'Content-Type: application/json' \
  -d '{"content":"{\"components\":[{\"ecosystem\":\"maven\",\"name\":\"log4j-core\",\"version\":\"2.14.0\"}]}"}'

# 畸形清单 -> 400 FORMAT_UNRECOGNIZED / MANIFEST_SYNTAX_INVALID ...
curl -i -X POST localhost:8080/api/scans -H 'Content-Type: application/json' \
  -d '{"content":"name: not-a-known-format"}'

# 查询 / 取消 / 重试
curl -s localhost:8080/api/scans/$SCAN_ID
curl -s -X POST localhost:8080/api/scans/$SCAN_ID/cancel
curl -s -X POST localhost:8080/api/scans/$SCAN_ID/retry
```

---

## 6. 验证方法

要求 JDK 21+、Maven 3.9+（依赖可离线使用时加 `-o`）。

```bash
mvn clean test
```

测试清单（共 26 个用例，全部通过）：

| 测试类 | 覆盖点 |
| --- | --- |
| `VersionSemanticsTest` | SemVer 优先级、开闭边界、前导零/缺段拒绝、预发布门槛四种组合、非法区间 |
| `ManifestParserTest` | 四种格式归一化、合法空清单、BOM、各格式畸形条目与可区分错误码归类 |
| `RuleRepositoryTest` | 规则排序、版本=哈希前缀、缓存、非法区间/缺字段/坏枚举/重复 id 拒绝 |
| `RuleMatcherServiceTest` | 边界命中、多命中确定性排序、结论可复现、预发布规则、坏规则隔离 + `RULE_MATCH_FAILED` |
| `ScanConcurrencyTest` | 串行/32 路并发重复提交幂等、排队期取消无残留、失败→重试成功结论替换、终态操作 409、404 |
| `ScanApiIntegrationTest` | 真实 HTTP：202/200/400/404/409、错误码、幂等、历史结论复现 |
| `ApplicationTests` | Spring 上下文装配（规则集启动加载） |

单测日志同时输出到 stdout 与 SLF4F，每个关键用例都打印
**输入、归一化结果、判定依据（区间/边界/预发布门槛）或拒绝归类**，例如：

```
[清单输入] invalid-version => {"components":[{"ecosystem":"maven","name":"x","version":"latest"}]}
[拒绝归类] invalid-version => code=MANIFEST_VERSION_INVALID, reason=... 'latest' 不是合法语义化版本
[判定依据] log4j-core@2.14.0 => CVE-2022-0001(CRITICAL) | 规则 CVE-2022-0001 的受影响区间 [>=2.0.0 <2.17.1] 包含版本 2.14.0（稳定版本）；CRITICAL：Log4Shell ...
[并发提交] 32 个相同提交产生的 scanId 集合=[...]
```

示例清单位于 `src/test/resources/manifests/`（4 种合法格式 + 2 个畸形样例）。

---

## 7. 包结构

```
model/      统一领域模型与枚举（Component/Manifest/VulnerabilityRule/ScanResult/ErrorCode/ScanStatus...）
version/    SemanticVersion、VersionRange（区间语法 + 预发布门槛）
parser/     FormatDetector + 四格式解析器 + ManifestParserService + ParsingSupport
rules/      RuleRepository（加载/版本/校验）、RuleMatcherService（匹配/隔离/排序）
scan/       ScanTask（锁内 CAS 状态迁移）、ScanTaskService（幂等/线程池/取消/重试）
web/        REST 控制器与全局异常映射
util/       SHA-256
```
