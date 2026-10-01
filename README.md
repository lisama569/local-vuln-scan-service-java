# local-vuln-scan-service-java

本地漏洞扫描服务：用本地清单文件与本地规则集模拟软件成分分析（SCA）与漏洞匹配，
保证不同格式、异常输入与并发提交下的扫描结论一致、可解释、可复现。

## 运行

```bash
mvn spring-boot:run          # 启动服务（application.properties 中 server.port=0 表示随机端口，可改为固定端口）
mvn test                     # 运行全部测试
```

## REST 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/scans` | 提交清单（请求体为原始清单文本），幂等返回 `{taskId, status}` |
| GET | `/api/scans/{taskId}` | 查询任务状态与报告 |
| POST | `/api/scans/{taskId}/cancel` | 取消任务 |
| GET | `/api/rules` | 查看当前规则集（含 `rulesetVersion`） |

## 支持的清单格式

格式按内容自动探测，归一到统一模型 `Component(ecosystem, name, version)`：

| 格式 | 探测特征 | 字段来源 |
| --- | --- | --- |
| `cyclonedx-json` | `"bomFormat":"CycloneDX"` | `components[]` 的 `name`/`version`，生态取自 `purl`（`pkg:<type>/...`） |
| `spdx-json` | `"spdxVersion":"SPDX-..."` | `packages[]` 的 `name`/`versionInfo`，生态取自 `externalRefs` 中的 purl |
| `csv` | 首行表头 `ecosystem,name,version` | 每行三列 |

### 拒绝语义（可区分原因）

任何畸形输入都不会被静默跳过，也不会把无法识别的内容当成空清单成功。
清单被拒绝时任务进入 `FAILED`，报告中携带归一化错误，原因可区分：

| 原因 | 含义 |
| --- | --- |
| `UNRECOGNIZED_FORMAT` | 内容无法识别为任何支持的格式（含空内容、无格式特征的 JSON） |
| `MALFORMED_DOCUMENT` | 文档整体畸形（JSON 无法解析、`components` 不是数组、CSV 无表头） |
| `MALFORMED_ENTRY` | 单条条目结构畸形（如 CSV 列数不对） |
| `MISSING_FIELD` | 必填字段缺失（name/version/ecosystem） |
| `INVALID_VERSION` | 版本字符串无法解析 |

同一清单中的多条错误会全部收集后一次性上报（`entryIndex` 定位条目）。

## 版本匹配规则

- 版本解析：宽松 semver，`主[.次[.补丁]][-预发布][+构建]`；缺省段按 0，构建元数据不参与比较。
- 预发布语义：严格按 semver 排序，无特殊豁免——`2.0.0-rc1 < 2.0.0`，
  因此 `<2.0.0` **包含** `2.0.0-rc1`，`>=2.0.0` **不包含** `2.0.0-rc1`。
- 区间写法：
  - 精确版本：`1.2.3`（或 `[1.2.3]`）
  - 比较表达式（合取）：`>=2.0.0,<2.15.0`
  - 区间记号：`[2.15.0,2.16.0)`、`(,2.0]`、`[,2.0)`（空端点表示无界）
- 非法区间（如 `[1.0,2.0`、`~1.2.3`）抛出 `InvalidVersionException`，
  出现在规则中时该规则被隔离为 `RULE_EVALUATION_FAILED`，不影响其他规则。

### 多规则命中的确定性

同一组件命中多条规则时，结论按 **(严重度降序, ruleId 升序)** 排序，
重复执行结果一致；每条命中都附带 `explanation`（版本如何落入区间）。

### 结论可复现

扫描报告记录 `rulesetVersion` 与 `artifactDigest`（清单内容 SHA-256）。
规则集更新通过 `RuleSetRepository.updateCurrent` 进行，历史版本快照
（`rules/ruleset-<version>.json`）保留在缓存中，可按版本重放历史结论。

## 扫描状态与并发语义

生命周期：`PENDING -> RUNNING -> COMPLETED | FAILED | CANCELLED`。

- **幂等提交**：以清单内容 SHA-256 为键，同一制品重复/并发提交返回同一 `taskId`，
  不会产生重复任务或重复结论。
- **并发执行**：固定线程池异步执行；状态迁移由 `ScanTask` 的 synchronized 守护，
  取消与完成不会交错。
- **取消**：`PENDING` 任务直接取消；`RUNNING` 任务在组件间检查点协作式取消。
  取消的任务不写报告，避免半截结论；终态任务取消返回 `false`。
- **失败**：清单被拒绝 → `FAILED` + `MANIFEST_REJECTED` 错误明细；
  单条规则出错 → `RULE_EVALUATION_FAILED`（任务仍 `COMPLETED`）；
  组件版本非法 → `COMPONENT_VERSION_INVALID`；未预期异常 → `INTERNAL_ERROR`。
  任何错误都归一化上报，不会静默失败。

## 验证方法

```bash
mvn test
```

| 测试类 | 覆盖点 |
| --- | --- |
| `VersionSemanticsTest` | 版本混淆、预发布排序、区间边界、非法区间 |
| `ManifestParserTest` | 三种格式归一、畸形清单、字段缺失、非法版本、无法识别格式 |
| `MatchEngineTest` | 多规则命中确定性排序、单规则出错隔离、预发布边界判定依据 |
| `ScanServiceConcurrencyTest` | 16 线程并发重复提交幂等、取消语义、失败归一化、结论无重复 |

单测日志会打印 **输入、归一化结果与判定依据**（如 `输入: range=... version=... | 判定: contains=...`），
可直接从日志核对每条结论的推理过程。

手工验证示例：

```bash
# 提交 CycloneDX 清单（假设服务监听 8080）
curl -s -X POST localhost:8080/api/scans -H 'Content-Type: application/json' -d '{
  "bomFormat":"CycloneDX",
  "components":[{"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/x/log4j-core@2.14.1"}]
}'
# 查询结果
curl -s localhost:8080/api/scans/<taskId>
```
