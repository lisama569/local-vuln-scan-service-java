package com.github.lisama569.localvulnscanservicejava.scan;

import com.github.lisama569.localvulnscanservicejava.manifest.ManifestParseException;
import com.github.lisama569.localvulnscanservicejava.manifest.ManifestParserRegistry;
import com.github.lisama569.localvulnscanservicejava.model.Component;
import com.github.lisama569.localvulnscanservicejava.model.ManifestError;
import com.github.lisama569.localvulnscanservicejava.model.ParsedManifest;
import com.github.lisama569.localvulnscanservicejava.rules.MatchEngine;
import com.github.lisama569.localvulnscanservicejava.rules.RuleEvaluationException;
import com.github.lisama569.localvulnscanservicejava.rules.RuleSet;
import com.github.lisama569.localvulnscanservicejava.rules.RuleSetRepository;
import com.github.lisama569.localvulnscanservicejava.version.InvalidVersionException;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 扫描任务服务。
 * <ul>
 *   <li>幂等：以制品内容 SHA-256 为键，重复/并发提交返回同一任务。</li>
 *   <li>并发：固定线程池异步执行，状态迁移由 ScanTask 守护。</li>
 *   <li>隔离：单条规则/单个组件出错归一化为 ScanError，不让整个任务静默失败。</li>
 *   <li>可复现：报告记录 rulesetVersion 与 artifactDigest。</li>
 * </ul>
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ManifestParserRegistry parserRegistry;
    private final RuleSetRepository ruleSetRepository;
    private final MatchEngine matchEngine;

    private final Map<String, ScanTask> tasksById = new ConcurrentHashMap<>();
    private final Map<String, String> taskIdByDigest = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    public ScanService(ManifestParserRegistry parserRegistry,
                       RuleSetRepository ruleSetRepository,
                       MatchEngine matchEngine) {
        this.parserRegistry = parserRegistry;
        this.ruleSetRepository = ruleSetRepository;
        this.matchEngine = matchEngine;
    }

    /** 提交扫描，返回任务 id；同一制品内容重复提交返回已有任务 id。 */
    public String submit(String manifestContent) {
        String digest = sha256(manifestContent);
        String taskId = taskIdByDigest.computeIfAbsent(digest, d -> {
            String id = UUID.randomUUID().toString();
            ScanTask task = new ScanTask(id, d, manifestContent);
            tasksById.put(id, task);
            executor.submit(() -> execute(task));
            log.info("scan submitted: taskId={} digest={}", id, d);
            return id;
        });
        return taskId;
    }

    public Optional<ScanTask> get(String taskId) {
        return Optional.ofNullable(tasksById.get(taskId));
    }

    /** 取消任务；已完成/已失败/已取消任务返回 false。 */
    public boolean cancel(String taskId) {
        ScanTask task = tasksById.get(taskId);
        if (task == null) {
            return false;
        }
        boolean ok = task.requestCancel();
        if (ok) {
            log.info("scan cancel requested: taskId={} status={}", taskId, task.status());
        }
        return ok;
    }

    private void execute(ScanTask task) {
        if (!task.markRunning()) {
            return; // 已在提交后被取消
        }
        RuleSet ruleSet = ruleSetRepository.current();
        String rulesetVersion = ruleSet.rulesetVersion();
        try {
            ParsedManifest manifest;
            try {
                manifest = parserRegistry.parse(task.manifestContent());
            } catch (ManifestParseException e) {
                // 清单被拒绝：归一化错误写入报告，任务标记 FAILED
                List<ScanError> errors = new ArrayList<>();
                for (ManifestError me : e.errors()) {
                    errors.add(new ScanError(ScanErrorReason.MANIFEST_REJECTED, null,
                            me.reason() + " at entry " + me.entryIndex() + ": " + me.message()));
                }
                task.fail(new ScanReport(task.taskId(), task.artifactDigest(),
                        "unparsed", rulesetVersion, List.of(), List.copyOf(errors)));
                log.warn("scan failed (manifest rejected): taskId={} errors={}", task.taskId(), errors);
                return;
            }
            List<Finding> findings = new ArrayList<>();
            List<ScanError> errors = new ArrayList<>();
            for (Component component : manifest.components()) {
                if (task.cancelIfRequested()) {
                    log.info("scan cancelled: taskId={}", task.taskId());
                    return; // 取消的任务不写报告，避免半截结论
                }
                MatchEngine.MatchOutcome outcome;
                try {
                    outcome = matchEngine.match(ruleSet, component);
                } catch (InvalidVersionException e) {
                    errors.add(new ScanError(ScanErrorReason.COMPONENT_VERSION_INVALID, null,
                            component.name() + "@" + component.version() + ": " + e.getMessage()));
                    continue;
                }
                for (MatchEngine.RuleMatch m : outcome.matches()) {
                    findings.add(new Finding(m.rule().ruleId(), m.rule().vulnId(),
                            m.rule().severity(), component, m.explanation()));
                }
                for (RuleEvaluationException ree : outcome.errors()) {
                    errors.add(new ScanError(ScanErrorReason.RULE_EVALUATION_FAILED,
                            ree.ruleId(), ree.getMessage()));
                }
            }
            ScanReport report = new ScanReport(task.taskId(), task.artifactDigest(),
                    manifest.format(), rulesetVersion,
                    List.copyOf(findings), List.copyOf(errors));
            if (!task.complete(report)) {
                log.info("scan finished but task no longer running (cancelled): taskId={}", task.taskId());
                return;
            }
            log.info("scan completed: taskId={} findings={} errors={}",
                    task.taskId(), findings.size(), errors.size());
        } catch (Exception e) {
            // 未预期错误：归一化为 INTERNAL_ERROR，不静默
            log.error("scan internal error: taskId={}", task.taskId(), e);
            task.fail(new ScanReport(task.taskId(), task.artifactDigest(),
                    "unknown", rulesetVersion, List.of(),
                    List.of(new ScanError(ScanErrorReason.INTERNAL_ERROR, null, e.toString()))));
        }
    }

    private static String sha256(String content) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }
}
