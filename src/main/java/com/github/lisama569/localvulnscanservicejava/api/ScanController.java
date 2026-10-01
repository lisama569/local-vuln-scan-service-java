package com.github.lisama569.localvulnscanservicejava.api;

import com.github.lisama569.localvulnscanservicejava.rules.RuleSet;
import com.github.lisama569.localvulnscanservicejava.rules.RuleSetRepository;
import com.github.lisama569.localvulnscanservicejava.scan.ScanReport;
import com.github.lisama569.localvulnscanservicejava.scan.ScanService;
import com.github.lisama569.localvulnscanservicejava.scan.ScanStatus;
import com.github.lisama569.localvulnscanservicejava.scan.ScanTask;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** 扫描 REST 接口。 */
@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanService scanService;
    private final RuleSetRepository ruleSetRepository;

    public ScanController(ScanService scanService, RuleSetRepository ruleSetRepository) {
        this.scanService = scanService;
        this.ruleSetRepository = ruleSetRepository;
    }

    /** 提交清单（请求体为原始清单文本），幂等返回任务 id。 */
    @PostMapping(value = "/scans", consumes = {"text/plain", "application/json", "text/csv", "*/*"})
    public Map<String, String> submit(@RequestBody String manifestContent) {
        String taskId = scanService.submit(manifestContent);
        ScanStatus status = scanService.get(taskId).map(ScanTask::status).orElse(ScanStatus.PENDING);
        return Map.of("taskId", taskId, "status", status.name());
    }

    /** 查询任务状态与报告。 */
    @GetMapping("/scans/{taskId}")
    public ResponseEntity<?> get(@PathVariable String taskId) {
        return scanService.get(taskId)
                .<ResponseEntity<?>>map(task -> ResponseEntity.ok(new TaskView(
                        task.taskId(), task.artifactDigest(), task.status().name(),
                        task.createdAt().toString(), task.report())))
                .orElseGet(() -> ResponseEntity.status(404)
                        .body(Map.of("error", "task not found: " + taskId)));
    }

    /** 取消任务。 */
    @PostMapping("/scans/{taskId}/cancel")
    public ResponseEntity<?> cancel(@PathVariable String taskId) {
        boolean cancelled = scanService.cancel(taskId);
        if (!cancelled && scanService.get(taskId).isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("error", "task not found: " + taskId));
        }
        return ResponseEntity.ok(Map.of("taskId", taskId, "cancelled", String.valueOf(cancelled)));
    }

    /** 当前规则集（含版本，供结论复现核对）。 */
    @GetMapping("/rules")
    public RuleSet rules() {
        return ruleSetRepository.current();
    }

    /** 任务视图。 */
    public record TaskView(String taskId, String artifactDigest, String status,
                           String createdAt, ScanReport report) {
    }
}
