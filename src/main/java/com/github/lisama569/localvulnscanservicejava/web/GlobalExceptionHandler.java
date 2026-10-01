package com.github.lisama569.localvulnscanservicejava.web;

import com.github.lisama569.localvulnscanservicejava.model.ErrorCode;
import com.github.lisama569.localvulnscanservicejava.parser.ManifestParseException;
import com.github.lisama569.localvulnscanservicejava.scan.ScanNotFoundException;
import com.github.lisama569.localvulnscanservicejava.scan.ScanStateConflictException;
import com.github.lisama569.localvulnscanservicejava.web.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 把领域异常映射成带可区分 code 的 HTTP 响应；任何异常都不返回 200 空成功。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(ManifestParseException.class)
    public ResponseEntity<ErrorResponse> handleManifest(ManifestParseException ex) {
        log.warn("清单被拒绝: code={}, message={}", ex.code(), ex.getMessage());
        return badRequest(ex.code(), ex.getMessage());
    }

    @ExceptionHandler(ScanNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(ScanNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse(ErrorCode.TASK_NOT_FOUND.name(), ex.getMessage()));
    }

    @ExceptionHandler(ScanStateConflictException.class)
    public ResponseEntity<ErrorResponse> handleConflict(ScanStateConflictException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new ErrorResponse(ex.code().name(), ex.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        return badRequest(ErrorCode.MANIFEST_SYNTAX_INVALID,
                "请求体不是合法 JSON，或无法读取: " + ex.getMostSpecificCause().getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOther(Exception ex) {
        log.error("未归类异常", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("INTERNAL_ERROR",
                        "服务内部错误: " + ex.getClass().getSimpleName()));
    }

    private static ResponseEntity<ErrorResponse> badRequest(ErrorCode code, String message) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(code.name(), message));
    }
}
