package com.github.lisama569.localvulnscanservicejava.manifest;

import com.github.lisama569.localvulnscanservicejava.model.ManifestError;

import java.util.List;

/** 清单被拒绝时抛出，携带全部可区分错误。 */
public class ManifestParseException extends RuntimeException {

    private final List<ManifestError> errors;

    public ManifestParseException(List<ManifestError> errors) {
        super(errors.isEmpty() ? "manifest rejected" : errors.get(0).message());
        this.errors = List.copyOf(errors);
    }

    public List<ManifestError> errors() {
        return errors;
    }
}
