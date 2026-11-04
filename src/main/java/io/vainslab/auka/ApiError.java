package io.vainslab.auka;

import java.util.Map;

/** Rendered as {"error": code, ...extra} with the given HTTP status. */
final class ApiError extends RuntimeException {
    final int status;
    final String code;
    final Map<String, Object> extra;

    ApiError(int status, String code) {
        this(status, code, Map.of());
    }

    ApiError(int status, String code, Map<String, Object> extra) {
        super(code, null, false, false);
        this.status = status;
        this.code = code;
        this.extra = extra;
    }
}
