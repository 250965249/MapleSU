package dev.maplesu.installer;

import java.io.IOException;

/**
 * An {@link IOException} that always carries the contract failure code
 * (02-switch-contract §4.3.1 / §4.5 / §5.6). The message starts with the code so callers that only
 * log the message stay diagnosable; {@link #code} is authoritative.
 */
public final class SwitchFailure extends IOException {
    public final String code;
    public final String detail;

    public SwitchFailure(String code, String detail) {
        super(detail == null || detail.isEmpty() ? code : code + ": " + detail);
        this.code = code;
        this.detail = detail == null ? "" : detail;
    }

    public SwitchFailure(String code, String detail, Throwable cause) {
        super(detail == null || detail.isEmpty() ? code : code + ": " + detail, cause);
        this.code = code;
        this.detail = detail == null ? "" : detail;
    }

    /** Wraps any other failure while preserving the contract code of the outer layer. */
    public static SwitchFailure of(String code, String detail, Throwable cause) {
        return new SwitchFailure(code, detail == null ? "" : detail, cause);
    }
}
