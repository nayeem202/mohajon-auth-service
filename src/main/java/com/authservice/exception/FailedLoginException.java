package com.authservice.exception;

import org.springframework.http.HttpStatus;

/** A rejected password whose failed-attempt audit must still be committed. */
public final class FailedLoginException extends ApiException {
    public FailedLoginException() {
        super(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "The email or password is incorrect.");
    }
}
