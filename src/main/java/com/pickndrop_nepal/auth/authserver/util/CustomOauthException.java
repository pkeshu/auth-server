package com.pickndrop_nepal.auth.authserver.util;

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;

public class CustomOauthException extends OAuth2Exception {
    public CustomOauthException(String msg, Throwable t) {
        super(msg, t);
    }

    public CustomOauthException(String msg) {
        super(msg);
    }
}
