package com.authservice.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

@Component
@Profile("dev")
public class RequestLoggingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger("HTTP");

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        long start = System.currentTimeMillis();
        ContentCachingResponseWrapper wrapper = new ContentCachingResponseWrapper(response);
        try {
            filterChain.doFilter(request, wrapper);
        } finally {
            long ms = System.currentTimeMillis() - start;
            String detail = "";
            if (wrapper.getStatus() >= 400) {
                byte[] content = wrapper.getContentAsByteArray();
                if (content.length > 0) {
                    detail = " body=" + new String(content, StandardCharsets.UTF_8);
                }
            }
            log.info("{} {} -> {} ({}ms) remote={}{}",
                    request.getMethod(), request.getRequestURI(),
                    wrapper.getStatus(), ms, request.getRemoteAddr(), detail);
            wrapper.copyBodyToResponse();
        }
    }
}
