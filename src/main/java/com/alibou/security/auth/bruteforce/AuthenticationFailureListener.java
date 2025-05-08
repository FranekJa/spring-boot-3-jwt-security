package com.alibou.security.auth.bruteforce;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class AuthenticationFailureListener
        implements ApplicationListener<AuthenticationFailureBadCredentialsEvent> {

    public static final int MAX_ATTEMPT = 5;

    private final IpAttemptRepository ipAttemptRepository;
    private final HttpServletRequest request;

    public AuthenticationFailureListener(IpAttemptRepository ipAttemptRepository,
                                         HttpServletRequest request) {
        this.ipAttemptRepository = ipAttemptRepository;
        this.request = request;
    }

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        String ip = getClientIP();
        IpAttempt attempt = ipAttemptRepository.findById(ip)
                .orElse(IpAttempt.builder().ip(ip).build());

        int newCount = attempt.getFailAttempts() + 1;
        attempt.setFailAttempts(newCount);

        if (newCount >= MAX_ATTEMPT) {
            attempt.setLockedAt(LocalDateTime.now());
        }
        ipAttemptRepository.save(attempt);
    }

    private String getClientIP() {
        String xfHdr = request.getHeader("X-Forwarded-For");
        if (xfHdr != null && !xfHdr.isBlank()) {
            return xfHdr.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}