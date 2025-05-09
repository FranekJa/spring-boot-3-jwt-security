package io.ksno.tennisBooking.security.auth.bruteforce;

import io.ksno.tennisBooking.security.config.jwt.JwtService;
import io.ksno.tennisBooking.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.LocalDateTime;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class IpBlockFilter extends OncePerRequestFilter {

    private static final int LOCK_MINUTES = 15;

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;
    @Autowired
    private final IpAttemptRepository ipAttemptRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        if (request.getServletPath().contains("/api/v1/auth/authenticate")) {
            String ip = getClientIP(request);
            IpAttempt attempt = ipAttemptRepository.findById(ip).orElse(null);
            if (attempt != null && attempt.getLockedAt() != null) {
                LocalDateTime unlockAt = attempt.getLockedAt().plusMinutes(LOCK_MINUTES);
                if (unlockAt.isAfter(LocalDateTime.now())) {
                    response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                    response.getWriter().write("IP blocked until " + unlockAt);
                    return;
                }
            }
        }
        filterChain.doFilter(request, response);
    }

    private String getClientIP(HttpServletRequest req) {
        String xf = req.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0];
        }
        return req.getRemoteAddr();
    }
}
