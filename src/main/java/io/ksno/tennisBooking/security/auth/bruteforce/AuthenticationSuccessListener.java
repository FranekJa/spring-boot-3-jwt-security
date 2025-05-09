package io.ksno.tennisBooking.security.auth.bruteforce;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessListener
        implements ApplicationListener<AuthenticationSuccessEvent> {

    private final IpAttemptRepository ipAttemptRepository;
    private final HttpServletRequest request;

    public AuthenticationSuccessListener(IpAttemptRepository ipAttemptRepository,
                                         HttpServletRequest request) {
        this.ipAttemptRepository = ipAttemptRepository;
        this.request = request;
    }

    @Override
    public void onApplicationEvent(AuthenticationSuccessEvent event) {
        String ip = getClientIP();
        ipAttemptRepository.findById(ip).ifPresent(attempt -> {
            attempt.setFailAttempts(0);
            attempt.setLockedAt(null);
            ipAttemptRepository.save(attempt);
        });
        //ipAttemptRepository.deleteById(ip);
    }

    private String getClientIP() {
        String xfHdr = request.getHeader("X-Forwarded-For");
        if (xfHdr != null && !xfHdr.isBlank()) {
            return xfHdr.split(",")[0];
        }
        return request.getRemoteAddr();
    }
}