package io.ksno.tennisBooking.security.auditing;

import io.ksno.tennisBooking.security.user.User;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * This class is used to get the current auditor (user) for auditing purposes.
 * It implements the AuditorAware interface and overrides the getCurrentAuditor method.
 * The method retrieves the current authentication from the SecurityContextHolder
 * and returns the user ID if the user is authenticated.
 *
 * W metodzie z main mamy adnotacje @EnabledJpaAuditing(auditorAwareRef = "applicationAuditAware")
 * dięki temu możemy korzystać z adnotacji @CreatedBy i @LastModifiedBy w encjach
 */
public class ApplicationAuditAware implements AuditorAware<Integer> {
    @Override
    public Optional<Integer> getCurrentAuditor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty();
        }

        User userPrincipal = (User) authentication.getPrincipal();
        return Optional.ofNullable(userPrincipal.getId());
    }
}
