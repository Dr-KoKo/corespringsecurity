package io.security.corespringsecurity.config.security.manager;

import io.security.corespringsecurity.config.security.service.SecurityResourceService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

public class PermitAllAuthorizationManager extends CustomAuthorizationManager {
    private final static List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();

    public PermitAllAuthorizationManager(SecurityResourceService securityResourceService, String... permitAllResources) {
        super(securityResourceService);
        for (String resource : permitAllResources) {
            permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
        }
    }

    @Override
    public void verify(Supplier<Authentication> authentication, HttpServletRequest request) {
        boolean permit = false;
        for (RequestMatcher requestMatcher : permitAllRequestMatchers) {
            if (requestMatcher.matches(request)) {
                permit = true;
                break;
            }
        }
        if (permit) {
            return;
        }
        super.verify(authentication, request);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
        boolean permit = false;
        for (RequestMatcher requestMatcher : permitAllRequestMatchers) {
            if (requestMatcher.matches(request)) {
                permit = true;
                break;
            }
        }
        if (permit) {
            return new AuthorizationDecision(true);
        }
        return super.check(authentication, request);
    }
}
