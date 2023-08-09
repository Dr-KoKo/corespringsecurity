package io.security.corespringsecurity.config.security.manager;

import io.security.corespringsecurity.config.security.service.SecurityResourceService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

@Component
public class CustomAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    private static LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

    public CustomAuthorizationManager(SecurityResourceService securityResourceService) {
        CustomAuthorizationManager.requestMap = securityResourceService.getResourceList();
    }

    @Override
    public void verify(Supplier<Authentication> authentication, HttpServletRequest request) {
        AuthorizationManager.super.verify(authentication, request);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> requestMatcherListEntry : requestMap.entrySet()) {
            RequestMatcher matcher = requestMatcherListEntry.getKey();
            MatchResult matchResult = matcher.matcher(request);

            if (matchResult.isMatch()) {
                return checkInternal(authentication.get(), requestMatcherListEntry.getValue());
            }
        }
        return null;
    }

    private AuthorizationDecision checkInternal(Authentication authentication, List<ConfigAttribute> authority) {
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        List<String> authList = authority.stream().map(ConfigAttribute::getAttribute).toList();
        boolean decision = authorities.stream().map(GrantedAuthority::getAuthority).anyMatch((auth) -> authList.contains(auth));
        return new AuthorizationDecision(decision);
    }
}
