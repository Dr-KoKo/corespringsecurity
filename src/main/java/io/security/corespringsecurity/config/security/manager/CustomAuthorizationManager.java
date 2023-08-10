package io.security.corespringsecurity.config.security.manager;

import io.security.corespringsecurity.config.security.service.SecurityResourceService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public class CustomAuthorizationManager implements AuthorizationManager<HttpServletRequest> {
    protected final SecurityResourceService securityResourceService;
    private static LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();
    private RoleHierarchy roleHierarchy;

    public CustomAuthorizationManager(SecurityResourceService securityResourceService, RoleHierarchy roleHierarchy) {
        this.securityResourceService = securityResourceService;
        this.requestMap = securityResourceService.getResourceList();
        this.roleHierarchy = roleHierarchy;
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
        Collection<? extends GrantedAuthority> authorities = roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
        List<String> authList = authority.stream().map(ConfigAttribute::getAttribute).toList();
        boolean decision = authorities.stream().map(GrantedAuthority::getAuthority).anyMatch((auth) -> authList.contains(auth));
        return new AuthorizationDecision(decision);
    }

    public void reload() {
        synchronized (CustomAuthorizationManager.requestMap) {
            CustomAuthorizationManager.requestMap = securityResourceService.getResourceList();
        }
    }
}
