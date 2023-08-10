package io.security.corespringsecurity.config.security.manager;

import io.security.corespringsecurity.config.security.service.SecurityResourceService;
import io.security.corespringsecurity.config.security.token.BlockedIpAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.List;
import java.util.function.Supplier;

public class CustomIpAuthorizationManager extends PermitAllAuthorizationManager {
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();

    public CustomIpAuthorizationManager(SecurityResourceService securityResourceService, RoleHierarchy roleHierarchy, String... permitAllResources) {
        super(securityResourceService, roleHierarchy, permitAllResources);
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.get().getDetails();
        String remoteAddress = details.getRemoteAddress();

        List<IpAddressMatcher> accessIpList = securityResourceService.getBlockedIpList();
        for (IpAddressMatcher matcher : accessIpList) {
            if (matcher.matches(remoteAddress)) {
                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(new BlockedIpAuthenticationToken(remoteAddress));
                this.securityContextHolderStrategy.setContext(context);
                return new AuthorizationDecision(false);
            }
        }
        return super.check(authentication, request);
    }
}
