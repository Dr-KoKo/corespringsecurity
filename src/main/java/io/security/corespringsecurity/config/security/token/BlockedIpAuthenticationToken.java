package io.security.corespringsecurity.config.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.User;

public class BlockedIpAuthenticationToken extends AbstractAuthenticationToken {
    private final Object principal;

    public BlockedIpAuthenticationToken(String ipAddress) {
        super(null);
        this.principal = new User(ipAddress, null, null);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
}
