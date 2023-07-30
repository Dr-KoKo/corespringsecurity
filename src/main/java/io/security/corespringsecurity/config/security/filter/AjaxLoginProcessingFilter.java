package io.security.corespringsecurity.config.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.config.security.token.AjaxAuthenticationToken;
import io.security.corespringsecurity.domain.AccountDto;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.io.IOException;

@Component
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private final ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        super(new AntPathRequestMatcher("/api/login"));
        setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        boolean isAjax = "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
        if (!isAjax) {
            throw new IllegalStateException("Authentication is not supported");
        }
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if (!StringUtils.hasText(accountDto.username()) || !StringUtils.hasText(accountDto.password())) {
            throw new IllegalArgumentException("Username Or Password is Empty");
        }
        Authentication ajaxAuthenticationToken = AjaxAuthenticationToken.unauthenticated(accountDto.username(), accountDto.password());
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }
}
