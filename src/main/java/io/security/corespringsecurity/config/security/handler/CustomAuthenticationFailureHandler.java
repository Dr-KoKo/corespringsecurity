package io.security.corespringsecurity.config.security.handler;

import jakarta.annotation.PostConstruct;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {
    @PostConstruct
    public void init() {
        setDefaultFailureUrl("/login?error=true");
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        super.onAuthenticationFailure(request, response, exception);

        String errorMessage = "Authentication Failed";

        if (exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username Or Password";
        } else if (exception instanceof InsufficientAuthenticationException) {
            errorMessage = "Invalid Secret Key";
        }

        if (isUseForward()) {
            request.setAttribute("errorMsg", errorMessage);
        } else {
            HttpSession session = request.getSession(false);
            if (session != null || isAllowSessionCreation()) {
                request.getSession().setAttribute("errorMsg", errorMessage);
            }
        }
    }
}
