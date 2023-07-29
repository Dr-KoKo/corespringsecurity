package io.security.corespringsecurity.controller.login;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.SessionAttribute;

@Controller
public class LoginController {
    @GetMapping("/login")
    public String login(@SessionAttribute(value = WebAttributes.AUTHENTICATION_EXCEPTION, required = false) AuthenticationException exception,
                        @SessionAttribute(value = "errorMsg", required = false) String errorMessage,
                        Model model) {
        if (exception != null) {
            model.addAttribute("errorMsg", errorMessage);
        }

        return "user/login/login";
    }

    @GetMapping("/denied")
    public String accessDenied(@RequestAttribute(WebAttributes.ACCESS_DENIED_403) AccessDeniedException exception,
                               @AuthenticationPrincipal User user,
                               Model model) {
        model.addAttribute("username", user.getUsername());
        model.addAttribute("errorMsg", exception.getMessage());

        return "user/login/denied";
    }
}
