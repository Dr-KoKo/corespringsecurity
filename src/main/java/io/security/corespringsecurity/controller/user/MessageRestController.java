package io.security.corespringsecurity.controller.user;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MessageRestController {
    @GetMapping("/api/messages")
    public String mypage() throws Exception {
        return "message_ok";
    }
}
