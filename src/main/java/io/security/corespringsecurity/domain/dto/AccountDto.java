package io.security.corespringsecurity.domain.dto;

import java.util.List;

public record AccountDto(
        String id,
        String username,
        String password,
        String email,
        Integer age,
        List<String> roles
) {
}
