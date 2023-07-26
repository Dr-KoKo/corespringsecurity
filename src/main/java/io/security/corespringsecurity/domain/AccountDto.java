package io.security.corespringsecurity.domain;

import lombok.Data;

public record AccountDto(
        String username,
        String password,
        String email,
        String age,
        String role
) {
}
