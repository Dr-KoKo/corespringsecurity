package io.security.corespringsecurity.domain;

public record AccountDto(
        String username,
        String password,
        String email,
        String age,
        String role
) {
}
