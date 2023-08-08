package io.security.corespringsecurity.domain.dto;

import io.security.corespringsecurity.domain.entity.Role;

import java.util.Set;

public record ResourcesDto(
        String id,
        String resourceName,
        String httpMethod,
        Integer orderNum,
        String resourceType,
        String roleName,
        Set<Role> roleSet
) {
}
