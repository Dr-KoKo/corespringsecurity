package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.BlockedIp;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlockedIpRepository extends JpaRepository<BlockedIp, Long> {
    BlockedIp findByIpAddress(String ipAddress);
}
