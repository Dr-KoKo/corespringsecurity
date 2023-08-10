package io.security.corespringsecurity.config.security.service;

import io.security.corespringsecurity.domain.entity.BlockedIp;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.BlockedIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

@Component
public class SecurityResourceService {
    private ResourcesRepository resourcesRepository;
    private BlockedIpRepository blockedIpRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository, BlockedIpRepository blockedIpRepository) {
        this.resourcesRepository = resourcesRepository;
        this.blockedIpRepository = blockedIpRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(res -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            res.getRoleSet().forEach(ro -> {
                configAttributeList.add(new SecurityConfig(ro.getRoleName()));
            });
            result.put(new AntPathRequestMatcher(res.getResourceName()), configAttributeList);
        });
        return result;
    }

    public List<IpAddressMatcher> getBlockedIpList() {
        return blockedIpRepository.findAll().stream().map(BlockedIp::getIpAddress).map(IpAddressMatcher::new).toList();
    }
}
