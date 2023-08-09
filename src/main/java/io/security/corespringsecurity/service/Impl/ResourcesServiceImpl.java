package io.security.corespringsecurity.service.Impl;

import io.security.corespringsecurity.config.security.manager.CustomAuthorizationManager;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.service.ResourcesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ResourcesServiceImpl implements ResourcesService {
    private final ResourcesRepository ResourcesRepository;
    private final CustomAuthorizationManager authorizationManager;

    public Resources getResources(long id) {
        return ResourcesRepository.findById(id).orElse(new Resources());
    }

    public List<Resources> getResources() {
        return ResourcesRepository.findAll(Sort.by(Sort.Order.asc("orderNum")));
    }

    @Transactional
    public void createResources(Resources resources) {
        ResourcesRepository.save(resources);
        authorizationManager.reload();
    }

    @Transactional
    public void deleteResources(long id) {
        ResourcesRepository.deleteById(id);
        authorizationManager.reload();
    }
}