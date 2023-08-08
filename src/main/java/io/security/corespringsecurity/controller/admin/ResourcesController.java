package io.security.corespringsecurity.controller.admin;


import io.security.corespringsecurity.domain.dto.ResourcesDto;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.service.ResourcesService;
import io.security.corespringsecurity.service.RoleService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Controller
@RequiredArgsConstructor
public class ResourcesController {
    private final ResourcesService resourcesService;
    private final RoleRepository roleRepository;
    private final RoleService roleService;

    private final ModelMapper modelMapper;

    @GetMapping("/admin/resources")
    public String getResources(Model model) {
        List<Resources> resources = resourcesService.getResources();
        model.addAttribute("resources", resources);
        return "admin/resource/list";
    }

    @PostMapping("/admin/resources")
    public String createResources(ResourcesDto resourcesDto) {
        Resources resources = modelMapper.map(resourcesDto, Resources.class);
        Set<Role> roles = new HashSet<>();
        Role role = roleRepository.findByRoleName(resourcesDto.roleName());
        roles.add(role);
        resources.setRoleSet(roles);
        resourcesService.createResources(resources);
        return "redirect:/admin/resources";
    }

    @GetMapping("/admin/resources/register")
    public String viewRoles(Model model) {
        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);
        Set<Role> roleSet = new HashSet<>();
        roleSet.add(new Role());
        ResourcesDto resources = new ResourcesDto(null, null, null, null, null, null, roleSet);
        model.addAttribute("resources", resources);
        return "admin/resource/detail";
    }

    @GetMapping("/admin/resources/{id}")
    public String getResources(@PathVariable String id, Model model) {
        List<Role> roleList = roleService.getRoles();
        model.addAttribute("roleList", roleList);
        Resources resources = resourcesService.getResources(Long.parseLong(id));
        model.addAttribute("resources",
                new ResourcesDto(
                        String.valueOf(resources.getId()),
                        resources.getResourceName(),
                        resources.getHttpMethod(),
                        resources.getOrderNum(),
                        resources.getResourceType(),
                        null,
                        resources.getRoleSet()
                ));
        return "admin/resource/detail";
    }

    @GetMapping("/admin/resources/delete/{id}")
    public String removeResources(@PathVariable String id, Model model) {
        Resources resources = resourcesService.getResources(Long.parseLong(id));
        resourcesService.deleteResources(Long.parseLong(id));
        return "redirect:/admin/resources";
    }
}
