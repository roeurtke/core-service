package com.auth.controller;

import com.auth.entity.Permission;
import com.auth.repository.PermissionRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/permissions")
public class PermissionController {
    @Autowired
    private PermissionRepository permissionRepository;

    @GetMapping
    @PreAuthorize("hasAuthority('PERMISSION_READ')")
    public List<Permission> getAllPermissions() {
        return permissionRepository.findAll();
    }

    @PostMapping
    @PreAuthorize("hasAuthority('PERMISSION_CREATE')")
    public Permission createPermission(@RequestBody Permission permission) {
        return permissionRepository.save(permission);
    }
}