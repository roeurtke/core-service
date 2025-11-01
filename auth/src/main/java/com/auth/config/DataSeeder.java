package com.auth.config;

import com.auth.entity.Permission;
import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.repository.PermissionRepository;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;

@Component
public class DataSeeder implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Create permissions
        Permission userRead = createPermissionIfNotFound("USER_READ", "Permission to read user information");
        Permission userCreate = createPermissionIfNotFound("USER_CREATE", "Permission to create new users");
        Permission userUpdate = createPermissionIfNotFound("USER_UPDATE", "Permission to update existing users");
        Permission userDelete = createPermissionIfNotFound("USER_DELETE", "Permission to delete users");
        
        Permission roleRead = createPermissionIfNotFound("ROLE_READ", "Permission to read role information");
        Permission roleCreate = createPermissionIfNotFound("ROLE_CREATE", "Permission to create new roles");
        Permission roleUpdate = createPermissionIfNotFound("ROLE_UPDATE", "Permission to update existing roles");
        Permission roleDelete = createPermissionIfNotFound("ROLE_DELETE", "Permission to delete roles");
        
        Permission permissionRead = createPermissionIfNotFound("PERMISSION_READ", "Permission to read permission information");
        Permission permissionCreate = createPermissionIfNotFound("PERMISSION_CREATE", "Permission to create new permissions");

        // Create roles
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", 
            new HashSet<>(Arrays.asList(userRead, userCreate, userUpdate, userDelete, roleRead, roleCreate, roleUpdate, roleDelete,permissionRead, permissionCreate)), "Administrator role with all permissions");
        
        Role userRole = createRoleIfNotFound("ROLE_USER", 
            new HashSet<>(Arrays.asList(userRead)), "Standard user role with limited permissions");

        // Create admin user
        createUserIfNotFound("admin", "admin@example.com", "admin123", 
            new HashSet<>(Arrays.asList(adminRole)), "1234567890");

        // Create regular user
        createUserIfNotFound("user", "user@example.com", "user123", 
            new HashSet<>(Arrays.asList(userRole)), "0987654321");
    }

    private Permission createPermissionIfNotFound(String name, String description) {
        Optional<Permission> opt = permissionRepository.findByName(name);
        if (opt.isPresent()) {
            return opt.get();
        }
        Permission permission = new Permission(name, description);
        return permissionRepository.save(permission);
    }

    private Role createRoleIfNotFound(String name, java.util.Set<Permission> permissions, String description) {
        Optional<Role> opt = roleRepository.findByName(name);
        if (opt.isPresent()) {
            return opt.get();
        }
        Role role = new Role(name, description);
        role.setPermissions(permissions);
        return roleRepository.save(role);
    }

    private void createUserIfNotFound(String username, String email, String password, java.util.Set<Role> roles, String phone) {
        if (!userRepository.existsByUsername(username)) {
            User user = new User(username, email, passwordEncoder.encode(password), phone);
            user.setRoles(roles);
            userRepository.save(user);
        }
    }
}