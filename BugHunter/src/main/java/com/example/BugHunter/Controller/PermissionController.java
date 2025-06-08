package com.example.BugHunter.Controller;

import com.example.BugHunter.Model.Permissions;
import com.example.BugHunter.Service.PermissionsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Controller for RBAC operations.
 *
 * Always Authorize to the ADMIN role
 */

@RestController
@RequestMapping("/v1/rbac/permission")
public class PermissionController {

    @Autowired
    private PermissionsService permissionsService;

    @PostMapping
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasAuthority('create_permission')")
    public ResponseEntity<Map<String, Object>> createPermission(@RequestBody Permissions permissions) {
        Permissions createdPermissions = permissionsService.createPermission(permissions);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "Routes Created Successfully", "routes", createdPermissions));
    }
}
