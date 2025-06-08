package com.example.BugHunter.Repositery;

import com.example.BugHunter.Model.Permissions;
import com.example.BugHunter.Model.Roles;
import com.example.BugHunter.Model.RolesPermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RolesPermissionRepository extends JpaRepository<RolesPermission, Long> {
    List<RolesPermission> findByRoleName(String roleName); // Notice the camel case matching the property
    List<RolesPermission> findByRoleId(Long roleId);

    List<RolesPermission> findPermissionsByRoleId(Long roleId);

    RolesPermission findByRoleAndPermissions(Roles role, Permissions permissions);
    List<RolesPermission> findAllByRole(Roles role);

//        RolePermission findByRoleIdAndRouteIdAndPermissionId(Long id, Long id1, Long id2);
//    boolean existsByRoleIdAndRouteIdAndPermissionId(Long id, Long id1, Long id2);
//    boolean existsByRole_IdAndRoute_Id(Long roleId, Long routeId);
}
