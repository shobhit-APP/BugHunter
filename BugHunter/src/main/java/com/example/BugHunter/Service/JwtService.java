package com.example.BugHunter.Service;

import com.example.BugHunter.DTO.AuthResponseDTO;
import com.example.BugHunter.DTO.BugHunterUserDTO;
import com.example.BugHunter.Model.BugHunterUser;
import com.example.BugHunter.Model.RolesPermission;
import com.example.BugHunter.Repositery.RolesPermissionRepository;
import com.example.BugHunter.Repositery.UserRepo;
import com.example.BugHunter.Util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class JwtService {
    @Autowired
    private UserService userService;
    @Autowired
    private RolesPermissionRepository rolesPermissionRepository;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private ReferenceTokenService referenceTokenService;
    @Autowired
    private UserRepo userRepo;
    public ResponseEntity<?> generateAuthResponseForUser(BugHunterUser user) {
        // Check if user is verified
        if (Objects.equals(user.getVerificationStatus(), "Unverified")) {
            return userService.notifyUser(user,false);
        }
        // Generate JWT token
        Long userRoleId = user.getRole().getId();
        String UserRole = user.getRole().getName();
        // Fetch permissions for the user
        List<RolesPermission> rolePermissions = rolesPermissionRepository.findPermissionsByRoleId(userRoleId);
        List<String> permissionList = rolePermissions.stream()
                .map(rp -> rp.getPermissions().getPermission())
                .collect(Collectors.toList());

        // Generate JWT token with permissions
        String jwtToken = jwtUtil.generateToken(user.getUsername(), UserRole,user.getFullname(),user.getId(), permissionList);
        String refreshToken = referenceTokenService.generateReferenceToken(jwtToken);
        BugHunterUser bugHunterUser = new BugHunterUser();
        System.out.println(user.getId());
        bugHunterUser.setId(user.getId());
        bugHunterUser.setStatus(BugHunterUser.UserStatus.Active);
        userRepo.save(bugHunterUser);
        // Generate and return response
        AuthResponseDTO authResponse = getJwtResponse(jwtToken, refreshToken, UserRole);
        return ResponseEntity.ok(authResponse);
    }

    /**
     * Create JWT response with user details and permissions.
     *
     * @param jwtToken     the JWT token
     * @param refreshToken the refresh token
     * @param userRole     the user role
     * @return the authentication response DTO
     */
    public AuthResponseDTO getJwtResponse(String jwtToken, String refreshToken, String userRole) {
        // Return JWT response with permissions
        return new AuthResponseDTO(jwtToken, refreshToken, userRole);
    }

}
