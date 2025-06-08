package com.example.BugHunter.Middleware;

import com.example.BugHunter.Component.UserContext;
import com.example.BugHunter.DTO.JWTUserDTO;
import com.example.BugHunter.Util.JwtUtil;
import com.example.BugHunter.Util.MyEncryptionUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class AuthorizationFilter extends OncePerRequestFilter {
    @Autowired
    private UserContext userContext;
    @Autowired
    private JwtUtil jwtUtil;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getServletPath();

//        // Allowlisted paths
//        if (path.matches("^/v1/auth/.*") || path.matches("^/v1/home/.*") ||
//                path.matches("^/v3/api-docs.*") || path.matches("^/swagger-ui/.*") ||
//                path.matches("^/swagger-ui.html$") || path.matches("^/internal.*")) {
//            filterChain.doFilter(request, response);
//            return;
//        }

        // Validate and extract user
        String username = userContext.validateAndExtractUser(request, response);
        if (username == null) return;

        String role = userContext.extractRole(request);
        String fullName = userContext.extractFullname(request);

        if (role == null) {
            userContext.sendUnauthorizedResponse(response, "Authorization failed: Role not found in token");
            return;
        }

        String token = userContext.extractToken(request);
        List<String> encryptedPermissions = jwtUtil.extractPermissions(token);

        if (SecurityContextHolder.getContext().getAuthentication() == null) {

            // Add permissions
            List<GrantedAuthority> authorities = new ArrayList<>(encryptedPermissions.stream()
                    .map(MyEncryptionUtil::decrypt)
                    .map(SimpleGrantedAuthority::new)
                    .toList());

            // Add role in "ROLE_" format (for hasRole() usage)
            authorities.add(new SimpleGrantedAuthority(role.toUpperCase()));

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(username, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authToken);
        }

        // Set user in request scope
        Long userId = userContext.extractUserId(request);
        JWTUserDTO user = new JWTUserDTO(userId, username, role, fullName);
        request.setAttribute("user", user);

        filterChain.doFilter(request, response);
    }
}
