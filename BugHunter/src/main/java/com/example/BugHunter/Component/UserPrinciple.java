package com.example.BugHunter.Component;

import com.example.BugHunter.Model.BugHunterUser;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Component
public class UserPrinciple implements UserDetails {
    private final BugHunterUser bugHunterUser;
    public UserPrinciple(BugHunterUser user) {
        this.bugHunterUser = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String UserRole=bugHunterUser.getRole().getName(); // Assuming user has a method getRole() that returns a single UserRole
        return Collections.singletonList(new SimpleGrantedAuthority(UserRole));
    }


    @Override
    public String getPassword() {
        return bugHunterUser.getPassword();
    }

    @Override
    public String getUsername() {
        return bugHunterUser.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
