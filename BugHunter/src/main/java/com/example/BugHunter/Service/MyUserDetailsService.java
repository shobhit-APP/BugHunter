package com.example.BugHunter.Service;

import com.example.BugHunter.Component.UserPrinciple;
import com.example.BugHunter.Model.BugHunterUser;
import com.example.BugHunter.Service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
    private UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(MyUserDetailsService.class);


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if (username == null || username.trim().isEmpty()) {
            logger.warn("Empty username provided.");
            throw new UsernameNotFoundException("Username must not be empty.");
        }
        BugHunterUser user=userService.getUserByUsername(username);

        if (user == null) {
            logger.warn("User not found: {}", username);
            throw new UsernameNotFoundException("User with username '" + username + "' was not found.");
        }

        return new UserPrinciple(user);
    }
}
