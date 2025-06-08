package com.example.BugHunter.Controller;


import com.example.BugHunter.DTO.BugHunterUserDTO;
import com.example.BugHunter.Exception.CustomException;
import com.example.BugHunter.Model.BugHunterUser;
import com.example.BugHunter.Service.UserService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/BugHunter")
public class AuthController {
    @Autowired
    private UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
    @PostMapping("/register")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_USER) or hasAuthority('register_user')")
    public ResponseEntity<?> register(@Valid @RequestBody BugHunterUserDTO UserDTO)
    {
        try {
            BugHunterUser bugHunterUser=userService.register(UserDTO);
            return userService.notifyUser(bugHunterUser,true);
        }catch (CustomException e)
        {
            return  ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error","Registration failed","message",e.getMessage()));
        }
    }

}
