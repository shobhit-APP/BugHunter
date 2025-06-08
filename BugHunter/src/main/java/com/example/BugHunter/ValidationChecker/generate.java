package com.example.BugHunter.ValidationChecker;

import com.example.BugHunter.DTO.BugHunterUserDTO;
import jakarta.servlet.http.HttpServletRequest;

public  interface  generate
{
    String generateUniqueUsername(BugHunterUserDTO userDTO);
    String generateResetLink(HttpServletRequest request);
    String maskEmail(String email);
}
