package com.example.BugHunter.ValidationChecker;

import com.example.BugHunter.DTO.BugHunterUserDTO;
import com.example.BugHunter.Model.BugHunterUser;
import com.example.BugHunter.Service.UserService;

public interface ValidateInput {
    void validateUserRegistrationInput(BugHunterUserDTO bugHunterUserDTO);
    void checkExistingUser(BugHunterUserDTO userDTO);
    boolean isNullOrEmpty(String str);
    boolean Check(String username, String email, String password);
    BugHunterUser loginWithEmail(String email);
    BugHunterUser findUser(UserService.LoginMethod loginMethod, String username, String phoneNumber, String email);
    UserService.LoginMethod determineLoginMethod(String username, String email);
}
