package com.example.BugHunter.DTO;

import com.example.BugHunter.Model.BugHunterUser;
import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.*;

import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponseDTO {

    private Long id;
    private String username;
    private String fullName;
    private String email;

    private BugHunterUser.VerificationStatus verificationStatus;
    private BugHunterUser.VerificationMethod verificationMethod;
    private BugHunterUser.UserStatus status;

    private String userRole;

    // Optional static mapper
    public static UserResponseDTO fromEntity(BugHunterUser user) {
        return UserResponseDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .fullName(user.getFullname())
                .email(user.getEmail())
                .verificationStatus(user.getVerificationStatus())
                .verificationMethod(user.getVerificationMethod())
                .status(user.getStatus())
                .userRole(user.getRole() != null ? user.getRole().getName() : null)
                .build();
    }

    public static List<UserResponseDTO> fromEntityList(List<BugHunterUser> users) {
        return users.stream()
                .map(UserResponseDTO::fromEntity)
                .collect(Collectors.toList());
    }
}