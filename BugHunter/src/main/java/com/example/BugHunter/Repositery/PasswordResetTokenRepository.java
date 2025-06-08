package com.example.BugHunter.Repositery;

import com.example.BugHunter.Model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

/**
     * Password Reset Token repository interface
     */
    public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
        PasswordResetToken findByToken(String token);
    }


