package com.example.BugHunter.Model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class BugHunterUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false, updatable = false)
    private Long id;

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "fullname", nullable = false)
    private String fullname;

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "xp", nullable = false)
    private int xp;

    @Column(name = "streak", nullable = false)
    private int streak;

    @Column(name = "total_solved", nullable = false)
    private int totalSolved;

    @Column(name = "last_solved_date")
    private String lastSolvedDate;

    // Optional OneToMany relation to Badge
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<Badge> badges;
}
