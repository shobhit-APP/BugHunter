package com.example.BugHunter.Repositery;

import com.example.BugHunter.Model.BugHunterUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<BugHunterUser,Long> {
    boolean existsByemail(String email);
    BugHunterUser findByUsername(String username);
    boolean existsByUsername(String username);
    BugHunterUser findByemail(String email);
}
