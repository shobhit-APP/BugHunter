package com.example.BugHunter.Repositery;

import com.example.BugHunter.Model.BugHunterUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<BugHunterUser,Long> {
}
