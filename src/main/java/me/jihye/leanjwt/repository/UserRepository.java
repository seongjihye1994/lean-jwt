package me.jihye.leanjwt.repository;

import me.jihye.leanjwt.entity.Users;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Users, Long> {
    @EntityGraph(attributePaths = "authorities")
    Optional<Users> findOneWithAuthoritiesByUsername(String username);
}