package com.sparta.jwt_tutorial.repository;


import com.sparta.jwt_tutorial.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // @EntityGraph는 쿼리가 수행될때 lazy조회가 아니고
    // Eager조회로 authorities정보를 같이 가져온다.
    @EntityGraph(attributePaths = "authorities")
    Optional<User> findOneWithAuthoritiesByUsername(String username);
}
