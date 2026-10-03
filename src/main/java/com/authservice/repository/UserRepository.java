package com.authservice.repository;

import com.authservice.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByPhoneNumber(String phoneNumber);

    Optional<User> findByGoogleSub(String googleSub);

    Optional<User> findByFacebookSub(String facebookSub);

    Optional<User> findByExternalId(String externalId);

    boolean existsByEmail(String email);

    boolean existsByPhoneNumber(String phoneNumber);
}
