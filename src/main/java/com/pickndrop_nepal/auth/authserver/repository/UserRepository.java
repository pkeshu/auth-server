package com.pickndrop_nepal.auth.authserver.repository;

import com.pickndrop_nepal.auth.authserver.enitity.UsersEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<UsersEntity,Long> {

    Optional<UsersEntity> findByUsername(String username);

    boolean existsByUsername(String username);
}
