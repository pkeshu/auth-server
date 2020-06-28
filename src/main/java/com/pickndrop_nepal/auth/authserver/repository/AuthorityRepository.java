package com.pickndrop_nepal.auth.authserver.repository;

import com.pickndrop_nepal.auth.authserver.enitity.AuthoritiesEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<AuthoritiesEntity,Long> {
}
