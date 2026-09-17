package com.ipsec.store;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RemediationRepository extends JpaRepository<RemediationEntity, Long> {
    Optional<RemediationEntity> findByActionId(String actionId);
}
