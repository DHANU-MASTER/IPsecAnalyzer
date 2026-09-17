package com.ipsec.store;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MorphicStateRepository extends JpaRepository<MorphicStateEntity, Long> {
    Optional<MorphicStateEntity> findTopByOrderByGeneratedAtDesc();
}
