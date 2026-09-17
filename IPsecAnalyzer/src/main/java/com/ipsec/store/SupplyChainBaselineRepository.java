package com.ipsec.store;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SupplyChainBaselineRepository extends JpaRepository<SupplyChainBaselineEntity, Long> {
    Optional<SupplyChainBaselineEntity> findByComponentName(String componentName);
}
