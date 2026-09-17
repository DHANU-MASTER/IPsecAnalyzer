package com.ipsec.store;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface MeshEventRepository extends JpaRepository<MeshEventEntity, Long> {
    List<MeshEventEntity> findByReporterNodeId(String reporterNodeId);
    long countByThreatTypeAndCreatedAtAfter(String threatType, LocalDateTime after);
    List<MeshEventEntity> findTop50ByOrderByCreatedAtDesc();
}
