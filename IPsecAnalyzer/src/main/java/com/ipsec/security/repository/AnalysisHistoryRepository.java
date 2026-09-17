package com.ipsec.security.repository;

import com.ipsec.security.entity.AnalysisHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AnalysisHistoryRepository extends JpaRepository<AnalysisHistory, Long> {
    List<AnalysisHistory> findByUserId(Long userId);

    /** Most recent analyses first — drives the scheduled morphic rotation. */
    List<AnalysisHistory> findTop50ByOrderByAnalyzedAtDesc();
}
