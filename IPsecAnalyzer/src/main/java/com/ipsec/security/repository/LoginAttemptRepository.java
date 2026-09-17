package com.ipsec.security.repository;

import com.ipsec.security.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, Long> {
    List<LoginAttempt> findByUsername(String username);

    List<LoginAttempt> findByIpAddressOrderByAttemptedAtDesc(String ipAddress);

    @Query("SELECT COUNT(a) FROM LoginAttempt a " +
           "WHERE a.ipAddress = :ip AND a.success = false " +
           "AND a.attemptedAt >= :since")
    long countFailedAttemptsSince(@Param("ip") String ip, @Param("since") java.time.LocalDateTime since);
}
