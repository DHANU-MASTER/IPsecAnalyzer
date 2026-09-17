package com.ipsec;

import com.ipsec.security.entity.User;
import com.ipsec.security.repository.LoginAttemptRepository;
import com.ipsec.security.repository.UserRepository;
import com.ipsec.security.service.JwtTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.time.LocalDateTime;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:authtest;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
    "spring.datasource.driverClassName=org.h2.Driver",
    "spring.datasource.username=sa",
    "spring.datasource.password=",
    "spring.jpa.database-platform=org.hibernate.dialect.H2Dialect",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "security.jwt.secret=test-secret-key-for-unit-tests-0123456789abcdef",
    "morphic.enabled=false",
    "admin.bootstrap-enabled=false"
})
@AutoConfigureMockMvc
class AuthFlowTest {

    private static final String PASSWORD = "Admin@123";
    private static final String THROTTLE_IP = "203.0.113.9";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenService jwtTokenService;

    private User admin;

    @BeforeEach
    void seedAdminUser() {
        User user = userRepository.findByUsername("admin").orElseGet(User::new);
        user.setUsername("admin");
        user.setPasswordHash(passwordEncoder.encode(PASSWORD));
        user.setEmail("admin@example.test");
        user.setWhitelistedIp("127.0.0.1");
        user.setDeviceFingerprint("test-fingerprint");
        user.setAccountLocked(false);
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        admin = userRepository.save(user);

        loginAttemptRepository.deleteAll();
    }

    private MockHttpServletRequestBuilder login(String username, String password) {
        return login(username, password, "127.0.0.1");
    }

    private MockHttpServletRequestBuilder login(String username, String password, String remoteAddr) {
        return post("/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}")
            .with(request -> {
                request.setRemoteAddr(remoteAddr);
                return request;
            });
    }

    @Test
    @DisplayName("Valid credentials return a signed JWT")
    void loginSucceedsWithValidCredentials() throws Exception {
        String body = mockMvc.perform(login("admin", PASSWORD))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.token").value(not(emptyOrNullString())))
            .andReturn().getResponse().getContentAsString();

        String token = body.replaceAll(".*\"token\":\"([^\"]+)\".*", "$1");
        assertNotNull(jwtTokenService.validateToken(token), "issued token should validate");
    }

    private String extractToken() throws Exception {
        String body = mockMvc.perform(login("admin", PASSWORD))
            .andReturn().getResponse().getContentAsString();
        return body.replaceAll(".*\"token\":\"([^\"]+)\".*", "$1");
    }

    @Test
    @DisplayName("Wrong password is rejected without leaking a token")
    void loginFailsWithWrongPassword() throws Exception {
        mockMvc.perform(login("admin", "not-the-password"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.token").doesNotExist());
    }

    @Test
    @DisplayName("Unknown users are rejected")
    void loginFailsForUnknownUser() throws Exception {
        mockMvc.perform(login("does-not-exist", PASSWORD))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("The backdoor password no longer works for a different hash")
    void hardCodedPasswordBackdoorIsGone() throws Exception {
        User other = new User();
        other.setUsername("operator");
        other.setPasswordHash(passwordEncoder.encode("SomeOtherSecret!42"));
        other.setEmail("operator@example.test");
        other.setWhitelistedIp("127.0.0.1");
        other.setDeviceFingerprint("operator-fingerprint");
        userRepository.save(other);

        // "Admin@123" used to be accepted for any account
        mockMvc.perform(login("operator", PASSWORD))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("Protected endpoints require a bearer token")
    void protectedEndpointRequiresToken() throws Exception {
        mockMvc.perform(get("/api/analyze/history"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Protected endpoints accept a valid token")
    void protectedEndpointAcceptsValidToken() throws Exception {
        String token = extractToken();

        mockMvc.perform(get("/api/analyze/history")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }

    @Test
    @DisplayName("Crafted paths no longer bypass authentication")
    void craftedPublicLookingPathIsNotPublic() throws Exception {
        mockMvc.perform(get("/fake/auth/login/x"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Public endpoints stay reachable without a token")
    void publicEndpointsAreOpen() throws Exception {
        mockMvc.perform(get("/health")).andExpect(status().isOk());
        mockMvc.perform(get("/api/public/info")).andExpect(status().isOk());
        mockMvc.perform(get("/api/public/client-ip")).andExpect(status().isOk());
    }

    @Test
    @DisplayName("Repeated failures from one IP are throttled")
    void repeatedFailuresFromOneIpAreThrottled() throws Exception {
        for (int attempt = 1; attempt <= 11; attempt++) {
            mockMvc.perform(login("admin", "wrong-password", THROTTLE_IP));
        }

        long failures = loginAttemptRepository.countFailedAttemptsSince(
            THROTTLE_IP, LocalDateTime.now().minusMinutes(15));
        assertTrue(failures >= 10, "failures should be recorded (was " + failures + ")");

        mockMvc.perform(login("admin", PASSWORD, THROTTLE_IP))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.message", containsString("Too many failed attempts")));
    }
}
