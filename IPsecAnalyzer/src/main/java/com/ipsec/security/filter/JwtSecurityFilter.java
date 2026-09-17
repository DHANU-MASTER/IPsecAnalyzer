package com.ipsec.security.filter;

import com.ipsec.security.service.JwtTokenService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Component
public class JwtSecurityFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenService jwtService;

    /**
     * Exact path prefixes that never require a JWT.
     * NOTE: matched with startsWith (not contains) so that crafted paths
     * like /fake/auth/login/x can no longer bypass authentication.
     */
    private static final Set<String> PUBLIC_PREFIXES = new HashSet<>(Arrays.asList(
        "/auth/",
        "/login",
        "/dashboard",
        "/health",
        "/api/public/",
        "/api/mesh/gossip",   // HMAC-signed peer events: the signature authenticates
        "/swagger-ui",
        "/v3/api-docs",
        "/ws-analysis",   // SockJS/STOMP endpoint (handshake + sockjs transports)
        "/actuator",
        "/css/",
        "/js/",
        "/favicon.ico"
    ));

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                   HttpServletResponse response,
                                   FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if (isPublicEndpoint(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(401);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Missing or invalid Authorization header\"}");
            return;
        }

        String token = authHeader.substring(7);

        try {
            jwtService.validateToken(token);
            String username = jwtService.getUsernameFromToken(token);

            // NOTE: IP-binding was removed deliberately. Binding JWTs to the
            // login IP caused random 403 "Token IP mismatch" failures whenever
            // the client's network path changed (Wi-Fi <-> LAN, VPN, proxies).
            // Session security is already enforced by the signed, expiring token.

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                username, null, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);

        } catch (JwtException e) {
            response.setStatus(401);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Invalid or expired token\"}");
        }
    }

    private boolean isPublicEndpoint(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        if ("/".equals(path)) {
            return true;
        }
        for (String prefix : PUBLIC_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
