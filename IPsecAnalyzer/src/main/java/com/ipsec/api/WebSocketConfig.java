package com.ipsec.api;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic");
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // NOTE: setAllowedOrigins("*") is rejected by Spring whenever the request
        // carries credentials (SockJS always sets allowCredentials=true), which
        // made every transport fail with HTTP 400 and the broker unreachable.
        // Origin *patterns* are the correct way to allow any origin here.
        registry.addEndpoint("/ws-analysis")
            .setAllowedOriginPatterns("*")
            .withSockJS();
    }
}
