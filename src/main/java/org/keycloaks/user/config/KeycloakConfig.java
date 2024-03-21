package org.keycloaks.user.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@RequiredArgsConstructor
@Slf4j
public class KeycloakConfig {

    private final KeycloakConfigProperties keycloakConfigProperties;

    @Bean
    public Keycloak keycloak() {
        return KeycloakBuilder.builder()
                .grantType(OAuth2Constants.PASSWORD)
                .realm(keycloakConfigProperties.getMasterRealm())
                .clientId(keycloakConfigProperties.getMasterClientId())
                .username(keycloakConfigProperties.getUsername())
                .password(keycloakConfigProperties.getPassword())
                .serverUrl(keycloakConfigProperties.getServerUrl())
                .build();
    }
}
