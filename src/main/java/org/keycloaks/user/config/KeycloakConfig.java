package org.keycloaks.user.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
@RequiredArgsConstructor
@Slf4j
public class KeycloakConfig {

    private final KeycloakConfigProperties keycloakConfigProperties;

    @Value("${KEYCLOAK_SERVER_URL}")
    private String serverUrl;

    @Value("${CLIENT_ID}")
    private String clientId;

    @Value("${CLIENT_SECRET}")
    private String clientSecret;

    @Value("${KEYCLOAK_MASTER_REALM}")
    private String masterRealm;



    @Bean
    public Keycloak keycloak() {

        return KeycloakBuilder.builder()
                .grantType(OAuth2Constants.PASSWORD)
                .realm(masterRealm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .username(keycloakConfigProperties.getUsername())
                .password(keycloakConfigProperties.getPassword())
                .serverUrl(serverUrl)
                .build();

    }
}
