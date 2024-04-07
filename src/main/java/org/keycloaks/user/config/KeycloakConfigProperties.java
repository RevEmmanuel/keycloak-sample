package org.keycloaks.user.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@Data
@ConfigurationProperties(prefix = "example.keycloak")
public class KeycloakConfigProperties {

    private String serverUrl;

    private String realm;

    private String masterRealm;

    private String clientId;

    private String masterClientId;

    private String username;

    private String password;

    private String clientSecret;

}
