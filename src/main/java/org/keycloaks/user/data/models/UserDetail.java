package org.keycloaks.user.data.models;

import lombok.Data;
import org.keycloak.representations.idm.RoleRepresentation;

import java.util.List;

@Data
public class UserDetail {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private List<RoleRepresentation> roles;
}
