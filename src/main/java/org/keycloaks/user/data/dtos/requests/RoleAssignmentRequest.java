package org.keycloaks.user.data.dtos.requests;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class RoleAssignmentRequest {
    String entityType;
    String entityId;
    String roleName;
}
