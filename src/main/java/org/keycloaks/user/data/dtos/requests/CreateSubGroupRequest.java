package org.keycloaks.user.data.dtos.requests;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CreateSubGroupRequest {
    private String parentGroupName;
    private String childGroupName;
}
