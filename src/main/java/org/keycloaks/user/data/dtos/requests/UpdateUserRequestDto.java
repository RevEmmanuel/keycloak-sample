package org.keycloaks.user.data.dtos.requests;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UpdateUserRequestDto {

//    private String name;

    private String firstName;

    private String lastName;

    private String email;

    private String phoneNumber;

}
