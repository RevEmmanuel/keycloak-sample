package org.keycloaks.user.data.dtos.responses;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {

    private String id;

//    private String name;

    private String firstName;

    private String lastName;

    private String email;

    private String phoneNumber;

    private LocalDateTime createdAt;

}
