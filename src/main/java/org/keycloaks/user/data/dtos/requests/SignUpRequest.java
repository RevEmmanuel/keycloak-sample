package org.keycloaks.user.data.dtos.requests;

import jakarta.validation.constraints.*;
import lombok.*;
import static org.keycloaks.utils.ProjectUtilities.NOT_BLANK;

@Setter
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SignUpRequest {

    @NotNull(message = "Please enter a valid first name")
    @NotBlank(message = NOT_BLANK)
    private String firstName;

    @NotNull(message = "Please enter a valid last name")
    @NotBlank(message = NOT_BLANK)
    private String lastName;

    @NotBlank(message = "Please enter an email address")
    @Email(message = "Please enter a valid email address")
    private String email;

    @NotNull(message = "Please enter a valid password")
    @NotBlank(message = NOT_BLANK)
    @Size(max = 20, min = 8)
    private String password;

}
