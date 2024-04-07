package org.keycloaks.user.data.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "users")
public class User {

    @Id
    private String id;

//    private String name;

    private String firstName;

    private String lastName;

    private String email;

    private String phoneNumber;

    private final LocalDateTime createdAt = LocalDateTime.now();

}
