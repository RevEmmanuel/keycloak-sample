package org.keycloaks.communities.data.models;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloaks.user.data.models.User;
import java.time.LocalDateTime;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Community {

    @Id
    private String id;

    private String communityName;

    private final LocalDateTime createdAt = LocalDateTime.now();

    @OneToOne
    private User creator;

}
