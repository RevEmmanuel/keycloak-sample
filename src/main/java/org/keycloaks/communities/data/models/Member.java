package org.keycloaks.communities.data.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.keycloaks.user.data.models.User;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Member {

    @Id
    private String id;

    @ManyToOne
    private Community community;

    @ManyToOne
    private User member;

}
