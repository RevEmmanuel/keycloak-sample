package org.keycloaks.communities.data.dtos.responses;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class CommunityResponse {

    private String id;

    private String communityName;

    private LocalDateTime createdAt;

}
