package org.keycloaks.communities.data.repositories;

import org.keycloaks.communities.data.models.Community;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CommunityRepository  extends JpaRepository<Community, String> {

    boolean existsByCommunityName(String communityName);

}
