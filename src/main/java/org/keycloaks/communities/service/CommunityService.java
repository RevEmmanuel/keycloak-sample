package org.keycloaks.communities.service;

import org.keycloaks.communities.data.dtos.requests.CreateCommunityRequest;
import org.keycloaks.communities.data.dtos.responses.CommunityResponse;

public interface CommunityService {

    CommunityResponse createCommunity(CreateCommunityRequest communityRequest);

}
