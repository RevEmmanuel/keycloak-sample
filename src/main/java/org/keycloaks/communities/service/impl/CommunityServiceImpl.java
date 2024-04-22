package org.keycloaks.communities.service.impl;

import lombok.RequiredArgsConstructor;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloaks.communities.data.dtos.requests.CreateCommunityRequest;
import org.keycloaks.communities.data.dtos.responses.CommunityResponse;
import org.keycloaks.communities.data.models.Community;
import org.keycloaks.communities.data.repositories.CommunityRepository;
import org.keycloaks.communities.service.CommunityService;
import org.keycloaks.user.service.KeycloakService;
import org.keycloaks.user.service.UserService;
import org.keycloaks.utils.ProjectUtilities;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;


@RequiredArgsConstructor
@Service
public class CommunityServiceImpl implements CommunityService  {

    private final ModelMapper modelMapper;
    private final CommunityRepository communityRepository;
    private final UserService userService;
    private final KeycloakService keycloakService;

    @Override
    public CommunityResponse createCommunity(CreateCommunityRequest communityRequest) {
        if (communityRepository.existsByCommunityName(communityRequest.getCommunityName())) {
            throw new RuntimeException("Community name exists already");
        }
        GroupRepresentation createdGroup;
        try {
            createdGroup = keycloakService.createGroup(communityRequest.getCommunityName());
        } catch (Exception exception) {
            throw new RuntimeException(exception.getMessage());
        }
        Community community = Community.builder()
                .communityName(communityRequest.getCommunityName())
                .creator(userService.getCurrentUser())
                .id(createdGroup.getId())
                .build();
        Community savedCommunity = communityRepository.save(community);
//        keycloakService.addRoleToRealm(savedCommunity.getId() +
//                ProjectUtilities.GROUP_EXTENSION, "The creator of the group");
        
        return null;
    }
}
