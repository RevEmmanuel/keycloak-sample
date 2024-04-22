package org.keycloaks.communities.controller;


import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloaks.communities.data.dtos.requests.CreateCommunityRequest;
import org.keycloaks.communities.data.dtos.responses.CommunityResponse;
import org.keycloaks.communities.service.CommunityService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@Slf4j
@RequestMapping("/api/v1/community")
public class CommunityController {

    private final CommunityService communityService;

    @PostMapping("/create")
    public ResponseEntity<CommunityResponse> createCommunity(CreateCommunityRequest communityRequest) {
        return new ResponseEntity<>(communityService.createCommunity(communityRequest), HttpStatus.CREATED);
    }
}
