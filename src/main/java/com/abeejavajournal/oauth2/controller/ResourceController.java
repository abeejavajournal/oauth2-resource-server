package com.abeejavajournal.oauth2.controller;

import com.abeejavajournal.oauth2.dto.ResourceDto;
import com.abeejavajournal.oauth2.dto.UserInfoDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;


@Slf4j
@RestController
@RequestMapping("/resources")
@RequiredArgsConstructor
public class ResourceController {

    /**
     * Public endpoint - no authentication required
     */
    @GetMapping("/public")
    public ResponseEntity<Map<String, String>> publicResource() {
        log.info("Accessing public resource");
        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a public resource");
        response.put("timestamp", Instant.now().toString());
        return ResponseEntity.ok(response);
    }

    /**
     * Protected endpoint - requires authentication but no specific scope
     */
    @GetMapping("/authenticated")
    public ResponseEntity<UserInfoDto> getAuthenticatedUserInfo(@AuthenticationPrincipal Jwt jwt) {
        log.info("Accessing authenticated resource for user: {}", jwt.getSubject());
        
        UserInfoDto userInfo = UserInfoDto.builder()
            .subject(jwt.getSubject())
            .email(jwt.getClaimAsString("email"))
            .name(jwt.getClaimAsString("name"))
            .issuedAt(jwt.getIssuedAt())
            .expiresAt(jwt.getExpiresAt())
            .authorities(SecurityContextHolder.getContext()
                .getAuthentication()
                .getAuthorities()
                .stream()
                .map(Object::toString)
                .collect(Collectors.toList()))
            .claims(jwt.getClaims())
            .build();
        
        return ResponseEntity.ok(userInfo);
    }

    /**
     * Endpoint requiring 'read' scope
     */
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<List<ResourceDto>> getResources() {
        log.info("Getting resources with read scope");
        
        List<ResourceDto> resources = List.of(
            ResourceDto.builder()
                .id(UUID.randomUUID().toString())
                .name("Resource 1")
                .description("First protected resource")
                .createdAt(Instant.now())
                .build(),
            ResourceDto.builder()
                .id(UUID.randomUUID().toString())
                .name("Resource 2")
                .description("Second protected resource")
                .createdAt(Instant.now())
                .build()
        );
        
        return ResponseEntity.ok(resources);
    }

    /**
     * Endpoint requiring 'write' scope
     */
    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_write')")
    public ResponseEntity<ResourceDto> createResource(@RequestBody ResourceDto resource) {
        log.info("Creating resource with write scope");
        
        resource.setId(UUID.randomUUID().toString());
        resource.setCreatedAt(Instant.now());
        
        return ResponseEntity.ok(resource);
    }

    /**
     * Endpoint requiring 'admin' scope
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<Map<String, String>> deleteResource(@PathVariable String id) {
        log.info("Deleting resource {} with admin scope", id);
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Resource deleted successfully");
        response.put("resourceId", id);
        response.put("deletedAt", Instant.now().toString());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint with complex authorization expression
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_write') and #resource.ownerId == authentication.name")
    public ResponseEntity<ResourceDto> updateResource(
            @PathVariable String id,
            @RequestBody ResourceDto resource) {
        
        log.info("Updating resource {} with owner check", id);
        
        resource.setId(id);
        resource.setUpdatedAt(Instant.now());
        
        return ResponseEntity.ok(resource);
    }

    /**
     * Endpoint demonstrating role-based access control
     */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> adminResource(Authentication authentication) {
        log.info("Accessing admin resource");
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin resource accessed");
        response.put("user", authentication.getName());
        response.put("authorities", authentication.getAuthorities());
        response.put("timestamp", Instant.now());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Endpoint with custom permission check
     */
    @GetMapping("/{id}/details")
    @PreAuthorize("@resourceSecurityService.hasAccessToResource(#id, authentication)")
    public ResponseEntity<ResourceDto> getResourceDetails(@PathVariable String id) {
        log.info("Getting details for resource: {}", id);
        
        ResourceDto resource = ResourceDto.builder()
            .id(id)
            .name("Protected Resource")
            .description("This resource requires custom permission check")
            .createdAt(Instant.now())
            .build();
        
        return ResponseEntity.ok(resource);
    }

    /**
     * Debug endpoint to inspect JWT claims
     */
    @GetMapping("/debug/jwt")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<Map<String, Object>> debugJwt(@AuthenticationPrincipal Jwt jwt) {
        log.debug("JWT debug endpoint accessed");

        Map<String, Object> debug = new HashMap<>();
        debug.put("headers", jwt.getHeaders());
        debug.put("claims", jwt.getClaims());
        String tokenValue = jwt.getTokenValue();
        debug.put("tokenValue", tokenValue.length() > 20 ? tokenValue.substring(0, 20) + "..." : tokenValue);
        debug.put("issuedAt", jwt.getIssuedAt());
        debug.put("expiresAt", jwt.getExpiresAt());
        debug.put("subject", jwt.getSubject());
        debug.put("issuer", jwt.getIssuer());
        debug.put("audience", jwt.getAudience());

        return ResponseEntity.ok(debug);
    }
}
