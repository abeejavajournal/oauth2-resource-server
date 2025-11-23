package com.abeejavajournal.oauth2.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

/**
 * Custom Security Service for Resource Access Control
 * 
 * This service demonstrates how to implement custom security logic
 * that can be used with @PreAuthorize annotations.
 * 
 * @author Abir
 */
@Slf4j
@Service("resourceSecurityService")
@RequiredArgsConstructor
public class ResourceSecurityService {

    /**
     * Custom method to check if a user has access to a specific resource
     * This can be used in @PreAuthorize annotations
     */
    public boolean hasAccessToResource(String resourceId, Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            log.debug("User is not authenticated");
            return false;
        }

        // Extract JWT principal
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            String userId = jwt.getSubject();
            
            log.debug("Checking access for user {} to resource {}", userId, resourceId);
            
            // Check if user has admin scope - admins can access all resources
            if (hasScope(authentication, "admin")) {
                log.debug("User has admin scope, granting access");
                return true;
            }
            
            // Check if user is the owner of the resource
            if (isResourceOwner(resourceId, userId)) {
                log.debug("User {} is owner of resource {}", userId, resourceId);
                return true;
            }
            
            // Check if user has been granted explicit access
            if (hasExplicitAccess(resourceId, userId)) {
                log.debug("User {} has explicit access to resource {}", userId, resourceId);
                return true;
            }
            
            // Check organization-based access
            String userOrg = jwt.getClaimAsString("organization");
            if (userOrg != null && hasOrganizationAccess(resourceId, userOrg)) {
                log.debug("User's organization {} has access to resource {}", userOrg, resourceId);
                return true;
            }
        }
        
        log.debug("Access denied for resource {}", resourceId);
        return false;
    }

    /**
     * Check if user has a specific scope
     */
    public boolean hasScope(Authentication authentication, String scope) {
        String scopeAuthority = "SCOPE_" + scope;
        return authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals(scopeAuthority));
    }

    /**
     * Check if user is in a specific role
     */
    public boolean hasRole(Authentication authentication, String role) {
        String roleAuthority = "ROLE_" + role.toUpperCase();
        return authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals(roleAuthority));
    }

    /**
     * Check if user can perform an action on a resource
     */
    public boolean canPerformAction(String action, String resourceId, Authentication authentication) {
        log.debug("Checking if user can perform action {} on resource {}", action, resourceId);
        
        // Map actions to required scopes
        switch (action.toLowerCase()) {
            case "read":
                return hasScope(authentication, "read") || hasScope(authentication, "admin");
            case "write":
            case "update":
                return hasScope(authentication, "write") || hasScope(authentication, "admin");
            case "delete":
                return hasScope(authentication, "admin");
            default:
                return false;
        }
    }

    /**
     * Check if user belongs to a specific group
     */
    public boolean isMemberOfGroup(Authentication authentication, String groupName) {
        if (authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            List<String> groups = jwt.getClaimAsStringList("groups");
            return groups != null && groups.contains(groupName);
        }
        return false;
    }

    /**
     * Simulate checking if user is the owner of a resource
     * In a real application, this would query a database
     */
    private boolean isResourceOwner(String resourceId, String userId) {
        // Simulated logic - in reality, this would check a database
        // For demo purposes, user owns resources starting with their ID
        return resourceId.startsWith(userId);
    }

    /**
     * Simulate checking explicit access grants
     * In a real application, this would query an ACL system
     */
    private boolean hasExplicitAccess(String resourceId, String userId) {
        // Simulated ACL check
        // In reality, this would query an access control list
        List<String> allowedUsers = Arrays.asList("user1", "user2", "user3");
        return allowedUsers.contains(userId);
    }

    /**
     * Simulate checking organization-based access
     */
    private boolean hasOrganizationAccess(String resourceId, String organization) {
        // Simulated organization access check
        // In reality, this would check organization permissions
        List<String> allowedOrgs = Arrays.asList("org1", "org2");
        return allowedOrgs.contains(organization);
    }
}
