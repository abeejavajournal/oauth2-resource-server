package com.abeejavajournal.oauth2.controller;

import com.abeejavajournal.oauth2.dto.ResourceDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("OAuth2 Resource Server Integration Tests")
class ResourceControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private JwtDecoder jwtDecoder;

    private ResourceDto testResource;

    @BeforeEach
    void setUp() {
        testResource = ResourceDto.builder()
            .name("Test Resource")
            .description("Resource for testing")
            .type("TEST")
            .ownerId("user123")
            .build();
    }

    @Test
    @DisplayName("Should access public endpoint without authentication")
    void testPublicEndpoint() throws Exception {
        mockMvc.perform(get("/resources/public"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("This is a public resource"))
            .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    @DisplayName("Should return 401 when accessing protected endpoint without token")
    void testProtectedEndpointWithoutToken() throws Exception {
        mockMvc.perform(get("/resources"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().exists("WWW-Authenticate"));
    }

    @Test
    @DisplayName("Should access protected endpoint with valid JWT token")
    void testProtectedEndpointWithValidToken() throws Exception {
        mockMvc.perform(get("/resources")
                .with(jwt()
                    .jwt(builder -> builder
                        .subject("user123")
                        .claim("email", "user@example.com")
                        .claim("scope", "read write")
                        .audience(List.of("api://default"))
                    )
                    .authorities(new SimpleGrantedAuthority("SCOPE_read"))
                ))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$", hasSize(2)))
            .andExpect(jsonPath("$[0].name").value("Resource 1"));
    }

    @Test
    @DisplayName("Should return user info for authenticated user")
    void testGetAuthenticatedUserInfo() throws Exception {
        mockMvc.perform(get("/resources/authenticated")
                .with(jwt()
                    .jwt(builder -> builder
                        .subject("user123")
                        .claim("email", "user@example.com")
                        .claim("name", "Test User")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(3600))
                    )))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.subject").value("user123"))
            .andExpect(jsonPath("$.email").value("user@example.com"))
            .andExpect(jsonPath("$.name").value("Test User"));
    }

    @Test
    @DisplayName("Should create resource with write scope")
    void testCreateResourceWithWriteScope() throws Exception {
        mockMvc.perform(post("/resources")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testResource))
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_write"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.id").exists())
            .andExpect(jsonPath("$.name").value(testResource.getName()))
            .andExpect(jsonPath("$.createdAt").exists());
    }

    @Test
    @DisplayName("Should return 403 when creating resource without write scope")
    void testCreateResourceWithoutWriteScope() throws Exception {
        mockMvc.perform(post("/resources")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(testResource))
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_read"))))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.error").value("insufficient_scope"));
    }

    @Test
    @DisplayName("Should delete resource with admin scope")
    void testDeleteResourceWithAdminScope() throws Exception {
        mockMvc.perform(delete("/resources/resource123")
                .with(jwt().authorities(new SimpleGrantedAuthority("SCOPE_admin"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Resource deleted successfully"))
            .andExpect(jsonPath("$.resourceId").value("resource123"));
    }

    @Test
    @DisplayName("Should return 403 when deleting resource without admin scope")
    void testDeleteResourceWithoutAdminScope() throws Exception {
        mockMvc.perform(delete("/resources/resource123")
                .with(jwt().authorities(
                    new SimpleGrantedAuthority("SCOPE_read"),
                    new SimpleGrantedAuthority("SCOPE_write")
                )))
            .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should access admin endpoint with ADMIN role")
    void testAdminEndpointWithAdminRole() throws Exception {
        mockMvc.perform(get("/resources/admin")
                .with(jwt()
                    .jwt(builder -> builder
                        .subject("admin123")
                        .claim("roles", "ADMIN"))
                    .authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Admin resource accessed"));
    }

    @Test
    @DisplayName("Should debug JWT claims")
    void testDebugJwtEndpoint() throws Exception {
        mockMvc.perform(get("/resources/debug/jwt")
                .with(jwt()
                    .jwt(builder -> builder
                        .subject("user123")
                        .issuer("https://auth.example.com")
                        .audience(List.of("api://default"))
                        .claim("custom_claim", "custom_value"))
                    .authorities(new SimpleGrantedAuthority("SCOPE_read"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.subject").value("user123"))
            .andExpect(jsonPath("$.issuer").value("https://auth.example.com"))
            .andExpect(jsonPath("$.claims.custom_claim").value("custom_value"));
    }


    @Test
    @WithMockUser(username = "user123", authorities = {"SCOPE_read", "SCOPE_write"})
    @DisplayName("Should test with mock user annotation")
    void testWithMockUserAnnotation() throws Exception {
        mockMvc.perform(get("/resources"))
            .andExpect(status().isOk());
    }

}
