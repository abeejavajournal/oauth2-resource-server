package com.abeejavajournal.oauth2.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserInfoDto {
    
    private String subject;
    private String email;
    private String name;
    private String username;
    private Instant issuedAt;
    private Instant expiresAt;
    private List<String> authorities;
    private Map<String, Object> claims;
}
