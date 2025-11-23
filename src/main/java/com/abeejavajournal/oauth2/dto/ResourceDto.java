package com.abeejavajournal.oauth2.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResourceDto {
    
    private String id;
    private String name;
    private String description;
    private String type;
    private String ownerId;
    private Instant createdAt;
    private Instant updatedAt;
    private Object metadata;
}
