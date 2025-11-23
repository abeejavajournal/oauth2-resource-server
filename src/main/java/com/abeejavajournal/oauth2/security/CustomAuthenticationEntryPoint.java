package com.abeejavajournal.oauth2.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    
    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, 
                        HttpServletResponse response,
                        AuthenticationException authException) throws IOException, ServletException {
        
        log.error("Authentication failed: {}", authException.getMessage());
        
        Map<String, Object> errorDetails = new LinkedHashMap<>();
        
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        if (authException instanceof OAuth2AuthenticationException) {
            OAuth2AuthenticationException oauthException = (OAuth2AuthenticationException) authException;
            OAuth2Error error = oauthException.getError();
            
            // Set WWW-Authenticate header as per RFC 6750
            String wwwAuthenticate = computeWWWAuthenticateHeaderValue(error);
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
            
            if (error instanceof BearerTokenError) {
                BearerTokenError bearerTokenError = (BearerTokenError) error;
                response.setStatus(bearerTokenError.getHttpStatus().value());
                errorDetails.put("error", bearerTokenError.getErrorCode());
                errorDetails.put("error_description", bearerTokenError.getDescription());
                errorDetails.put("error_uri", bearerTokenError.getUri());
            } else {
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                errorDetails.put("error", error.getErrorCode());
                errorDetails.put("error_description", error.getDescription());
                errorDetails.put("error_uri", error.getUri());
            }
        } else {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            errorDetails.put("error", "unauthorized");
            errorDetails.put("error_description", authException.getMessage());
        }
        
        errorDetails.put("timestamp", Instant.now().toString());
        errorDetails.put("path", request.getRequestURI());
        errorDetails.put("trace_id", request.getHeader("X-Trace-Id"));
        
        log.debug("Sending authentication error response: {}", errorDetails);
        
        objectMapper.writeValue(response.getOutputStream(), errorDetails);
    }
    
    /**
     * Compute WWW-Authenticate header value according to RFC 6750
     */
    private String computeWWWAuthenticateHeaderValue(OAuth2Error error) {
        StringBuilder wwwAuthenticate = new StringBuilder();
        wwwAuthenticate.append("Bearer");
        
        if (error != null) {
            if (error.getErrorCode() != null) {
                wwwAuthenticate.append(" error=\"").append(error.getErrorCode()).append("\"");
            }
            
            if (error.getDescription() != null) {
                wwwAuthenticate.append(", error_description=\"")
                              .append(error.getDescription()).append("\"");
            }
            
            if (error.getUri() != null) {
                wwwAuthenticate.append(", error_uri=\"").append(error.getUri()).append("\"");
            }
            
            if (error instanceof BearerTokenError) {
                BearerTokenError bearerTokenError = (BearerTokenError) error;
                if (bearerTokenError.getScope() != null) {
                    wwwAuthenticate.append(", scope=\"")
                                  .append(bearerTokenError.getScope()).append("\"");
                }
            }
        }
        
        return wwwAuthenticate.toString();
    }
}
