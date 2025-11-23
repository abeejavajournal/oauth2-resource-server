package com.abeejavajournal.oauth2.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
@Component
@RequiredArgsConstructor
public class CustomBearerTokenAccessDeniedHandler implements AccessDeniedHandler {
    
    private final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, 
                      HttpServletResponse response,
                      AccessDeniedException accessDeniedException) throws IOException, ServletException {
        
        log.error("Access denied: {}", accessDeniedException.getMessage());
        
        Map<String, Object> errorDetails = new LinkedHashMap<>();
        
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        
        // Set WWW-Authenticate header with insufficient_scope error
        response.setHeader("WWW-Authenticate", 
                          "Bearer error=\"insufficient_scope\", " +
                          "error_description=\"The request requires higher privileges than provided by the access token.\"");
        
        errorDetails.put("error", "insufficient_scope");
        errorDetails.put("error_description", 
                        "The request requires higher privileges than provided by the access token");
        errorDetails.put("timestamp", Instant.now().toString());
        errorDetails.put("path", request.getRequestURI());
        errorDetails.put("method", request.getMethod());
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            
            errorDetails.put("subject", jwt.getSubject());
            errorDetails.put("current_authorities", 
                           authentication.getAuthorities().stream()
                               .map(Object::toString)
                               .collect(Collectors.toList()));
            
            log.debug("Access denied for subject: {} with authorities: {}",
                     jwt.getSubject(), authentication.getAuthorities());
        }
        
        errorDetails.put("message", "You don't have permission to access this resource");
        errorDetails.put("trace_id", request.getHeader("X-Trace-Id"));
        
        objectMapper.writeValue(response.getOutputStream(), errorDetails);
    }
}
