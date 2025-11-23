package com.abeejavajournal.oauth2.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;


@Slf4j
@RequiredArgsConstructor
public class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {
    
    private final String expectedAudience;
    
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        log.debug("Validating JWT audience claim");
        
        List<String> audiences = jwt.getAudience();
        
        if (audiences == null || audiences.isEmpty()) {
            log.warn("JWT has no audience claim");
            OAuth2Error error = new OAuth2Error(
                "invalid_audience",
                "The required audience is missing",
                null
            );
            return OAuth2TokenValidatorResult.failure(error);
        }
        
        if (!audiences.contains(expectedAudience)) {
            log.warn("JWT audience {} does not contain expected audience {}", 
                     audiences, expectedAudience);
            OAuth2Error error = new OAuth2Error(
                "invalid_audience",
                String.format("The audience '%s' is not valid", audiences),
                null
            );
            return OAuth2TokenValidatorResult.failure(error);
        }
        
        log.debug("JWT audience validation successful");
        return OAuth2TokenValidatorResult.success();
    }
}
