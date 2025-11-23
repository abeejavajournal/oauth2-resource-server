package com.abeejavajournal.oauth2.config;

import com.abeejavajournal.oauth2.security.CustomAuthenticationEntryPoint;
import com.abeejavajournal.oauth2.security.CustomBearerTokenAccessDeniedHandler;
import com.abeejavajournal.oauth2.security.JwtAudienceValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;
    
    @Value("${app.security.jwt.audience}")
    private String audience;
    
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final CustomBearerTokenAccessDeniedHandler accessDeniedHandler;

    /**
     * Main security filter chain configuration
     * Demonstrates how OAuth2 Resource Server processes requests
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("Configuring OAuth2 Resource Server security filter chain");
        
        return http
            .csrf(AbstractHttpConfigurer::disable)
            
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            .authorizeHttpRequests(authorize -> authorize

                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/public/**", "/resources/public", "/swagger-ui/**", "/v3/api-docs/**").permitAll()

                .requestMatchers("/admin/**").hasAuthority("SCOPE_admin")
                .requestMatchers("/users/**").hasAnyAuthority("SCOPE_read", "SCOPE_write")

                .anyRequest().authenticated()
            )
            
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDeniedHandler)
            )
            
            .build();
    }

    /**
     * Custom JWT decoder with additional validators
     * This shows how Spring Security validates JWT tokens under the hood
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        log.info("Creating JWT decoder with custom validators");
        
        NimbusJwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(issuerUri);
        
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtAudienceValidator(audience);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(
            defaultValidators, 
            audienceValidator
        );
        
        jwtDecoder.setJwtValidator(withAudience);
        
        return jwtDecoder;
    }

    /**
     * Custom JWT authentication converter
     * Demonstrates how to extract authorities from JWT claims
     */
    @Bean
    public Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
            
            log.debug("Extracted authorities from JWT: {}", authorities);
            return authorities;
        });
        
        converter.setPrincipalClaimName("sub");
        
        return converter;
    }

    /**
     * Extract authorities from JWT claims
     * Demonstrates different strategies for authority extraction
     */
    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();
        Collection<GrantedAuthority> grantedAuthorities = scopesConverter.convert(jwt);
        
        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles != null) {
            List<GrantedAuthority> roleAuthorities = roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toList());
            grantedAuthorities.addAll(roleAuthorities);
        }
        
        List<String> permissions = jwt.getClaimAsStringList("permissions");
        if (permissions != null) {
            List<GrantedAuthority> permissionAuthorities = permissions.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
            grantedAuthorities.addAll(permissionAuthorities);
        }
        
        return grantedAuthorities;
    }

    /**
     * CORS configuration for the resource server
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "https://app.example.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
