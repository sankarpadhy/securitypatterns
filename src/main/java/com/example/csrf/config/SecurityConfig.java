package com.example.csrf.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import jakarta.servlet.http.Cookie;

/**
 * Security configuration class for the CSRF protection demo application.
 * This class configures Spring Security with CSRF protection using cookie-based tokens.
 *
 * Flow Diagram:
 * ============
 *
 * 1. Initial Request for CSRF Token:
 * ---------------------------------
 * Client                    Server
 *   |                         |
 *   |  GET /csrf-token        |
 *   |------------------------>|
 *   |                         | Generate CSRF Token
 *   |                         | Set Cookie: XSRF-TOKEN
 *   |     Token + Cookie      |
 *   |<------------------------|
 *
 * 2. Protected Request Flow:
 * -------------------------
 * Client                    Server
 *   |                         |
 *   |  POST /api/...          |
 *   |  X-XSRF-TOKEN: token    |
 *   |  Cookie: XSRF-TOKEN     |
 *   |------------------------>|
 *   |                         | Validate Token
 *   |                         | Process Request
 *   |      Response           |
 *   |<------------------------|
 *
 * Security Filter Chain:
 * ====================
 * [DisableEncodeUrlFilter]
 *          ↓
 * [SecurityContextFilter]
 *          ↓
 * [CsrfFilter] → Validates CSRF token
 *          ↓
 * [LogoutFilter]
 *          ↓
 * [UsernamePasswordAuthFilter]
 *          ↓
 * [ExceptionTranslationFilter]
 *          ↓
 * [AuthorizationFilter]
 *
 * Key features:
 * - CSRF protection using cookie-based tokens
 * - Custom authentication success/failure handlers
 * - Stateless session management
 * - Secure logout handling
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    /**
     * Configures the security filter chain with CSRF protection.
     * 
     * CSRF Filter Flow:
     * 1. When a request comes in, Spring Security's FilterChainProxy invokes filters in order
     * 2. CsrfFilter is called early in the chain to validate CSRF tokens
     * 3. CsrfTokenRequestAttributeHandler processes the token:
     *    - For GET requests: Generates new token if none exists
     *    - For POST/PUT/DELETE: Validates token from request against stored token
     * 
     * Token Validation Process:
     * 1. CsrfFilter extracts token from request header or parameter
     * 2. Compares it with token from CookieCsrfTokenRepository
     * 3. If tokens don't match → AccessDeniedException
     * 4. If tokens match → request proceeds to next filter
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // Create CSRF token handler
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        // Set the request attribute name where token will be stored
        requestHandler.setCsrfRequestAttributeName("_csrf");

        // Configure CSRF token repository to use cookies
        CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        // Set custom cookie name that client will receive
        tokenRepository.setCookieName("XSRF-TOKEN");
        // Set custom header name that client should use to send token
        tokenRepository.setHeaderName("X-XSRF-TOKEN");

        http
            // Configure CSRF protection
            .csrf(csrf -> csrf
                // Use cookie-based token repository
                .csrfTokenRepository(tokenRepository)
                // Use custom request handler
                .csrfTokenRequestHandler(requestHandler)
                // Disable CSRF protection for specific endpoints (optional, use with caution)
                .ignoringRequestMatchers("/api/auth/logout", "/transfer"))
            // Configure authentication
            .formLogin(form -> form
                .loginProcessingUrl("/api/auth/login")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler()))
            // Configure logout
            .logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .logoutSuccessHandler(logoutSuccessHandler())
                // Clear authentication and cookies
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID", "XSRF-TOKEN"))
            // Configure authorization
            .authorizeHttpRequests(auth -> auth
                // Allow CSRF token endpoint without authentication
                .requestMatchers("/api/auth/csrf-token").permitAll()
                // Allow unauthenticated requests for /, /home, /css/**, /js/**
                .requestMatchers("/", "/home", "/css/**", "/js/**").permitAll()
                // Require authentication for all other requests
                .anyRequest().authenticated())
            // Configure exception handling
            .exceptionHandling(exc -> exc
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));

        return http.build();
    }

    /**
     * When Spring Security processes a request:
     * 1. Request enters FilterChainProxy
     * 2. CsrfFilter checks if request requires CSRF protection:
     *    - GET, HEAD, TRACE, OPTIONS → allowed without token
     *    - POST, PUT, DELETE, PATCH → require valid token
     * 3. If token required:
     *    - Extracts from X-XSRF-TOKEN header or _csrf parameter
     *    - Validates against token in XSRF-TOKEN cookie
     *    - Invalid/missing token → 403 Forbidden
     */
    /**
     * Configures the authentication success handler to return JSON response.
     *
     * @return configured AuthenticationSuccessHandler
     */
    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            response.setStatus(HttpStatus.OK.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"status\":\"success\",\"message\":\"Login successful\"}");
        };
    }

    /**
     * Configures the authentication failure handler to return JSON response with error details.
     *
     * @return configured AuthenticationFailureHandler
     */
    private AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, exception) -> {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"status\":\"error\",\"message\":\"" + exception.getMessage() + "\"}");
        };
    }

    /**
     * Configures the logout success handler to return JSON response.
     *
     * @return configured LogoutSuccessHandler
     */
    private LogoutSuccessHandler logoutSuccessHandler() {
        return (request, response, authentication) -> {
            // Clear XSRF-TOKEN cookie
            Cookie csrfCookie = new Cookie("XSRF-TOKEN", null);
            csrfCookie.setMaxAge(0);
            csrfCookie.setPath("/");
            response.addCookie(csrfCookie);

            // Set response
            response.setStatus(HttpStatus.OK.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"status\":\"success\",\"message\":\"Logout successful\"}");
        };
    }

    /**
     * Configures the authentication manager.
     *
     * @param authConfig the authentication configuration
     * @return configured AuthenticationManager
     * @throws Exception if an error occurs during configuration
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * Configures the user details service with an in-memory user.
     *
     * @return configured UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password(passwordEncoder().encode("password"))
            .roles("USER")
            .build();

        return new InMemoryUserDetailsManager(user);
    }

    /**
     * Configures the password encoder for secure password storage.
     *
     * @return configured PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
