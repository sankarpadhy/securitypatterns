package com.example.csrf.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * Controller handling authentication and CSRF token operations.
 *
 * Flow Diagram for CSRF Token Generation:
 * =====================================
 *
 * 1. Token Generation Flow:
 * ------------------------
 * Client → GET /api/auth/csrf-token → Controller
 *                                        ↓
 *                                   Generate Token
 *                                        ↓
 *                                   Set Cookie
 *                                        ↓
 * Client ← JSON Response + Cookie ← Controller
 *
 * Response Format:
 * {
 *   "token": "random-csrf-token",
 *   "headerName": "X-XSRF-TOKEN",
 *   "parameterName": "_csrf"
 * }
 *
 * 2. Token Usage Flow:
 * -------------------
 * Client → POST /api/auth/login → Spring Security
 *          Headers:                     ↓
 *          - X-XSRF-TOKEN           Validate Token
 *          - Cookie                     ↓
 *                                   Process Login
 *                                        ↓
 * Client ← Success/Error Response ← Controller
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * Endpoint to retrieve a CSRF token and set it as a cookie.
     * 
     * This endpoint:
     * 1. Retrieves the CSRF token from Spring Security
     * 2. Sets it as a cookie in the response
     * 3. Returns token details in the response body
     *
     * @param token The CSRF token provided by Spring Security
     * @param response The HTTP response object to set the cookie
     * @return ResponseEntity containing token details (token value, header name, parameter name)
     */
    @GetMapping("/csrf-token")
    public ResponseEntity<Map<String, String>> getCsrfToken(CsrfToken token, HttpServletResponse response) {
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("token", token.getToken());
        responseBody.put("headerName", token.getHeaderName());
        responseBody.put("parameterName", token.getParameterName());
        
        Cookie cookie = new Cookie("XSRF-TOKEN", token.getToken());
        cookie.setHttpOnly(false);
        cookie.setSecure(true);
        cookie.setPath("/");
        response.addCookie(cookie);
        
        return ResponseEntity.ok(responseBody);
    }
}
