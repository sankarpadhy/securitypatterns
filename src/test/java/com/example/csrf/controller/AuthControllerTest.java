package com.example.csrf.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the AuthController class.
 * 
 * These tests verify:
 * - CSRF token generation and cookie setting
 * - Authentication success/failure scenarios
 * - CSRF protection enforcement
 */
@SpringBootTest
@AutoConfigureMockMvc
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * Tests successful login with valid credentials and CSRF token.
     * 
     * Verifies:
     * - HTTP 200 status code
     * - JSON response format
     * - Success message in response
     */
    @Test
    public void loginSuccess() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "user")
                .param("password", "password"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.status").value("success"))
            .andExpect(jsonPath("$.message").value("Login successful"))
            .andReturn();
    }

    /**
     * Tests login failure with invalid credentials.
     * 
     * Verifies:
     * - HTTP 401 status code
     * - JSON response format
     * - Error status in response
     */
    @Test
    public void loginFailure() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "user")
                .param("password", "wrongpassword"))
            .andExpect(status().isUnauthorized())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.status").value("error"))
            .andReturn();
    }

    /**
     * Tests that requests without CSRF token are rejected.
     * 
     * Verifies:
     * - HTTP 403 status code for missing CSRF token
     */
    @Test
    public void loginWithoutCsrf() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "user")
                .param("password", "password"))
            .andExpect(status().isForbidden())
            .andReturn();
    }

    /**
     * Tests CSRF token generation and cookie setting.
     * 
     * Verifies:
     * - HTTP 200 status code
     * - JSON response format
     * - Token details in response
     * - CSRF cookie presence
     */
    @Test
    public void getCsrfToken() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/auth/csrf-token"))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(jsonPath("$.token").exists())
            .andExpect(jsonPath("$.headerName").exists())
            .andExpect(jsonPath("$.parameterName").exists())
            .andExpect(cookie().exists("XSRF-TOKEN"))
            .andReturn();
    }
}
