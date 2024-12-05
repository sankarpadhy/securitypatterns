package com.example.csrf.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Test class for TransferController that validates CSRF protection.
 * Tests both successful transfers (with CSRF token) and failed attempts (without CSRF token).
 */
@SpringBootTest
@AutoConfigureMockMvc
public class TransferControllerTest {

    @Autowired
    private MockMvc mockMvc;

    /**
     * Test accessing the home page.
     * Should return the index page successfully.
     */
    @Test
    @WithMockUser
    public void testHomeAccess() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("index"));
    }

    /**
     * Test a successful transfer with valid CSRF token.
     * Should process the transfer and redirect with success message.
     */
    @Test
    @WithMockUser
    public void testTransferWithCsrf() throws Exception {
        mockMvc.perform(post("/transfer")
                .param("recipient", "John Doe")
                .param("amount", "100.00")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"))
                .andExpect(flash().attributeExists("message"))
                .andExpect(flash().attribute("message", "Successfully transferred $100.00 to John Doe"));
    }

    /**
     * Test a transfer attempt without CSRF token.
     * Should be rejected with 403 Forbidden status.
     */
    @Test
    @WithMockUser
    public void testTransferWithoutCsrf() throws Exception {
        mockMvc.perform(post("/transfer")
                .param("recipient", "John Doe")
                .param("amount", "100.00"))
                .andExpect(status().isForbidden());
    }

    /**
     * Test a transfer with invalid parameters.
     * Should return 400 Bad Request.
     */
    @Test
    @WithMockUser
    public void testTransferWithInvalidParams() throws Exception {
        mockMvc.perform(post("/transfer")
                .param("recipient", "")
                .param("amount", "invalid")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest());
    }

    /**
     * Test accessing transfer endpoint without authentication.
     * Should return 401 Unauthorized.
     */
    @Test
    public void testTransferWithoutAuth() throws Exception {
        mockMvc.perform(post("/transfer")
                .param("recipient", "John Doe")
                .param("amount", "100.00")
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isUnauthorized());
    }
}
