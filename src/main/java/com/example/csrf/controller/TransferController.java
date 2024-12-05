package com.example.csrf.controller;

import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.math.BigDecimal;

/**
 * TransferController demonstrates a real-world scenario where CSRF protection is crucial.
 * It simulates a money transfer functionality that could be vulnerable to CSRF attacks
 * if not properly protected.
 *
 * Security Flow:
 * -------------
 * 1. Initial Page Load:
 *    Client → GET / → Server returns index.html with CSRF token
 *    - Token embedded in form as hidden field
 *    - Token stored in cookie XSRF-TOKEN
 *
 * 2. Transfer Request:
 *    Client → POST /transfer + CSRF token → Server
 *    - Request must include valid CSRF token
 *    - Token validated by CsrfFilter before reaching controller
 *
 * Protection Against CSRF:
 * ----------------------
 * 1. Synchronizer Token Pattern:
 *    - Each form submission requires a valid CSRF token
 *    - Tokens are cryptographically secure random values
 *    - Tokens validated server-side by Spring Security
 *
 * 2. Double Submit Cookie:
 *    - Token sent in both cookie and request header/parameter
 *    - Prevents cross-origin attacks due to Same-Origin Policy
 *
 * Example Attack Scenario (Prevented):
 * ---------------------------------
 * 1. Attacker creates malicious site with auto-submit form
 * 2. Form targets /transfer endpoint
 * 3. User visits malicious site while authenticated
 * 4. Attack fails because:
 *    - Malicious site cannot read CSRF cookie (Same-Origin Policy)
 *    - Request rejected without valid token
 */
@Controller
public class TransferController {

    /**
     * Serves the main page containing the transfer form.
     * Spring Security automatically adds CSRF token to the model.
     *
     * @return view name for the index page
     */
    @GetMapping("/")
    public String showTransferForm() {
        return "index";
    }

    /**
     * Processes money transfer requests.
     * This endpoint is protected against CSRF attacks by Spring Security's CSRF filter.
     * The filter validates the CSRF token before this method is called.
     *
     * @param recipient who receives the transfer
     * @param amount amount to transfer
     * @param redirectAttributes for flash messages
     * @return redirects to home page with status message
     */
    @PostMapping("/transfer")
    public String handleTransfer(
            @RequestParam String recipient,
            @RequestParam String amount,
            RedirectAttributes redirectAttributes) {
        
        try {
            // Validate amount
            BigDecimal transferAmount = new BigDecimal(amount);
            if (transferAmount.compareTo(BigDecimal.ZERO) <= 0) {
                redirectAttributes.addFlashAttribute("error", "Amount must be greater than zero");
                return "redirect:/";
            }

            // Simulate transfer processing
            String successMessage = String.format("Successfully transferred $%s to %s", amount, recipient);
            redirectAttributes.addFlashAttribute("message", successMessage);
            
        } catch (NumberFormatException e) {
            redirectAttributes.addFlashAttribute("error", "Invalid amount");
            return "redirect:/";
        }

        return "redirect:/";
    }

    @ExceptionHandler({InvalidCsrfTokenException.class, MissingCsrfTokenException.class})
    public String handleCsrfError(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("error", "Invalid CSRF Token");
        return "redirect:/";
    }
}
