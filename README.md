# Cross-Site Request Forgery (CSRF) Protection Tutorial

## Learning Objectives
By the end of this tutorial, you will:
1. Understand CSRF attacks and their impact on web security
2. Learn how to implement CSRF protection in Spring Boot applications
3. Master best practices for token-based security
4. Build a secure money transfer application with CSRF protection

## Prerequisites
- Basic knowledge of Spring Boot
- Understanding of web security concepts
- Java development environment setup
- Maven installed
- IDE (preferably IntelliJ IDEA or Eclipse)

## Project Context
Imagine you're building a banking application where users can transfer money. Without proper CSRF protection, attackers could trick users into making unauthorized transfers. This tutorial demonstrates how to prevent such attacks.

## Step-by-Step Implementation Guide

### Step 1: Project Setup
1. Create a new Spring Boot project:
   ```bash
   mvn archetype:generate \
     -DgroupId=com.example.csrf \
     -DartifactId=csrf-protection \
     -DarchetypeArtifactId=maven-archetype-quickstart \
     -DinteractiveMode=false
   ```

2. Add dependencies to `pom.xml`:
   ```xml
   <dependencies>
       <dependency>
           <groupId>org.springframework.boot</groupId>
           <artifactId>spring-boot-starter-web</artifactId>
       </dependency>
       <dependency>
           <groupId>org.springframework.boot</groupId>
           <artifactId>spring-boot-starter-security</artifactId>
       </dependency>
       <dependency>
           <groupId>org.springframework.boot</groupId>
           <artifactId>spring-boot-starter-thymeleaf</artifactId>
       </dependency>
   </dependencies>
   ```

### Step 2: Configure Security
1. Create `SecurityConfig.java`:
   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfig {
       @Bean
       public SecurityFilterChain filterChain(HttpSecurity http) {
           // Configure CSRF token handler
           CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
           requestHandler.setCsrfRequestAttributeName("_csrf");

           // Configure token repository
           CookieCsrfTokenRepository tokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
           tokenRepository.setCookieName("XSRF-TOKEN");
           tokenRepository.setHeaderName("X-XSRF-TOKEN");

           return http
               .csrf(csrf -> csrf
                   .csrfTokenRepository(tokenRepository)
                   .csrfTokenRequestHandler(requestHandler))
               // ... other security configurations
               .build();
       }
   }
   ```

### Step 3: Create Frontend Interface
1. Create `index.html`:
   ```html
   <!DOCTYPE html>
   <html xmlns:th="http://www.thymeleaf.org">
   <head>
       <title>Secure Money Transfer</title>
   </head>
   <body>
       <!-- Login Form -->
       <form id="loginForm">
           <input type="text" name="username" />
           <input type="password" name="password" />
           <button type="submit">Login</button>
       </form>

       <!-- Transfer Form -->
       <form id="transferForm">
           <input type="text" name="recipient" />
           <input type="number" name="amount" />
           <button type="submit">Transfer</button>
       </form>

       <script>
           // CSRF token handling
           let csrfToken;
           
           // Fetch CSRF token
           async function fetchCsrfToken() {
               const response = await fetch('/api/auth/csrf-token');
               csrfToken = await response.json();
           }
           
           // Initialize on page load
           fetchCsrfToken();
       </script>
   </body>
   </html>
   ```

### Step 4: Implement Controllers
1. Create `AuthController.java`:
   ```java
   @RestController
   @RequestMapping("/api/auth")
   public class AuthController {
       @GetMapping("/csrf-token")
       public CsrfToken getCsrfToken(CsrfToken token) {
           return token;
       }
   }
   ```

2. Create `TransferController.java`:
   ```java
   @RestController
   public class TransferController {
       @PostMapping("/transfer")
       public ResponseEntity<?> transfer(@RequestParam String recipient, 
                                       @RequestParam BigDecimal amount) {
           // Transfer logic here
           return ResponseEntity.ok().build();
       }
   }
   ```

### Step 5: Testing Your Implementation
1. Run the application:
   ```bash
   mvn spring-boot:run
   ```

2. Test CSRF protection:
   - Log in with username: "user", password: "password"
   - Try making a transfer
   - Verify CSRF token in browser dev tools
   - Attempt transfer without token (should fail)

## Common Pitfalls and Solutions

### 1. Token Not Being Sent
Problem: CSRF token not included in requests
Solution: Ensure proper token extraction and inclusion in headers:
```javascript
fetch('/transfer', {
    method: 'POST',
    headers: {
        [csrfToken.headerName]: csrfToken.token
    }
});
```

### 2. Token Validation Failures
Problem: Server rejecting valid tokens
Solution: Check token configuration:
```java
tokenRepository.setCookieName("XSRF-TOKEN");
tokenRepository.setHeaderName("X-XSRF-TOKEN");
```

## Best Practices Checklist
- [ ] Use HTTPS in production
- [ ] Implement proper error handling
- [ ] Clear tokens on logout
- [ ] Use secure cookie settings
- [ ] Implement request logging
- [ ] Add comprehensive testing

## Troubleshooting Guide
1. **403 Forbidden Error**
   - Check if CSRF token is present in request
   - Verify token header name matches configuration
   - Ensure token hasn't expired

2. **Token Not Generated**
   - Verify security configuration
   - Check if token endpoint is accessible
   - Confirm cookie settings

## Learning Resources
1. **Official Documentation**
   - [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
   - [OWASP CSRF Guide](https://owasp.org/www-community/attacks/csrf)

2. **Additional Reading**
   - [Understanding CSRF Attacks](https://portswigger.net/web-security/csrf)
   - [Token-Based Authentication](https://auth0.com/learn/token-based-authentication-made-easy/)

## Next Steps
1. Add more security features:
   - Rate limiting
   - Input validation
   - Audit logging

2. Enhance the application:
   - Add user management
   - Implement transaction history
   - Add email notifications

## Support
- Create an issue in the GitHub repository
- Join our community discussions
- Check the FAQ section

## Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License
MIT License - Feel free to use this code for learning and development

Remember: Security is a continuous process. Stay updated with the latest security practices and regularly review your implementation.
