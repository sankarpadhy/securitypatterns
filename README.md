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

## System Architecture

### Component Overview
```mermaid
graph TB
    subgraph "Client Side"
        B[Browser]
        C[CSRF Token Cookie]
        H[Hidden Form Field]
        SC[Session Cookie]
    end
    
    subgraph "Spring Security Layer"
        F[CsrfFilter]
        V[CsrfTokenValidator]
        R[CsrfTokenRepository]
        AF[AuthenticationFilter]
        AS[AuthenticationService]
    end
    
    subgraph "Application Layer"
        A[Authentication]
        P[Protected Endpoints]
        S[Services]
        U[(User Repository)]
    end

    %% Authentication Flow
    B --1.Login Request--> AF
    AF --2.Validate Credentials--> AS
    AS --3.Check User--> U
    AS --4.Create Session--> SC
    
    %% CSRF Protection Flow
    B --5.Initial Request--> F
    F --6.Generate Token--> R
    R --7.Store Token--> C
    R --8.Include in Response--> H
    
    %% Protected Resource Access
    B --9.Submit with Token--> F
    F --10.Check Session--> AF
    F --11.Extract & Verify--> V
    V --12.If Valid--> P
    P --13.Process--> S
```

### Attack Prevention Workflow
```mermaid
sequenceDiagram
    participant U as User
    participant B as Browser
    participant M as Malicious Site
    participant A as Bank App
    
    Note over U,A: Attack Scenario (Without CSRF Protection)
    U->>B: 1. Log into bank website
    Note over B: User is now authenticated
    U->>M: 2. Visit malicious site
    M->>B: 3. Load page with hidden form
    Note over M: Form targets bank's transfer endpoint
    M->>B: 4. Auto-submit form via JavaScript
    B->>A: 5. POST /transfer (with valid session cookie)
    A->>B: 6. Process transfer (Attack succeeds!)

    Note over U,A: With CSRF Protection
    U->>B: 1. Log into bank website
    B->>A: 2. GET /dashboard
    A->>B: 3. Send CSRF token
    U->>M: 4. Visit malicious site
    M->>B: 5. Auto-submit form
    B->>A: 6. POST without CSRF token
    A->>B: 7. 403 Forbidden (Attack prevented!)
```

### Security Components
```mermaid
graph LR
    subgraph "Frontend Security"
        T[CSRF Token]
        F[Forms]
        A[AJAX Requests]
    end

    subgraph "Security Filters"
        CF[CsrfFilter]
        TR[TokenRepository]
        TV[TokenValidator]
    end

    subgraph "Protected Resources"
        PE[POST Endpoints]
        PU[PUT Endpoints]
        PD[DELETE Endpoints]
    end

    T -->|Included In| F
    T -->|Header X-CSRF-TOKEN| A
    F -->|Submit| CF
    A -->|Submit| CF
    CF -->|Validate| TV
    CF -->|Store/Retrieve| TR
    TV -->|If Valid| PE
    TV -->|If Valid| PU
    TV -->|If Valid| PD
```

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
