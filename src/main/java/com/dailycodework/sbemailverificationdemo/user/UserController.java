package com.dailycodework.sbemailverificationdemo.user;

import com.dailycodework.sbemailverificationdemo.registration.RegistrationRequest;
import com.dailycodework.sbemailverificationdemo.registration.token.VerificationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getUsers();
        return ResponseEntity.ok(users);
    }

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody RegistrationRequest request) {
        User user = userService.registerUser(request);
        String token = UUID.randomUUID().toString();
        userService.saveUserVerificationToken(user, token);
        // Here you can send an email with the verification token
        return ResponseEntity.ok("User registered successfully. Verification token sent to email.");
    }

    @GetMapping("/verify")
    public ResponseEntity<String> verifyUser(@RequestParam("token") String token) {
        String result = userService.validateToken(token);
        if ("valid".equals(result)) {
            return ResponseEntity.ok("User verified successfully.");
        } else {
            return ResponseEntity.badRequest().body(result);
        }
    }

    @PostMapping("/password-reset")
    public ResponseEntity<String> resetPassword(@RequestParam("token") String token,
                                                @RequestParam("newPassword") String newPassword) {
        String validationResult = userService.validatePasswordResetToken(token);
        if (!"valid".equals(validationResult)) {
            return ResponseEntity.badRequest().body("Invalid or expired password reset token.");
        }
        User user = userService.findUserByPasswordToken(token);
        userService.changePassword(user, newPassword);
        return ResponseEntity.ok("Password reset successfully.");
    }

    @PostMapping("/password-reset-request")
    public ResponseEntity<String> requestPasswordReset(@RequestParam("email") String email) {
        var userOptional = userService.findByEmail(email);
        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body("No user associated with this email.");
        }
        User user = userOptional.get();
        String token = UUID.randomUUID().toString();
        userService.createPasswordResetTokenForUser(user, token);
        // Here you can send an email with the reset token
        return ResponseEntity.ok("Password reset link sent to your email.");
    }

    @PostMapping("/change-password")
    public ResponseEntity<String> changePassword(@RequestParam("oldPassword") String oldPassword,
                                                 @RequestParam("newPassword") String newPassword,
                                                 @RequestParam("email") String email) {
        var userOptional = userService.findByEmail(email);
        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body("No user associated with this email.");
        }
        User user = userOptional.get();
        if (!userService.oldPasswordIsValid(user, oldPassword)) {
            return ResponseEntity.badRequest().body("Old password is incorrect.");
        }
        userService.changePassword(user, newPassword);
        return ResponseEntity.ok("Password changed successfully.");
    }

    @PostMapping("/resend-verification-token")
    public ResponseEntity<String> resendVerificationToken(@RequestParam("oldToken") String oldToken) {
        VerificationToken newToken = userService.generateNewVerificationToken(oldToken);
        // Here you can resend the new token to the user via email
        return ResponseEntity.ok("New verification token sent.");
    }
}

