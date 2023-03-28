package tn.esprit.spingSecurity.Controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tn.esprit.spingSecurity.Payload.request.LoginRequest;
import tn.esprit.spingSecurity.Payload.request.SignupRequest;
import tn.esprit.spingSecurity.Services.AuthentificationImpSercice;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthentificationImpSercice authentificationImpSercice;


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) throws MessagingException {
        return authentificationImpSercice.authenticateUser(loginRequest);
    }
    @PostMapping("/signup")
    public ResponseEntity<?> addAdmin(@Valid @RequestBody SignupRequest signUpRequest, HttpServletRequest request) throws MessagingException {
        return authentificationImpSercice.registerUser(signUpRequest, request);
    }
    @GetMapping("/SignUp/verify")
    public ResponseEntity<?> verifySignUp(@RequestParam int code) {
        return authentificationImpSercice.verifySignUp(code);
    }

    @PostMapping("/deconnection")
    public ResponseEntity<?> deconnection() {
        return authentificationImpSercice.logoutUser();
    }
}
