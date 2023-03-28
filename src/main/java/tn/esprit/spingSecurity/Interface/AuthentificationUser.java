package tn.esprit.spingSecurity.Interface;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import tn.esprit.spingSecurity.Payload.request.LoginRequest;
import tn.esprit.spingSecurity.Payload.request.SignupRequest;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

public interface AuthentificationUser {
    ResponseEntity<?> logoutUser();
    ResponseEntity<?> authenticateUser(LoginRequest loginRequest) throws MessagingException;
    ResponseEntity<?> registerUser(SignupRequest signUpRequest, HttpServletRequest request) throws MessagingException;
    ResponseEntity<?> verifySignUp(int code);
}
