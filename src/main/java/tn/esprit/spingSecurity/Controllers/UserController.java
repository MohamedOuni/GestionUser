package tn.esprit.spingSecurity.Controllers;

import lombok.RequiredArgsConstructor;
import org.hibernate.procedure.spi.ParameterRegistrationImplementor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import tn.esprit.spingSecurity.Entities.User;
import tn.esprit.spingSecurity.Payload.request.ForgotPassRequest;
import tn.esprit.spingSecurity.Payload.request.ResetPassRequest;
import tn.esprit.spingSecurity.Payload.response.MessageResponse;
import tn.esprit.spingSecurity.Repository.UserRepository;
import tn.esprit.spingSecurity.Services.UserImpSercice;

import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

import static com.sun.mail.imap.protocol.BASE64MailboxDecoder.decode;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/users")
public class UserController {


    private final UserImpSercice userImpSercice;
    private final UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder;


    @Transactional
    @PutMapping("/modifieruser")
    public ResponseEntity<?> updateUser(@RequestBody User updatedUser,
                                        @RequestParam("password") String password,
                                        @AuthenticationPrincipal UserDetails userDetails) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUserName = authentication.getName();
        User currentUser = userRepository.findUserByUsername(currentUserName);
        if (currentUser == null) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Vous devez se connecter"));
        }
        User savedUser = userImpSercice.updateUser(userDetails, updatedUser, password);
        return ResponseEntity.ok(savedUser);
    }

    @GetMapping("/MyProfile")
    public ResponseEntity<?> getMyProfile(@AuthenticationPrincipal UserDetails userDetails) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUserName = authentication.getName();
        User currentUser = userRepository.findUserByUsername(currentUserName);
        if (currentUser == null) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Vous devez se connecter"));
        }
        User getUser = userImpSercice.getMyProfile(userDetails);
        return ResponseEntity.ok(getUser);
    }


    @Transactional
    @DeleteMapping("/Delete")
    public ResponseEntity<Void> deleteUser(@AuthenticationPrincipal UserDetails userDetails, @RequestParam String currentPassword) {
        String currentUsername = userDetails.getUsername();
        User user = userRepository.findUserByUsername(currentUsername);
        if (user != null && passwordEncoder.matches(decode(currentPassword), user.getPassword())) {
            userRepository.delete(user);
            return ResponseEntity.noContent().build();
        } else {
            throw new IllegalArgumentException("Invalid username or password.");
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPassRequest forgotPassRequest, HttpServletRequest request) {
        return userImpSercice.forgotPassword(forgotPassRequest,request);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPassRequest resetPassRequest) {
        return userImpSercice.resetPassword(resetPassRequest);
    }
}
