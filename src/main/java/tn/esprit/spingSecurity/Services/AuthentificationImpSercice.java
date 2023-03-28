package tn.esprit.spingSecurity.Services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import tn.esprit.spingSecurity.Entities.Enum.ERole;
import tn.esprit.spingSecurity.Entities.Role;
import tn.esprit.spingSecurity.Entities.User;
import tn.esprit.spingSecurity.Interface.AuthentificationUser;
import tn.esprit.spingSecurity.Payload.request.LoginRequest;
import tn.esprit.spingSecurity.Payload.request.SignupRequest;
import tn.esprit.spingSecurity.Payload.response.JwtResponse;
import tn.esprit.spingSecurity.Payload.response.MessageResponse;
import tn.esprit.spingSecurity.Repository.RoleRepository;
import tn.esprit.spingSecurity.Repository.UserRepository;
import tn.esprit.spingSecurity.Security.JWT.JwtUtils;
import tn.esprit.spingSecurity.Security.Services.UserDetailsImpl;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthentificationImpSercice implements AuthentificationUser {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder encoder;

    private final JwtUtils jwtUtils;

    private final JavaMailSender javaMailSender;

    private final UserDetailsService userDetailsService;
    private final Map<String, Integer> loginAttempts = new HashMap<>();


    @Override
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) throws MessagingException {
        String username = loginRequest.getUsername();
        Integer attempts = loginAttempts.getOrDefault(username, 0);

        if (attempts >= 3) {
            User user = userRepository.findUserByUsername(username);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Too many failed login attempts!"));
            }
            String email = user.getEmail();
            if (StringUtils.isEmpty(email)) {
                System.out.println("Alert: Too many failed login attempts for user " + username + ", but no email address available to send alert to.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Too many failed login attempts!"));
            }
            System.out.println("Alert: Too many failed login attempts for user " + username);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Too many failed login attempts! Please check your email for further instructions."));
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (BadCredentialsException e) {
            loginAttempts.put(username, attempts + 1);
            if (attempts + 1 >= 3) {
                // Génération du code de vérification
                User user = userRepository.findUserByUsername(username);
                int verificationCode = (int) (Math.random() * 90000000) + 10000000;

                user.setVerificationCode(verificationCode);
                user.setVerified(false);
                userRepository.save(user);
                String to = user.getEmail();
                String subject = "Tentatives de connexion infructueuses";
                String body = "<html><body style='font-family: Arial, sans-serif;'>"
                        + "<p style='color: #1c87c9; font-size: 18px;'>Dear " + user.getUsername() + ",</p>"
                        + "<p style='color: #333333; font-size: 16px;'>We have detected multiple invalid password attempts on your account. As a security measure, we have disabled your account temporarily.</p>"
                        + "<table style='border-collapse: collapse;'><tr>"
                        + "<td style='border: 1px solid #1E90FF; padding: 10px; color: #008000; font-size: 16px; font-weight: bold;'>Verification Code:</td>"
                        + "<td style='border: 1px solid #1E90FF; padding: 10px; color: #DC143C; font-size: 16px; font-weight: bold;'>" + verificationCode + "</td>"
                        + "</tr></table>"
                        + "<p style='color: #333333; font-size: 16px;'>To regain access to your account, please use the verification code provided above.</p>"
                        + "<p style='color: #333333; font-size: 16px;'>Thank you for your cooperation.</p>"
                        + "<p style='color: #333333; font-size: 16px;'>Sincerely,</p>"
                        + "<p style='color: #DC143C; font-size: 16px;'>The Account Recovery Team</p>"
                        + "</body></html>";

                MimeMessage message = javaMailSender.createMimeMessage();
                MimeMessageHelper helper = new MimeMessageHelper(message, true);
                helper.setTo(to);
                helper.setSubject(subject);
                helper.setText(body, true);
                javaMailSender.send(message);
                if (user == null) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid username or password!"));
                }
                String email = user.getEmail();
                if (StringUtils.isEmpty(email)) {
                    System.out.println("Alert: Too many failed login attempts for user " + username + ", but no email address available to send alert to.");
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Too many failed login attempts!"));
                }
                loginAttempts.put(username, 0);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Too many failed login attempts! Please check your email for further instructions."));
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid username or password!"));
        }
        UserDetailsImpl userDetails = (UserDetailsImpl) userDetailsService.loadUserByUsername(loginRequest.getUsername());
        if (!userDetails.isVerified()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new MessageResponse("Error: Account not verified!"));
        }
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        ResponseCookie jwt = jwtUtils.generateJwtCookie(userDetails);
        if (!encoder.matches(loginRequest.getPassword(), userDetails.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid password!"));
        }
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwt.toString())
                .body(new JwtResponse(jwt.toString(),
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getEmail(),
                        userDetails.getProfile(),
                        roles));
    }

    @Override
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest, HttpServletRequest request) throws MessagingException {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        User user = null;
        try {
            user = new User(signUpRequest.getNom(), signUpRequest.getPrenom(), signUpRequest.getUsername(),
                    signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()),
                    new SimpleDateFormat("dd/MM/yyyy").parse(signUpRequest.getDateNaissance())
            );
        } catch (ParseException e) {
            e.printStackTrace();
        }

        int verificationCode = (int) (Math.random() * 90000000) + 10000000;

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null || strRoles.isEmpty()) {
            Role userRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseGet(() -> roleRepository.save(new Role(ERole.ROLE_ADMIN)));
            roles.add(userRole);
        } else {
            for (String roleName : strRoles) {
                if (ERole.ROLE_ADMIN.name().equals(roleName)) {

                    Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                            .orElseGet(() -> roleRepository.save(new Role(ERole.ROLE_ADMIN)));
                    roles.add(adminRole);
                } else if (ERole.ROLE_ETUDIANT.name().equals(roleName)) {
                    Role modRole = roleRepository.findByName(ERole.ROLE_ETUDIANT)
                            .orElseGet(() -> roleRepository.save(new Role(ERole.ROLE_ETUDIANT)));
                    roles.add(modRole);
                } else if (ERole.ROLE_UNIVERSITE.name().equals(roleName)) {
                    Role userRole = roleRepository.findByName(ERole.ROLE_UNIVERSITE)
                            .orElseGet(() -> roleRepository.save(new Role(ERole.ROLE_UNIVERSITE)));
                    roles.add(userRole);
                }
            }
        }

        user.setRoles(roles);

        user.setVerificationCode(verificationCode);

        userRepository.save(user);

        String appUrl = request.getScheme() + "://" + request.getServerName();
        String message = "<html><body><p>Bonjour " + signUpRequest.getNom() + ",</p>" +
                "<p>Votre inscription sur notre site a été effectuée avec succès.</p>" +
                "<p>Veuillez cliquer sur le lien suivant pour vérifier votre compte :</p>" +
                "<table border='1'><tr><td>URL</td><td>" + appUrl + "/ToBuySignUp/verify?code=" + verificationCode + "</td></tr>" +
                "<tr><td>Code de vérification</td><td>" + verificationCode + "</td></tr></table>" +
                "<p>Merci de votre confiance.</p></body></html>";

        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(signUpRequest.getEmail());
        mailMessage.setSubject("Inscription réussie");
        mailMessage.setText("Un email de confirmation vous a été envoyé à l'adresse " + signUpRequest.getEmail() + ". Veuillez suivre les instructions pour vérifier votre compte.");

        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, true, "UTF-8");
        helper.setTo(mailMessage.getTo());
        helper.setSubject(mailMessage.getSubject());
        helper.setText(message, true);

        javaMailSender.send(mimeMessage);

        String responseMessage = "Un email de confirmation a été envoyé à l'adresse " + signUpRequest.getEmail() + ". " +
                "Veuillez suivre les instructions pour vérifier votre compte.";

        return ResponseEntity.ok(new MessageResponse(responseMessage));
    }

    @Override
    public ResponseEntity<?> verifySignUp(int code) {
        User user = userRepository.findByVerificationCode(code);
        if (user == null) {
            return ResponseEntity.badRequest().body(new MessageResponse("Code de vérification invalide."));
        }

        user.setVerified(true);
        user.setVerificationCode(0);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("Votre compte a été vérifié avec succès."));
    }

    @Override
    public ResponseEntity<?> logoutUser() {
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("You've been signed out!"));
    }
}

