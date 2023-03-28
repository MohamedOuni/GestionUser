package tn.esprit.spingSecurity.Services;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import tn.esprit.spingSecurity.Entities.User;
import tn.esprit.spingSecurity.Interface.UserService;
import tn.esprit.spingSecurity.Payload.request.ForgotPassRequest;
import tn.esprit.spingSecurity.Payload.request.ResetPassRequest;
import tn.esprit.spingSecurity.Payload.response.MessageResponse;
import tn.esprit.spingSecurity.Repository.UserRepository;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;

import static com.sun.mail.imap.protocol.BASE64MailboxDecoder.decode;


@Service
@RequiredArgsConstructor
public class UserImpSercice implements UserService {

    private final UserRepository userRepository;

    private final JavaMailSender javaMailSender;
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPassRequest forgotPassRequest, HttpServletRequest request) {
        if (!userRepository.existsByEmail(forgotPassRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Il n'existe aucun utilisateur avec cet email, vérifiez vos données"));
        } else {
            User user = userRepository.findByEmail(forgotPassRequest.getEmail());

            int code = (int) (Math.random() * 90000000) + 10000000;

            user.setResetpasswordcode(String.valueOf(code));
            user.setVerified(false);
            userRepository.save(user);

            MimeMessage message = javaMailSender.createMimeMessage();
            try {
                MimeMessageHelper helper = new MimeMessageHelper(message, true);
                helper.setSubject("Réinitialisation de mot de passe");
                helper.setTo(forgotPassRequest.getEmail());

                String codeTable = "<table style=\"border: 2px solid #068fdc; font-weight: bold;\">";
                codeTable += "<tr><td style=\"padding: 10px; color: #ec0a0a; border-right: 1px solid black;\">Code de vérification:</td><td style=\"padding: 10px;\"> " + code + " </td></tr>";
                codeTable += "<tr><td style=\"padding: 10px; color: #ec0a0a; border-right: 1px solid black;\">Verification avec Url:</td><td style=\"padding: 10px;\"> " +
                        "<a href=\"http://localhost:8888/api/users/reset-password?code=" + code + "\">http://localhost:8888/api/users/reset-password?code=" + code + "</a></td></tr>";
                codeTable += "</table>";

                String text = "<html><body>";
                text += "<p>Bonjour,</p>";
                text += "<p>Vous trouvez ci-joint un code de vérification pour réinitialiser votre mot de passe:</p>";
                text += codeTable;
                text += "<p>Cordialement,</p>";
                text += "<p>L'équipe de support</p>";
                text += "</body></html>";
                helper.setText(text, true);

                javaMailSender.send(message);

                return ResponseEntity.ok().body(new MessageResponse("Code de vérification envoyé avec succès!"));

            } catch (MessagingException e) {
                e.printStackTrace();
                return ResponseEntity.badRequest().body(new MessageResponse("Erreur lors de l'envoi du message"));
            }
        }
    }

    @Override
    public ResponseEntity<?> resetPassword(@RequestBody ResetPassRequest resetPassRequest) {
        if (!userRepository.existsByEmail(resetPassRequest.getEmail()) ){
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("il n'existe aucun utilisateur avec cet email, vérifiez vos données"));
        }
        User user = userRepository.findByEmail(resetPassRequest.getEmail());

        if (!user.getResetpasswordcode().equals(resetPassRequest.getResetpasswordcode())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new MessageResponse("Invalid verification code!"));
        }

        user.setPassword(passwordEncoder.encode(resetPassRequest.getPassword()));
        user.setVerified(true);
        userRepository.save(user);

        return ResponseEntity.ok().body(new MessageResponse("Password reset successful!"));
    }

    @Override
    public User updateUser(@AuthenticationPrincipal UserDetails userDetails, User updatedUser, String password) {
        String currentUsername = userDetails.getUsername();
        User user = userRepository.findUserByUsername(currentUsername);

        if (!passwordEncoder.matches(decode(password),user.getPassword())) {
            throw new IllegalArgumentException("Current password is incorrect");
        }

        user.setNom(updatedUser.getNom());
        user.setPrenom(updatedUser.getPrenom());
        user.setEmail(updatedUser.getEmail());
        user.setDateNaissance(updatedUser.getDateNaissance());
        return userRepository.save(user);
    }

    @Override
    public User getMyProfile(UserDetails userDetails) {
        String cuurentname = userDetails.getUsername();
        User user = userRepository.findUserByUsername(cuurentname);
        return user;
    }
}
