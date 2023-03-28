package tn.esprit.spingSecurity.Services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tn.esprit.spingSecurity.Entities.Enum.ERole;
import tn.esprit.spingSecurity.Entities.Role;
import tn.esprit.spingSecurity.Entities.User;
import tn.esprit.spingSecurity.Repository.UserRepository;

import javax.transaction.Transactional;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.sun.mail.imap.protocol.BASE64MailboxDecoder.decode;

@RequiredArgsConstructor
@Service
public class AdminImpSercice {

    private final UserRepository userRepository;

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    public Map<ERole, Integer> getUserRoleStats() {
        Map<ERole, Integer> userRoleStats = new HashMap<>();
        userRoleStats.put(ERole.ROLE_ETUDIANT, 0);
        userRoleStats.put(ERole.ROLE_UNIVERSITE, 0);

        List<User> users = userRepository.findAll();
        for (User user : users) {
            Set<Role> roles = user.getRoles();
            for (Role role : roles) {
                if (role.getName().equals(ERole.ROLE_ETUDIANT)) {
                    userRoleStats.put(ERole.ROLE_ETUDIANT, userRoleStats.get(ERole.ROLE_ETUDIANT) + 1);
                } else if (role.getName().equals(ERole.ROLE_UNIVERSITE)) {
                    userRoleStats.put(ERole.ROLE_UNIVERSITE, userRoleStats.get(ERole.ROLE_UNIVERSITE) + 1);
                }
            }
        }

        return userRoleStats;
    }

    public User getUserById(Long id_user)
    {
        return userRepository.findById(id_user).orElse(null);
    }

    public void deleteUserById(Long id_user)
    {
        userRepository.deleteById(id_user);
    }

    public User GetUserByUsername(String username)
    {
        return userRepository.findUserByUsername(username);
    }

    @Transactional
    public ResponseEntity<Void> DeleteUserCoteAdmin(String currentUsername) {
        User user = userRepository.findUserByUsername(currentUsername);
        if (user != null) {
            userRepository.delete(user);
            return ResponseEntity.noContent().build();
        } else {
            throw new IllegalArgumentException("Invalid username");
        }
    }
}
