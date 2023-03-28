package tn.esprit.spingSecurity.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import tn.esprit.spingSecurity.Entities.Enum.ERole;
import tn.esprit.spingSecurity.Entities.User;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
    User findUserByUsername(String username);
    User findByEmail(String email);
    User findByVerificationCode (Integer code);
    List<User> findByRoles_name(ERole role);

}
