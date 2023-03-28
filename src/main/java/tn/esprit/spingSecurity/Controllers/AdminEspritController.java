package tn.esprit.spingSecurity.Controllers;


import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import tn.esprit.spingSecurity.Entities.Enum.ERole;
import tn.esprit.spingSecurity.Entities.User;
import tn.esprit.spingSecurity.Repository.UserRepository;
import tn.esprit.spingSecurity.Services.AdminImpSercice;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/adminEsprit")
@RequiredArgsConstructor
public class AdminEspritController {
    private final AdminImpSercice adminImpSercice;

    private final UserRepository userRepository;

    @GetMapping("/AllUser")
    @PreAuthorize("hasRole('ADMIN')")
    public List<User> getUsers() {
        return adminImpSercice.getAllUsers();
    }

    @GetMapping("/Statistique")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<ERole, Integer> getUserRoleStats() {
        return adminImpSercice.getUserRoleStats();
    }


    @GetMapping("/ProfileUserByName/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public User GetUserByUserName(@PathVariable String username)
    {
        return adminImpSercice.GetUserByUsername(username);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/DeleteUserByUsername/{currentUsername}")
    public void SupprimerUserByUserName(@PathVariable String currentUsername)
    {
        adminImpSercice.DeleteUserCoteAdmin(currentUsername);
    }


}
