package tn.esprit.spingSecurity.Repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import tn.esprit.spingSecurity.Entities.Enum.ERole;
import tn.esprit.spingSecurity.Entities.Role;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findByName(ERole name);

    @Query("SELECT r FROM Role r WHERE r.name='ROLE_ADMIN' ")
    public Role getRoleAdmin();
    @Query("SELECT r FROM Role r WHERE r.name='ROLE_ETUDIANT' ")
    public Role getRoleEtudiant();
    @Query("SELECT r FROM Role r WHERE r.name='ROLE_UNIVERSITE' ")
    public Role getRoleUnicersite();
}