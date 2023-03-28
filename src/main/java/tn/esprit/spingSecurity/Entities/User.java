package tn.esprit.spingSecurity.Entities;

import lombok.*;
import lombok.experimental.FieldDefaults;

import javax.persistence.*;
import java.util.*;

@Entity
@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
public class User {
    /**
     *
     */
    static final long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id_user;

    String nom;

    String prenom;

    @Column
    String username;

    @Temporal(TemporalType.DATE)
    Date dateNaissance;

    String email;

    String password;

    int verificationCode;

    String resetpasswordcode;
    private boolean verified = false;

    public String getResetpasswordcode() {
        return resetpasswordcode;
    }

    public void setResetpasswordcode(String resetpasswordcode) {
        this.resetpasswordcode = resetpasswordcode;
    }

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "id_user"),
            inverseJoinColumns = @JoinColumn(name = "id"))
    private Set<Role> roles = new HashSet<>();


    public User(String nom,String prenom,String username,String email,String password,Date dateNaissance){
        this.nom = nom;
        this.prenom =prenom ;
        this.username = username;
        this.email = email;
        this.password = password;
        this.dateNaissance = dateNaissance ;
    }
    public User(String nom,String prenom,String email,Date dateNaissance){
        this.nom = nom;
        this.prenom =prenom ;
        this.email = email;
        this.dateNaissance = dateNaissance ;
    }

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    @Override
    public String toString() {
        return "Client [id_user=" + id_user + ", nom=" + nom + ", prenom=" + prenom + ", dateNaissance="
                + dateNaissance + ", email=" + email + "]";
    }

    public int getVerificationCode() {
        return verificationCode;
    }

    public void setVerificationCode(int verificationCode) {
        this.verificationCode = verificationCode;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }


}
