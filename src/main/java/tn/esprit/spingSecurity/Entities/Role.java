package tn.esprit.spingSecurity.Entities;

import lombok.*;
import tn.esprit.spingSecurity.Entities.Enum.ERole;

import javax.persistence.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name="role")
public class Role {
    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Enumerated(EnumType.STRING)
    @Column
    private ERole name;

    public Role(ERole name) {
        this.name = name;
    }
}
