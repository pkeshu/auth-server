package com.pickndrop_nepal.auth.authserver.enitity;

import com.pickndrop_nepal.auth.authserver.service.Authority;

import javax.persistence.*;

@Entity
@Table(name ="authorities" )
public class AuthoritiesEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private UsersEntity user;

    @Enumerated(EnumType.STRING)
    private Authority authority;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Authority getAuthority() {
        return authority;
    }

    public void setAuthority(Authority authority) {
        this.authority = authority;
    }

    public UsersEntity getUser() {
        return user;
    }

    public void setUser(UsersEntity user) {
        this.user = user;
    }
}