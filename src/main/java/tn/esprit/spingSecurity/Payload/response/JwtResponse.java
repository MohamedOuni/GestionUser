package tn.esprit.spingSecurity.Payload.response;


import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import tn.esprit.spingSecurity.Entities.User;

import java.util.Collection;
import java.util.List;

public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String username;
    private String email;
    private User profile;
    private List<String> roles;



    public JwtResponse(String accessToken, Long id, String username, String email, User profile, List<String> roles) {
        this.token = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.profile = profile ;
        this.roles = roles;
    }

    public JwtResponse(ResponseCookie jwt, Long id, String username, String email, Collection<? extends GrantedAuthority> authorities) {
    }


    public void setProfile(User profile) {
        this.profile = profile;
    }

    public User getProfile() {
        return profile;
    }

    public String getAccessToken() {
        return token;
    }

    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }

    public String getTokenType() {
        return type;
    }

    public void setTokenType(String tokenType) {
        this.type = tokenType;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }


}


