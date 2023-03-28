package tn.esprit.spingSecurity.Payload.request;

import javax.validation.constraints.NotBlank;

public class ForgotPassRequest {

    @NotBlank
    private String email;

    public void setEmail(String email) {
        this.email = email;
    }
    public String getEmail() {
        return email;
    }
}
