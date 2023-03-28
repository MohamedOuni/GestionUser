package tn.esprit.spingSecurity.Payload.request;


import javax.validation.constraints.NotBlank;

public class ResetPassRequest {
    @NotBlank
    private String email;

    @NotBlank
    private String password;

    private String resetpasswordcode;

    public void setEmail(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getResetpasswordcode() {
        return resetpasswordcode;
    }

    public void setResetpasswordcode(String resetpasswordcode) {
        this.resetpasswordcode = resetpasswordcode;
    }
}
