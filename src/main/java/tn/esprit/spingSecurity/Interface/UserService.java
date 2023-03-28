package tn.esprit.spingSecurity.Interface;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import tn.esprit.spingSecurity.Entities.User;
import tn.esprit.spingSecurity.Payload.request.ForgotPassRequest;
import tn.esprit.spingSecurity.Payload.request.ResetPassRequest;

import javax.servlet.http.HttpServletRequest;

public interface UserService {

    ResponseEntity<?> forgotPassword( ForgotPassRequest forgotPassRequest, HttpServletRequest request);
    ResponseEntity<?> resetPassword(@RequestBody ResetPassRequest resetPassRequest);

    User updateUser(UserDetails userDetails, User updatedUser, String password);

    User getMyProfile(UserDetails userDetails);
}
