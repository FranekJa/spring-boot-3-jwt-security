package io.ksno.tennisBooking.security.user;

import io.ksno.tennisBooking.security.exceptions.InvalidPasswordException;
import io.ksno.tennisBooking.security.user.password.PasswordConstraintValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
@RequiredArgsConstructor
public class UserService {

    private final PasswordEncoder passwordEncoder;
    private final PasswordConstraintValidator passwordValidator;
    private final UserRepository repository;

    public void changePassword(ChangePasswordRequest request, Principal connectedUser) {

        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // check if the current password is correct
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalStateException("Wrong password");
        }
        // check if the two new passwords are the same
        if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
            throw new IllegalStateException("Password are not the same");
        }
        // Walidacja siły hasła
        var result = passwordValidator.validate(request.getNewPassword());
        if (!result.isValid()) {
            String combined = String.join(", ", passwordValidator.getValidator().getMessages(result));
            throw new InvalidPasswordException(combined);
        }

        // update the password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        // save the new password
        repository.save(user);
    }

    public void updateProfile(UpdateProfileRequest request, Principal connectedUser) {

        var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

        // update the firstname and lastname
        user.setFirstname(request.getNewFirstname());
        user.setLastname(request.getNewLastname());

        // save updated user
        repository.save(user);
    }


}
