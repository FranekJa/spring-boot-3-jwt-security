package io.ksno.tennisBooking.security.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UpdateProfileRequest {

    @NotBlank(message = "Firstname is required")
    @Size(max = 50, message = "Firstname must be at most 50 characters")
    private String newFirstname;
    @NotBlank(message = "Lastname is required")
    @Size(max = 50, message = "Lastname must be at most 50 characters")
    private String newLastname;

}
