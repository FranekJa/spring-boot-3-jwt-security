package com.alibou.security.auth;

import com.alibou.security.user.Role;
import jakarta.persistence.Column;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

  @Size(max = 50)
  private String firstname;
  @Size(max = 50)
  private String lastname;
  @Email(message = "Invalid email format")
  private String email;
  @NotBlank
  private String password;
  @Size(min = 5, max = 50)
  private String username;
  private Role role;
}
