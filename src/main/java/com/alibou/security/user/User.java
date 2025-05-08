package com.alibou.security.user;

import com.alibou.security.token.Token;
import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "_user")
public class User implements UserDetails {

  @Id
  @GeneratedValue
  private Integer id;
  @Column(nullable = false, unique = true)
  private String username;
  @Column(nullable = false, unique = true)
  private String email;
  @Column(nullable = false)
  private String password;
  @Enumerated(EnumType.STRING)
  private Role role;
  @OneToMany(mappedBy = "user")
  private List<Token> tokens;
  @CreatedDate
  @Column(nullable = false,updatable = false)
  private LocalDateTime createDate;
  @LastModifiedDate
  @Column(insertable = false)
  private LocalDateTime lastModified;
  @CreatedBy
  @Column(nullable = false,updatable = false)
  private Integer createdBy;
  @LastModifiedBy
  @Column(insertable = false)
  private Integer lastModifiedBy;
  private String firstname;
  private String lastname;



  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return role.getAuthorities();
  }

  @Override
  public String getUsername() { return username; }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
