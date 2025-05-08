package com.alibou.security.user;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UpdateProfileRequest {
    private String newFirstname;
    private String newLastname;
}
