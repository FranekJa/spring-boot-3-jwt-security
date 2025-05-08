package com.alibou.security.auth.bruteforce;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "ip_attempts")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class IpAttempt {

    @Id
    private String ip;

    private int failAttempts = 0;

    private LocalDateTime lockedAt;
}