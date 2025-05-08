package com.alibou.security.auth.bruteforce;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IpAttemptRepository extends JpaRepository<IpAttempt, String> {

}