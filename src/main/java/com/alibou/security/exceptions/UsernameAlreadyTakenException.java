package com.alibou.security.exceptions;

public class UsernameAlreadyTakenException extends RuntimeException {
    public UsernameAlreadyTakenException(String msg) { super(msg); }
}
