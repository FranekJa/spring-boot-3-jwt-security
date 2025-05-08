package com.alibou.security.exceptions;

public class EmailAlreadyTakenException extends RuntimeException {
    public EmailAlreadyTakenException(String msg) { super(msg); }
}