package io.ksno.tennisBooking.security.exceptions;

public class EmailAlreadyTakenException extends RuntimeException {

    public EmailAlreadyTakenException(String msg) {
        super(msg);
    }

}