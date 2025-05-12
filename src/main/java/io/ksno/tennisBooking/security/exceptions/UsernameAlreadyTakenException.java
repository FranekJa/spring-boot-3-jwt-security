package io.ksno.tennisBooking.security.exceptions;

public class UsernameAlreadyTakenException extends RuntimeException {

    public UsernameAlreadyTakenException(String msg) {
        super(msg);
    }

}
