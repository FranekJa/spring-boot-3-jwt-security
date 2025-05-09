package io.ksno.tennisBooking.security.user.password;

import org.passay.*;
import org.springframework.stereotype.Component;

import java.util.Arrays;

@Component
public class PasswordConstraintValidator {

    private final PasswordValidator validator;

    public PasswordConstraintValidator() {
        this.validator = new PasswordValidator(Arrays.asList(
                // co najmniej 8 znaków
                new LengthRule(8, 128),
                // co najmniej jedna wielka litera
                new CharacterRule(EnglishCharacterData.UpperCase, 1),
                // co najmniej jedna mała litera
                new CharacterRule(EnglishCharacterData.LowerCase, 1),
                // co najmniej jedna cyfra
                new CharacterRule(EnglishCharacterData.Digit, 1),
                // co najmniej jeden symbol
                new CharacterRule(EnglishCharacterData.Special, 1),
                // bez ciągów sekwencyjnych jak "abc" czy "123"
                new IllegalSequenceRule(EnglishSequenceData.Alphabetical, 3, false),
                new IllegalSequenceRule(EnglishSequenceData.Numerical, 3, false),
                // zabronione zmiany domyślne, np. username
                new WhitespaceRule()
        ));
    }

    /**
     * Zwraca null jeżeli hasło jest poprawne,
     * lub listę komunikatów o błędach.
     */
    public RuleResult validate(String password) {
        return validator.validate(new PasswordData(password));
    }

    public PasswordValidator getValidator() {
        return validator;
    }

}