package com.pickndrop_nepal.auth.authserver.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class PasswordEncoderGenerator {

    public static void main(String[] args) {
        System.out.println(encodePassword("pick@dropN3p@l"));
    }

    public static String encodePassword(String rawPassword) {
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        return passwordEncoder.encode(rawPassword);
    }


}
