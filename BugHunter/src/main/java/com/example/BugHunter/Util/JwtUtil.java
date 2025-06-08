package com.example.BugHunter.Util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    private String SECRET_KEY;
    @Value("${jwt.expiration}")
    private long JWT_EXPIRATION;

    public JwtUtil()
    {
        //
    }

}
