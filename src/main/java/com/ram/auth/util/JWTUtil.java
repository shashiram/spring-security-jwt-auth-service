package com.ram.auth.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

public class JWTUtil {

    private static final String KEY_STR="d7b72171-3cc2-4f34-a799-b78a83b8f3bb";
    private static final Key key= Keys.hmacShaKeyFor(KEY_STR.getBytes(StandardCharsets.UTF_8));

    public static String generateToken(String userName,int expiry){
        return Jwts.builder()
                .setSubject(userName)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiry*60*1000))
                .signWith(key, SignatureAlgorithm.HS256).compact();
    }

    public static String getUser(String token){
       return Jwts.parser()
                .setSigningKey(key).build()
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

    public static boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

}
