package com.mrdevv.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Set;

@Component
@Slf4j
public class JwtUtils {

    private final SecretKey SECRET_KEY = Jwts.SIG.HS256.key().build();;

    @Value("${jwt.time.experition}")
    private String timeExpiration;

    //    Generar token de acceso
    public String generateAccessToken(String username, Set<String> claims) {
        return Jwts.builder()
                .claim("authorities", claims)
                .subject(username)
                .signWith(SECRET_KEY)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + Long.parseLong(timeExpiration)))
                .compact();
    }

    //    Validar el token de acceso
    public boolean isTokenValid(String token) {
        try {
            Jwts.parser()
                    .verifyWith(SECRET_KEY)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            return true;
        } catch (JwtException e) {
            log.error("Token invalido, error ".concat(e.getMessage()));
            return false;
        }
    }

    //    Obtener el username del token
    public String getUsernameFromToken(String token) {
        return Jwts.parser()
                .verifyWith(SECRET_KEY)
                .build()
                .parseSignedClaims(token)
                .getPayload().getSubject();
    }
}
