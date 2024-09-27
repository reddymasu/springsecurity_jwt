package com.springsecurityjwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

//validating jwt token and issuing the jwt token secret
// key is used for generetion of jwt and validating

@Service
public class JwtService {

    private static  final String SECRETKEY ="327E7988773E3675191AC524A1E6AAD65C3AA60604D13C47BC79EC1513C5DDEC08518A9703890B9CB7E03E10460D302E4DBFC84A603652A8B5B6BE3906EAB789";
    private static final long VALIDITY = TimeUnit.MINUTES.toMillis(30);

    public String generateToken(UserDetails userDetails)
    {
        Map<String, String> claims = new HashMap<>();
        claims.put("iss", "https://secure.genuinecoder.com");
        return Jwts.builder()
                .claims(claims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
                .signWith(generateKey())
                .compact();
    }

    //convert the key (encoder ) in to secret key object

    private SecretKey generateKey() {
        byte[] decodedKey = Base64.getDecoder().decode(SECRETKEY);
        return Keys.hmacShaKeyFor(decodedKey);
    }

    public String extractusername(String jwt) {
        //for generatin we have ised the nbulider
        //use parser tpo parse the dcata from the  web token
        //parser will be pea[pfre with yhe secretb key

        //res[pondse of this is clamis here subject is the usermname

        Claims claims = getClaims(jwt);
        return  claims.getSubject();

    }

    private Claims getClaims(String jwt) {


        return Jwts.parser()
                .verifyWith(generateKey())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    public boolean isTokenValid(String jwt) {

        //expiratujn date is should  be ib the future
        Claims claims = getClaims(jwt);
        return claims.getExpiration().after(Date.from(Instant.now()));



    }
}
