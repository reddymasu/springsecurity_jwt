package com.springsecurityjwt;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import jakarta.xml.bind.DatatypeConverter;
import org.junit.Test;

import javax.crypto.SecretKey;

public class JwtSecretMakerTest {

    @Test
    public  void genreateSecfretKey()
    {
        SecretKey key = Jwts.SIG.HS512.key().build();
        String  encoderkey =DatatypeConverter.printHexBinary(key.getEncoded());

        System.out.println("\n key=[%s]\n"+encoderkey);
    }
}
