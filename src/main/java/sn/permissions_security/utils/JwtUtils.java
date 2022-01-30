package sn.permissions_security.utils;


import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@Slf4j
public class JwtUtils {
    @Value("${token.expire}")
    private String TIME_EXPIRE_TOKEN;
    @Value("${token.expire.refresh}")
    private String TIME_EXPIRE_REFRESH_TOKEN;
    @Value("${token.secret}")
    private String JWT_SECRET;


    public String generateToken(String username, List<String> authorities, String type) {
        long time_expire;
        if (type.equals("ACCESS_TOKEN")) {
            time_expire = Long.parseLong(TIME_EXPIRE_TOKEN);
        } else {
            time_expire = Long.parseLong(TIME_EXPIRE_REFRESH_TOKEN);
        }
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", authorities);

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis())) // creation date
                .setExpiration(new Date(System.currentTimeMillis() + time_expire * 1000)) // expire date in milliseconds
                .signWith(signatureAlgorithm, JWT_SECRET) //signature
                .compact();
    }

    public Claims getClaims(String token) throws JwtException {
        try {
            return Jwts.parser().setSigningKey(JWT_SECRET).parseClaimsJws(token).getBody();
        }catch (JwtException exception){
            throw new JwtException(exception.getMessage());
        }

    }
}
