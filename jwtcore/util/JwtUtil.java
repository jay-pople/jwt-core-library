package com.jwtcore.util;

import io.jsonwebtoken.security.Keys;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * Responsible for encoding and decoding of the key
 */
public class JwtUtil {

    private final String key;

    public JwtUtil(String key) {
        this.key = key;
    }


    public String getEncodedKey() {
        return key;
    }

    public SecretKey getDecodedKey() {
        byte[] decodedKey = Base64.decodeBase64(key);
        return new SecretKeySpec(decodedKey, "HmacSHA256");
    }
}