package com.jwtcore.util;

import java.util.Base64;
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
        byte[] decodedKey = Base64.getDecoder().decode(key);
        return new SecretKeySpec(decodedKey, "HmacSHA256");
    }
}