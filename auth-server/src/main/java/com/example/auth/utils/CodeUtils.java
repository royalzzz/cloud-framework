package com.example.auth.utils;

import java.security.MessageDigest;
import java.util.Base64;

public class CodeUtils {

    public static String sha256(String inStr) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("SHA256");
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
            return "";
        }
        char[] charArray = inStr.toCharArray();
        byte[] byteArray = new byte[charArray.length];

        for (int i = 0; i < charArray.length; i++)
            byteArray[i] = (byte) charArray[i];
        byte[] md5Bytes = md5.digest(byteArray);
        StringBuilder hexValue = new StringBuilder();
        for (byte md5Byte : md5Bytes) {
            int val = ((int) md5Byte) & 0xff;
            if (val < 16)
                hexValue.append("0");
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }

    public static String base64UrlEncode(String inStr) {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("SHA256");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }

        md5.update(inStr.getBytes());
        String reg1 = "=";
        return Base64.getMimeEncoder()
                .encodeToString(md5.digest())
                .replaceAll(reg1, "");
    }
}
