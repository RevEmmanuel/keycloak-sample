package org.keycloaks.utils;


import java.security.SecureRandom;
import java.util.Base64;

public class ProjectUtilities {

    public static final String BEARER = "Bearer ";
    public static final String NOT_NULL = "Cannot be null";
    public static final String NOT_BLANK = "Cannot be blank";
    public static final int MAX_NUMBER_PER_PAGE = 5;
    public static final String ADMIN_EXTENSION = "_ADMIN";
    public static final String CREATOR_EXTENSION = "_CREATOR";
    public static final String MEMBER_EXTENSION = "_MEMBER";
    public static final String OWNER_EXTENSION = "_OWNER";
    public static final String GROUP_EXTENSION = "_GROUP";



    public static String generateToken(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

}
