package com.sparta.jwt_tutorial.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public class SecurityUtil {

    private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

    private SecurityUtil() {
    }

    // getCurrentUsername 메서드를 하나맘 가지고 있다.
    // SecurityContextHolder에서 getAuthentication을 꺼내와서
    // authentication객체를 통해서 username을 리턴한다.
    public static Optional<String> getCurrentUsername() {
        // Security Context에 Authentication객체가 저장되는 시점은 jwtfilter의 doFilter메소드에서
        // Request가 들어올때 SecurityContext에 Authetication 객체를 저장해서 사용하게 된다.
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            logger.debug("Security Context에 인증 정보가 없습니다.");
            return Optional.empty();
        }

        String username = null;
        if (authentication.getPrincipal() instanceof UserDetails) {
            UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
            username = springSecurityUser.getUsername();
        } else if (authentication.getPrincipal() instanceof String) {
            username = (String) authentication.getPrincipal();
        }

        return Optional.ofNullable(username);
    }
}
