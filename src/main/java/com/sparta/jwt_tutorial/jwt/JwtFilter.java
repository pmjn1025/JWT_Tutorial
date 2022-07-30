package com.sparta.jwt_tutorial.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

// jwt 커스텀 필터
// jwt필터는 방금 만들었던 token프로바이더를 주입받는다.
public class JwtFilter extends GenericFilterBean {
    //slf4j.Logger :
    // 스프링의 Logging Framework에서 가장 유명한 라이브러리가
    // 바로 slf4j(Simple Logging Facade For Java) 입니다.
    //slf4j는 다양한 자바 로깅 시스템을 사용할 수 있도록 해주는
    // 파사드 패턴의 인터페이스라고 생각하시면 될 것 같습니다.
    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private TokenProvider tokenProvider;
    
    // GenericFilterBean의 메서드 
    public JwtFilter(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    // 실제 필터 로직.
    //GenericFilterBean의 메서드
    // doFilter의 역할은 jwt토큰의 인증정보를 Security Context에 저장하는 역할.
    @Override
    public void doFilter(ServletRequest servletRequest,
                         ServletResponse servletResponse,
                         FilterChain filterChain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        //resolveToken을 통해 토큰을 받아와서 유효성검사를 하고 정상 토큰이면 SecurityContext에 저장.
        String jwt = resolveToken(httpServletRequest);
        String requestURI = httpServletRequest.getRequestURI();

        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            // Security Context에 Authentication객체가 저장되는 시점은 jwtfilter의 doFilter메소드에서
            // Request가 들어올때 SecurityContext에 Authetication 객체를 저장해서 사용하게 된다.
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    // 필터링을 하기위해서 토큰 정보가 필요하니까 resolveToken을 추가
    // request header에서 토큰정보를 꺼내오기 위한 resolve Token메서드를 추가
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
