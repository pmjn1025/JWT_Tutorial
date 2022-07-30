package com.sparta.jwt_tutorial.controller;

import com.sparta.jwt_tutorial.dto.LoginDto;
import com.sparta.jwt_tutorial.dto.TokenDto;
import com.sparta.jwt_tutorial.jwt.JwtFilter;
import com.sparta.jwt_tutorial.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        //LoginDto의 username, pw를 매개변수로 받고 이를 이용해 UsernamePasswordAuthenticationToken을 생성한다.
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(),
                        loginDto.getPassword());
        // authenticationToken을 이용해서 authentication객체를 생성하려고 authenticate메서드가 실행될때
        // loadUserByUsername메서드가 실행된다.
        // 실행된 결과값을 가지고 authentication객체생성하고 이를 SecurityContext에 저장하고
        Authentication authentication =
                authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Authentication 객체를 createToken메서드를 통해서 JWT토큰을 생성한다.
        String jwt = tokenProvider.createToken(authentication);
        // jwt토큰을 response header에도 넣어주고 TokenDto를 이용해서 Response Body에도 넣어서 리턴
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);
    }
}
