package com.sparta.jwt_tutorial.config;

import com.sparta.jwt_tutorial.jwt.JwtAccessDeniedHandler;
import com.sparta.jwt_tutorial.jwt.JwtAuthenticationEntryPoint;
import com.sparta.jwt_tutorial.jwt.JwtSecurityConfig;
import com.sparta.jwt_tutorial.jwt.TokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.CorsFilter;

@Component
@EnableWebSecurity
// @preAuthorize 어노테이션을 메서드 단위로 추가하기 위해서 적용.
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final TokenProvider tokenProvider;

    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;


    @Autowired // 생성자 부분의 객체들을 주입받음.
    public SecurityConfig(
            TokenProvider tokenProvider,

            JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
            JwtAccessDeniedHandler jwtAccessDeniedHandler
    ) {
        this.tokenProvider = tokenProvider;

        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }


    @Bean // 비밀번호 암호와
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // h2-console 사용에 대한 허용 (CSRF, FrameOptions 무시)
        return (web) -> web.ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                        ,"/error"
                );
    }



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http

                // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
                .csrf().disable()

                //.addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()


                .and()
                .sessionManagement()
                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()

                // HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정
                .authorizeRequests()

                //antMatchers(path).permitAll()은 /api/hello에대한 요청은 인증없이 접근을 허용하겠다.
                // 로그인 api, 회원가입api는 토큰이 없는 상태에서 요청이 들어오기 때문에 둘다 인증없이
                // 들어올 수 있도록 열어주자.
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll()
                .antMatchers("/api/signup").permitAll()

                // 나머지 요청들에 대해서는 모두 인증되어야 한다.
                .anyRequest().authenticated()

                .and()
                //jwtFilter를 addfilterBefore로 등록했던 jwtSecurityConfig클래스 적용
                .apply(new JwtSecurityConfig(tokenProvider));



        return http.build();


    }



}
