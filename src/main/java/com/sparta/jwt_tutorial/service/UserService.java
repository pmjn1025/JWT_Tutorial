package com.sparta.jwt_tutorial.service;

import java.util.Collections;
import java.util.Optional;

import com.sparta.jwt_tutorial.dto.UserDto;

import com.sparta.jwt_tutorial.entity.Authority;
import com.sparta.jwt_tutorial.entity.User;
import com.sparta.jwt_tutorial.exception.DuplicateMemberException;
import com.sparta.jwt_tutorial.repository.UserRepository;

import com.sparta.jwt_tutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public UserDto signup(UserDto userDto) {
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return UserDto.from(userRepository.save(user));
    }

    // 두가지 메서드의 허용권한을 다르게해서 권한 검증에 대한 부분을 테스트해보자.
    // getUserWithAuthorities는 username을 기준으로 정보를 가져오고
    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    // getMyUserWithAuthorities는 securityContext에 저장된 username의 정보만 가져온다.
    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername).orElse(null));


    }
}
