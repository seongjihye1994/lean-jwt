package me.jihye.leanjwt.service;

import lombok.RequiredArgsConstructor;
import me.jihye.leanjwt.dto.UserDto;
import me.jihye.leanjwt.entity.Authority;
import me.jihye.leanjwt.entity.Users;
import me.jihye.leanjwt.exception.DuplicateMemberException;
import me.jihye.leanjwt.repository.UserRepository;
import me.jihye.leanjwt.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * 회원가입 API
     *
     * @param userDto
     * @return
     */
    @Transactional
    public UserDto signup(UserDto userDto) {

        // 중복 유저 검증
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }

        // 중복 유저 없으면 권한 정보 생성
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER") // 이 정보로 권한을 검증함
                .build();

        // 권한 정보를 유저 객체에 넣음
        Users user = Users.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();

        return UserDto.from(userRepository.save(user));
    }

    /**
     * username 을 파라미터로 받아
     * 이 정보로 권한 정보를 가져오는 API
     *
     * @param username
     * @return
     */
    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    /**
     * 현재 Security Context 내부에 저장되어 있는 username 과 관련된 정보만 가져오는 API
     *
     * @return
     */
    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername).orElse(null));
    }
}
