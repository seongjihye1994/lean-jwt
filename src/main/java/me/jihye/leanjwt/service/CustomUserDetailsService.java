package me.jihye.leanjwt.service;

import lombok.RequiredArgsConstructor;
import me.jihye.leanjwt.entity.Users;
import me.jihye.leanjwt.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.userdetails.User;

import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    /**
     * CustomUserDetailsService 의 역할?
     *
     * 로그인 시, DB에서 유저정보와 권한정보를 가져오는데,
     * 이 정보를 기반으로 userdetails.Users 객체를 생성해서 리턴한다.
     *
     * @param username the username identifying the user whose data is required.
     * @return
     */

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username) {
        return userRepository.findOneWithAuthoritiesByUsername(username)
                .map(user -> createUser(username, user))
                .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
    }

    private User createUser(String username, Users user) {
        if (!user.isActivated()) {
            throw new RuntimeException(username + "  -> 활성화되어 있지 않습니다.");
        }

        List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
                .collect(Collectors.toList());

        return new org.springframework.security.core.userdetails.User(user.getUsername(),
                user.getPassword(),
                grantedAuthorities);
    }
}
