package me.jihye.leanjwt.util;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

@Slf4j
@NoArgsConstructor
public class SecurityUtil {

    /**
     * 이 메소드는 Security Context 에서 Authentication 객체를 꺼내와
     * Authentication 안에 있는 username을 리턴해주는 유틸성 메소드
     *
     * 참고로 Authentication 내부의 정보는
     * JWTFilter에 doFilter 에서 request가 들어오는 시점에
     * SecurityContextHolder 객체에 setAuthentication 을 해주는데,
     * 이 때 값이 세팅된다.
     *
     * @return
     */

    public static Optional<String> getCurrentUsername() {

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            log.debug("Security Context에 인증 정보가 없습니다.");
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