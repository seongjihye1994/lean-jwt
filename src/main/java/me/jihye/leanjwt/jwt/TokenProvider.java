package me.jihye.leanjwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
public class TokenProvider implements InitializingBean {

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long tokenValidityInMilliseconds; // application.yml에 설정한 token expire time

    private Key key;

    // 생성자
    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.token-validity-in-seconds}") long tokenValidityInSeconds) {
        this.secret = secret;
        this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
    }

    /**
     * 이 TokenProvider가 Bean으로 생성이 되고 의존성 주입이 완료되면,
     * 주입받은 secret 값을 BASE64로 decode 하고,
     * key 변수에 할당함.
     */
    @Override
    public void afterPropertiesSet() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * authentication 객체에 포함되어 있는 권한 정보들을 담은 토큰을 생성하는 메소드
     *
     * @param authentication
     * @return
     */
    public String createToken(Authentication authentication) {

        // 파라미터로 전달받은 authentication 객체 내부에 있는 권한 정보들을 꺼내고
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.tokenValidityInMilliseconds);
        // application.yml에 설정한 token expire time 을 설정

        // 해당 정보들로 jwt 토큰 생성해서 리턴
        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .signWith(key, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    /**
     * Token을 파라미터로 받아서, Token에 담겨있는 권한 정보들을 이용해
     * authentication 객체를 만들어 리턴하는 메소드
     *
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {

        // 파라미터로 받은 토큰으로 claims 을 생성
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // claims 에서 권한 정보들을 빼내서
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // 권한 정보들로 user 객체를 만든 후
        User principal = new User(claims.getSubject(), "", authorities);

        // 만든 user 객체, token, authorities 객체를 이용해서 최종적으로
        // Authentication 객체 (UsernamePasswordAuthenticationToken) 을 리턴!
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    /**
     * 토큰을 파라미터로 받아 유효성 검사를 하는 메소드
     *
     * @param token
     * @return
     */
    public boolean validateToken(String token) {
        try {
            // 받은 토큰을 파싱해서
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true; // 문제가 없으면 true 리턴

        // 문제가 있으면 catch 로 exception을 잡고
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            log.info("만료된 JWT 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            log.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            log.info("JWT 토큰이 잘못되었습니다.");
        }
        return false; // 문제 있을 시 false 리턴
    }
}