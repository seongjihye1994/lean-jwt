package me.jihye.leanjwt.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends GenericFilterBean {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    private final TokenProvider tokenProvider; // 미리 만들어 놓은 TokenProvider 를 주입

    /**
     * GenericFilterBean 의 doFilter를 오버라이드
     *
     * 이 doFilter 안에 실제 필터링 로직이 들어간다.
     *
     * 이 doFilter 역할은 JWT 토큰의 인증 정보를 현재 실행중은 security context 에 저장하는 역할을 수행한다.
     *
     * @param servletRequest  The request to process
     * @param servletResponse The response associated with the request
     * @param filterChain    Provides access to the next filter in the chain for this
     *                 filter to pass the request and response to for further
     *                 processing
     *
     * @throws IOException
     * @throws ServletException
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;

        // Request 에서 token 을 받는다.
        String jwt = resolveToken(httpServletRequest);
        String requestURI = httpServletRequest.getRequestURI();

        // Request 에서 꺼낸 token의 유효성 검사를 진행한다.
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {

            // 토큰이 정상이라면 토큰에서 authentication 객체를 받아와서
            Authentication authentication = tokenProvider.getAuthentication(jwt);

            // security context에 set 해준다.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
        } else {
            log.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

    /**
     * 필터링을 하기 위한 토큰 정보를 위해
     * Request Header 에서 토큰 정보를 꺼내오는 메소드
     *
     * @param request
     * @return
     */
    private String resolveToken(HttpServletRequest request) {

        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        return null;
    }
}