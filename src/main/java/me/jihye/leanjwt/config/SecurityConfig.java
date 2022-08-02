package me.jihye.leanjwt.config;

import lombok.RequiredArgsConstructor;
import me.jihye.leanjwt.jwt.JwtAccessDeniedHandler;
import me.jihye.leanjwt.jwt.JwtAuthenticationEntryPoint;
import me.jihye.leanjwt.jwt.JwtSecurityConfig;
import me.jihye.leanjwt.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true) // @PreAuthorize 어노테이션을 메소드 단위로 추가하기 위해 적용
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 의존성 주입
    private final TokenProvider tokenProvider;
//    private CorsFilter corsFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    // PasswordEncoder 는 BCryptPasswordEncoder 을 사용
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsFilter corsFilter() {
        // 소스코드 출처
        //http://useof.org/java-open-source/org.springframework.web.filter.CorsFilter
        // Example 3
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("OPTIONS");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("DELETE");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    /**
     * "/h2-console/**", "/favicon.ico" url 로 들어오는 요청은 Security 를 무시(적용x)한다.
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers(
                        "/h2-console/**"
                                ,"/favicon.ico"
                );
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // token을 사용하는 방식이기 때문에 csrf를 disable합니다.
                .csrf().disable()

                .addFilterBefore(corsFilter(), UsernamePasswordAuthenticationFilter.class)

                // 익셉션을 핸들링할 때
                .exceptionHandling()
                // authenticationEntryPoint 와 accessDeniedHandler 을 우리가 만들었던 클래스들로 추가해준다.
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // h2-console 을 위한 설정 추가
                // enable h2-console
                .and()
                .headers()
                .frameOptions()
                .sameOrigin()

                // 세션을 사용하지 않기 때문에 STATELESS로 설정
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .authorizeRequests()
                .antMatchers("/api/hello").permitAll()
                .antMatchers("/api/authenticate").permitAll() // 토큰을 받기 위한 api 와
                .antMatchers("/api/signup").permitAll() // 회원 가입 api는 둘 다 토큰이 없는 상태에서 요청하기 때문에 이 url은 아무나 들어올수 있기

                .anyRequest().authenticated()

                // JwtFilter를 addFilterBefore로 등록했던 JwtSecurityConfig 클래스도 적용
                .and()
                .apply(new JwtSecurityConfig(tokenProvider));

    }
}
