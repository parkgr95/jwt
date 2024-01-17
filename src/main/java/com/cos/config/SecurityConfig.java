package com.cos.config;

import com.cos.filter.MyFilter3;
import com.cos.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain Configure(HttpSecurity http) throws Exception {
        return http
                .addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .addFilter(corsConfig.corsFilter()) // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //세션을 사용하지 않겠다.
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilter(new JwtAuthenticationFilter()) //AuthenticationManager를 통해 로그인 시도를 하면 필터가 동작함
                .authorizeHttpRequests(request -> {
                    request.requestMatchers("api/v1/user/**")
                            .hasAnyRole("USER", "MANANGER", "ADMIN");
                    request.requestMatchers("/manager/**")
                            .hasAnyRole("MANAGER", "ADMIN"); //Role은 붙이면 안됨. 자동으로 ROLE_이 붙음
                    request.requestMatchers("/admin/**")
                            .hasRole("ADMIN"); //Role은 붙이면 안됨. 자동으로 ROLE_이 붙음
                    request.anyRequest().permitAll();
                })
                .build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");
        //1. username, password 받아서
        //2. 정상인지 로그인 시도를 해봄. authenticationManager로 로그인 시도를 하면!!
        //PrincipalDetailsService가 호출됨 => loadUserByUsername() 함수 실행
        //3. PrincipalDetails를 세션에 담고 (권한 관리를 위해)
        //4. JWT 토큰을 만들어서 응답해주면 됨
        return authenticationConfiguration.getAuthenticationManager();
    }
}
