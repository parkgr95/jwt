package com.cos.config;

import com.cos.config.jwt.JwtAuthorizationFilter;
import com.cos.filter.MyFilter3;
import com.cos.config.jwt.JwtAuthenticationFilter;
import com.cos.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
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
    private final UserRepository userRepository;

    @Bean
    public SecurityFilterChain Configure(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder sharedObject = http.getSharedObject(AuthenticationManagerBuilder.class);
        AuthenticationManager authenticationManager = sharedObject.build();

        http.authenticationManager(authenticationManager);
        return http
//                .addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
//                .addFilter(corsConfig.corsFilter()) // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //세션을 사용하지 않겠다.
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilter(new JwtAuthenticationFilter(authenticationManager)) //AuthenticationManager를 통해 로그인 시도를 하면 필터가 동작함
                .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository)) //권한이나 인증이 필요한 주소 요청이 있을 때 동작하는 필터
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
}
