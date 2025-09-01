package com.my131.password_practice.config;

import com.my131.password_practice.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration      //스프링 설정 클래스로 등록
@EnableWebSecurity  //스프링 시큐리티 활성화
public class SecurityConfig {
    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        int costFactor = 12;

        System.out.println("🔐 BCrypt 패스워드 인코더 설정");
        System.out.println("📊 Cost Factor: " + costFactor + " (2^" + costFactor + " = " +
                Math.pow(2, costFactor) + "번 해싱)");

        // BCryptPasswordEncoder(12) 인스턴스를 컨테이너에 등록
        // 이후 비밀번호 저장/검증에서 이 인코더가 사용
        return new BCryptPasswordEncoder(costFactor);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(
                        auth -> auth
                                // 누구나 접근 허용.
                                .requestMatchers("/", "/register", "/h2-console/**", "/css/**", "/js/**", "/error").permitAll()
                                .requestMatchers("/password-test/**").permitAll()
                                // 그 외 모든 요청은 인증 필요.
                                .anyRequest().authenticated()
                )
                // 커스텀 로그인 페이지 경로: /login (접근 허용)
                .formLogin(form -> form.loginPage("/login").permitAll()
                        // 로그인 성공 시 /dashboard로 항상 이동(true)
                        .defaultSuccessUrl("/dashboard", true)
                        // 실패 시 쿼리 파라미터로 에러 표시(/login?error=true)
                        .failureUrl("/login?error=true")
                )
                .logout(logout -> logout
                        // 로그아웃 성공 시 /login?logout=true로 이동(알림 표시 용도)
                        .logoutSuccessUrl("/login?logout=true")
                        // 로그아웃 URL은 기본 /logout(POST). 접근 권한 허용.
                        .permitAll()
                )
                // H2 콘솔 같은 iframe 기반 페이지를 띄우기 위해 스프링 시큐리티의 iframe 차단(X-Frame-Options)을 꺼주는 설정
                .headers(headers -> headers.frameOptions(frame -> frame.disable()))
                // CSRF 예외 설정
                .csrf(csrf -> csrf
                        // H2 콘솔/패스워드 테스트 API/회원가입 엔드포인트에 대해 CSRF 보호를 건너뜀.
                        .ignoringRequestMatchers("/h2-console/**")
                        .ignoringRequestMatchers("/password-test/**")
                        .ignoringRequestMatchers("/register")
                )
                // 세션 정책
                .sessionManagement(session -> session
                        // 필요할 때만 세션 생성(폼 로그인 시 등).
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        // URL 리라이팅 비활성화
                        .enableSessionUrlRewriting(false)
                )
                .build();
    }
    // AuthenticationManager : 인증(로그인)을 처리하는 총괄 매니저
    //username과 password를 받아서 내부에 등록된 AuthenticationProvider들(DaoAuthenticationProvider 등)에게 넘겨
    // 사용자가 진짜 맞는지 확인한 뒤, 성공하면 인증된 사용자 정보를 돌려줌
    //스프링이 자동으로 만든 AuthenticationManager를 AuthenticationConfiguration에서 꺼내고 @Bean으로 등록해서, 다른 컴포넌트에서도
    //@Autowired AuthenticationManager 식으로 바로 사용할 수 있게 함.
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        // DAO 기반 인증 프로바이더 생성.
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        // CustomUserDetailsService를 사용해 사용자 로드 전략을 지정.
        authenticationProvider.setUserDetailsService(userDetailsService);
        // 위에서 등록한 BCryptPasswordEncoder(12)를 비밀번호 검증기로 설정.
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        // 커스텀 DaoAuthenticationProvider를 빈으로 등록
        return authenticationProvider;
    }
}