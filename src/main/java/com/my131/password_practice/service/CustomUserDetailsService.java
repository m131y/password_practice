package com.my131.password_practice.service;

import com.my131.password_practice.model.User;
import com.my131.password_practice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Autowired
    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // username으로 DB 조회 → User객체를 UserDetails 변환
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // DB에서 username을 조회.
        // 없다면 UsernameNotFoundException을 던져서 로그인 실패 처리.
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다.: " + username));

        // 디버깅용 로그
        System.out.println("🔍 로그인 시도: " + username);
        System.out.println("📧 이메일: " + user.getEmail());
        System.out.println("🔒 저장된 해시: " + user.getPassword());

        // UserDetails 객체 생성
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(new ArrayList<>())
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(!user.getEnabled())
                .build();
    }
}
