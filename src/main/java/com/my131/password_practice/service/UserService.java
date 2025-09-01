package com.my131.password_practice.service;

import com.my131.password_practice.model.User;
import com.my131.password_practice.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.regex.Pattern;

@Service
@Transactional
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    // 비밀번호 강도 정규식
    // (?=.*[a-z]) 소문자 1+
    // (?=.*[A-Z]) 대문자 1+
    // (?=.*\\d) 숫자 1+
    // (?=.*[@$!%*?&]) 특수문자 1+
    // [A-Za-z\\d@$!%*?&]{8,}: 허용 문자만 사용해 8자 이상
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$");

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }
    // 회원가입
    public User registerUser(String username, String rawPassword, String email) {
        // 중복 검사: 사용자명/이메일 중복 시 즉시 예외.
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("이미 존재하는 사용자명입니다: " + username);
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("이미 등록된 이메일입니다: " + email);
        }
        // 비밀번호 강도 규칙 검사
        validatePasswordStrength(rawPassword);

        System.out.println("🔐 패스워드 해싱 시작");
        System.out.println("📝 원본 패스워드: " + rawPassword);

        long startTime = System.currentTimeMillis();
        String encodedPassword = passwordEncoder.encode(rawPassword);
        long endTime = System.currentTimeMillis();

        System.out.println("🔒 해시 결과: " + encodedPassword);
        System.out.println("⏱️ 해싱 소요 시간: " + (endTime - startTime) + "ms");
        System.out.println("📏 해시 길이: " + encodedPassword.length() + " characters");

        // 엔티티 생성 → 저장 → 반환.
        User user = new User(username, encodedPassword, email);
        User savedUser = userRepository.save(user);

        System.out.println("✅ 사용자 등록 완료: " + savedUser);

        return savedUser;
    }

    // 비밀번호 강도 검사
    private void validatePasswordStrength(String password) {
        // 최소 길이 검사
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("패스워드는 최소 8자 이상이어야 합니다");
        }
        // 정규식 패턴 검사
        if(!PASSWORD_PATTERN.matcher(password).matches()) {
            throw new IllegalArgumentException("패스워드는 대소문자, 숫자, 특수문자를 모두 포함해야 합니다");
        }
        // 흔한 패턴 포함 여부 검사
        String[] commonPasswords = {"password", "123456789", "qwerty", "admin"};
        String lowerPassword = password.toLowerCase();

        for (String common: commonPasswords) {
            if (lowerPassword.contains(common)) {
                throw new IllegalArgumentException("너무 일반적인패스워드 입니다.");
            }
        }

        System.out.println("패스워드 강도 검증 통과");
    }

    // 로그인 검증
    private boolean validateLogin(String username, String rawPassword) {
        // 사용자 조회
        Optional<User> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            System.out.println("❌ 사용자를 찾을 수 없음: " + username);
            return false;
        }

        User user = userOpt.get();

        System.out.println("🔍 로그인 검증 시작");
        System.out.println("👤 사용자: " + username);
        System.out.println("📝 입력된 패스워드: " + rawPassword);
        System.out.println("🔒 저장된 해시: " + user.getPassword());

        long startTime = System.currentTimeMillis();
        // 입력 vs 저장 해시 비교
        boolean matches = passwordEncoder.matches(rawPassword, user.getPassword());
        long endTime = System.currentTimeMillis();

        System.out.println("⏱️ 검증 소요 시간: " + (endTime - startTime) + "ms");
        System.out.println("🎯 검증 결과: " + (matches ? "성공" : "실패"));

        return matches;
    }

    // 비밀번호 변경
    private void changePassword(String username, String oldPassword, String newPassword) {
        // 사용자 확인
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다"));
        if(!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new IllegalArgumentException("기존 패스워드가 일치하지 않습니다");
        }
        // 새 비밀번호 강도 검사.
        validatePasswordStrength(newPassword);
        // 새 비번 해싱 → 저장.
        String encodedNewPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedNewPassword);

        userRepository.save(user);
        System.out.println("✅ 패스워드 변경 완료: " + username);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

}