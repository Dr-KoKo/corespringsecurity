package io.security.corespringsecurity.config.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    public void globalConfigure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        });
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests((request) ->
                        request
                                .requestMatchers("/", "/users").permitAll()
                                .requestMatchers("/mypage").hasRole("USER")
                                .requestMatchers("/messages").hasRole("MANAGER")
                                .requestMatchers("/config").hasRole("ADMIN")
                                .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());

        return http.build();
    }
}
