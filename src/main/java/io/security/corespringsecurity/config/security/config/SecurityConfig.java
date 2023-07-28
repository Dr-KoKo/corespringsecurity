package io.security.corespringsecurity.config.security.config;

import io.security.corespringsecurity.config.security.common.CustomAuthenticationDetailsSource;
import io.security.corespringsecurity.config.security.handler.CustomAuthenticationSuccessHandler;
import io.security.corespringsecurity.config.security.provider.CustomAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {
    @Autowired
    private CustomAuthenticationDetailsSource authenticationDetailsSource;
    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;

    @Autowired
    public void globalConfigure(AuthenticationManagerBuilder auth, CustomAuthenticationProvider provider) throws Exception {
        auth.authenticationProvider(provider);
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
                .formLogin((formLogin) ->
                        formLogin
                                .loginPage("/login")
                                .loginProcessingUrl("/login_proc")
                                .authenticationDetailsSource(authenticationDetailsSource)
                                .successHandler(authenticationSuccessHandler)
                                .permitAll()
                )
                .logout((logout) ->
                        logout
                                .logoutRequestMatcher(AntPathRequestMatcher.antMatcher("/logout"))
                                .logoutSuccessUrl("/")
                );

        return http.build();
    }
}
