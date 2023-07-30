package io.security.corespringsecurity.config.security.config;

import io.security.corespringsecurity.config.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.config.security.provider.AjaxAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Order(0)
@Slf4j
public class AjaxSecurityConfig {
    @Autowired
    private AjaxLoginProcessingFilter ajaxLoginProcessingFilter;

    @Autowired
    public void globalConfigure(AuthenticationManagerBuilder auth, AjaxAuthenticationProvider provider) {
        auth.authenticationProvider(provider);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests((authorizeHttpRequests) ->
                        authorizeHttpRequests
                                .anyRequest().authenticated()
                )
                .addFilterBefore(ajaxLoginProcessingFilter, UsernamePasswordAuthenticationFilter.class)
                .csrf((csrf) -> csrf.disable());

        return http.build();
    }
}
