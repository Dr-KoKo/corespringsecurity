package io.security.corespringsecurity.config.security.config;

import io.security.corespringsecurity.config.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.config.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.config.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.config.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.config.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.config.security.provider.AjaxAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@Order(0)
@Slf4j
public class AjaxSecurityConfig {
    @Autowired
    private AuthenticationConfiguration authenticationConfiguration;
    @Autowired
    private SecurityContextRepository securityContextRepository;

    @Autowired
    public void globalConfigure(AuthenticationManagerBuilder auth, AjaxAuthenticationProvider provider) {
        auth.authenticationProvider(provider);
    }

    @Bean
    public SecurityFilterChain ajaxFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(AntPathRequestMatcher.antMatcher("/api/**"))
                .authorizeHttpRequests((authorizeHttpRequests) ->
                        authorizeHttpRequests
                                .requestMatchers("/api/messages").hasRole("MANAGER")
                                .anyRequest().authenticated()
                )
                .exceptionHandling((exceptionHandling) ->
                        exceptionHandling
                                .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
                                .accessDeniedHandler(new AjaxAccessDeniedHandler())
                )
                .csrf((csrf) -> csrf.disable());

        http
                .apply(new AjaxLoginConfigurer())
                .successHandlerAjax(new AjaxAuthenticationSuccessHandler())
                .failureHandlerAjax(new AjaxAuthenticationFailureHandler())
                .setAuthenticationManager(authenticationConfiguration.getAuthenticationManager())
                .securityContextRepository(securityContextRepository)
                .loginProcessingUrl("/api/login");

        return http.build();
    }
}
