package io.security.corespringsecurity.config.security.config;

import io.security.corespringsecurity.config.security.common.CustomAuthenticationDetailsSource;
import io.security.corespringsecurity.config.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.config.security.handler.CustomAuthenticationFailureHandler;
import io.security.corespringsecurity.config.security.handler.CustomAuthenticationSuccessHandler;
import io.security.corespringsecurity.config.security.manager.CustomAuthorizationManager;
import io.security.corespringsecurity.config.security.provider.CustomAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatchers;

@Configuration
@EnableWebSecurity
@Order(1)
@Slf4j
public class SecurityConfig {
    @Autowired
    private CustomAuthenticationDetailsSource authenticationDetailsSource;
    @Autowired
    private CustomAuthenticationSuccessHandler authenticationSuccessHandler;
    @Autowired
    private CustomAuthenticationFailureHandler authenticationFailureHandler;
    @Autowired
    private CustomAccessDeniedHandler accessDeniedHandler;
    @Autowired
    private CustomAuthorizationManager authorizationManager;

    @Autowired
    public void globalConfigure(AuthenticationManagerBuilder auth, CustomAuthenticationProvider provider) {
        auth.authenticationProvider(provider);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) ->
                web.ignoring()
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                        .requestMatchers("/error/**");
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public HttpSessionSecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(RequestMatchers.not(AntPathRequestMatcher.antMatcher("/api/**")))
                .authorizeHttpRequests((authorizeHttpRequests) ->
                        authorizeHttpRequests
                                .requestMatchers("/", "/users", "/login*").permitAll()
//                                .requestMatchers("/mypage").hasRole("USER")
//                                .requestMatchers("/messages").hasRole("MANAGER")
//                                .requestMatchers("/config").hasRole("ADMIN")
                                .anyRequest().authenticated()
                )
                .formLogin((formLogin) ->
                        formLogin
                                .loginPage("/login")
                                .loginProcessingUrl("/login_proc")
                                .authenticationDetailsSource(authenticationDetailsSource)
                                .securityContextRepository(securityContextRepository())
                                .successHandler(authenticationSuccessHandler)
                                .failureHandler(authenticationFailureHandler)
                                .permitAll()
                )
                .logout((logout) ->
                        logout
                                .logoutRequestMatcher(AntPathRequestMatcher.antMatcher("/logout"))
                                .logoutSuccessUrl("/")
                )
                .exceptionHandling((exceptionHandling) ->
                        exceptionHandling
                                .accessDeniedHandler(accessDeniedHandler)
                );

        http
                .addFilterBefore(new AuthorizationFilter(authorizationManager), AuthorizationFilter.class);
        return http.build();
    }
}
