package com.hch;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) {
        auth.inMemoryAuthentication()
                .withUser("discUser")
                .password("{noop}discPassword")
                .roles("SYSTEM");
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sessionManagement ->
                        sessionManagement.
                                sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/eureka/apps/**").hasRole("SYSTEM")
                                .anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Configuration
    public static class AdminSecurityConfig {

        @Autowired
        public void configureGlobal(AuthenticationManagerBuilder auth) {
            auth.inMemoryAuthentication()
                    .withUser("admin")
                    .password("{noop}admin")
                    .roles("ADMIN");
        }

        @Bean
        @Order(1)
        public SecurityFilterChain configure(HttpSecurity http) throws Exception {
            http.securityMatcher("/",
                            "/info",
                            "/health",
                            "/webjars/**",
                            "/eureka",
                            "/eureka/",
                            "/eureka/css/**",
                            "/eureka/js/**",
                            "/eureka/images/**")
                    .sessionManagement(sessionManagement ->
                            sessionManagement.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                    .httpBasic(Customizer.withDefaults())
                    .authorizeHttpRequests(authorize ->
                            authorize
                                    .requestMatchers("/info", "/health").authenticated()
                                    .requestMatchers(HttpMethod.GET,
                                            "/",
                                            "/webjars/**",
                                            "/eureka",
                                            "/eureka/",
                                            "/eureka/css/**",
                                            "/eureka/js/**",
                                            "/eureka/images/**")
                                    .hasRole("ADMIN")
                                    .anyRequest().denyAll())
                    .csrf(AbstractHttpConfigurer::disable);
            return http.build();
        }
    }
}
