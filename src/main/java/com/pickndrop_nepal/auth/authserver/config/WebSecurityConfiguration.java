package com.pickndrop_nepal.auth.authserver.config;

import com.pickndrop_nepal.auth.authserver.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@Import(Encoders.class)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

        @Override
    protected void configure(HttpSecurity http) throws Exception {
            http.headers().frameOptions().disable();
            http.csrf().disable().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and().authorizeRequests().antMatchers("/oauth/token","/user/**")
                    .permitAll().anyRequest().authenticated();

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder);
    }
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

//    @Autowired
//    private DataSource dataSource;
//
//    @Bean
//    public UserDetailsService userDetailsService() {
//        if (userDetailsService == null) {
//            userDetailsService = new JdbcDaoImpl();
//            ((JdbcDaoImpl) userDetailsService).setDataSource(dataSource);
//        }
//        return userDetailsService;
//    }
//
//
//
//
//
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        super.configure(web);
//    }



}
