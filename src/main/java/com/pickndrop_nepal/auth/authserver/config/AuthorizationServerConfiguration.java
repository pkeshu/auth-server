package com.pickndrop_nepal.auth.authserver.config;

import com.pickndrop_nepal.auth.authserver.util.CustomOauthException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.sql.DataSource;
import java.security.KeyPair;

@Configuration
@EnableAuthorizationServer
@EnableConfigurationProperties(SecurityProperties.class)
@Import(Encoders.class)
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private DataSource dataSource;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;

    private final SecurityProperties securityProperties;

    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource);
    }

    public AuthorizationServerConfiguration(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    @Bean
    public DefaultTokenServices tokenServices(final TokenStore tokenStore,
                                              final ClientDetailsService clientDetailsService) {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setAuthenticationManager(authenticationManager);
        return tokenServices;
    }

    @Bean
    JdbcApprovalStore jdbcApprovalStore() {
        return new JdbcApprovalStore(dataSource);
    }

    @Bean
    public JwtAccessTokenConverter jwtTokenEnhancer() {
        SecurityProperties.JwtProperties jwtProperties = securityProperties.getJwt();
        KeyPair keyPair = keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));

        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair);
        return jwtAccessTokenConverter;
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(dataSource);
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.authenticationManager(authenticationManager)
                .accessTokenConverter(jwtTokenEnhancer())
                .approvalStore(jdbcApprovalStore())
                .tokenStore(tokenStore()).exceptionTranslator((exception) -> {
            if (exception instanceof OAuth2Exception) {
                OAuth2Exception auth2Exception = (OAuth2Exception) exception;
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new CustomOauthException(auth2Exception.getMessage()));
            } else {
                throw exception;
            }
        });
    }

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.passwordEncoder(passwordEncoder).tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    private KeyPair keyPair(SecurityProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
        return keyStoreKeyFactory.getKeyPair(jwtProperties.getKeyPairAlias(), jwtProperties.getKeyPairPassword().toCharArray());
    }

    private KeyStoreKeyFactory keyStoreKeyFactory(SecurityProperties.JwtProperties jwtProperties) {
        return new KeyStoreKeyFactory(jwtProperties.getKeyStore(), jwtProperties.getKeyStorePassword().toCharArray());
    }

    @Bean
    public FilterRegistrationBean corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }


}