package com.pickndrop_nepal.auth.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.web.client.RestTemplate;

import static java.lang.String.format;
import static java.util.Arrays.asList;

public class RestTemplateConfiguration {

    @Bean
    public RestTemplate getRestTemplate() {
        return new RestTemplate();
    }


    public static OAuth2RestTemplate oauth2RestTemplate(String username, String password) {

        ClientCredentialsResourceDetails resourceDetails = new ClientCredentialsResourceDetails();
        resourceDetails.setAccessTokenUri(format("%s/oauth/token?grant_type=password&username=" + username + "&password=" + password, "http://localhost:9191"));
        resourceDetails.setClientId("mobile");
        resourceDetails.setClientSecret("pick@dropN3p@l");
        resourceDetails.setGrantType("client_credentials");
        resourceDetails.setScope(asList("read", "write"));
        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext();
        return new OAuth2RestTemplate(resourceDetails, clientContext);
    }

}
