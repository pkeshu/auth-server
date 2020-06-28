package com.pickndrop_nepal.auth.authserver.controller;

import com.pickndrop_nepal.auth.authserver.config.RestTemplateConfiguration;
import com.pickndrop_nepal.auth.authserver.config.SecurityProperties;
import com.pickndrop_nepal.auth.authserver.enitity.AuthoritiesEntity;
import com.pickndrop_nepal.auth.authserver.enitity.UsersEntity;
import com.pickndrop_nepal.auth.authserver.model.ErrorResponse;
import com.pickndrop_nepal.auth.authserver.model.LoginResponseDto;
import com.pickndrop_nepal.auth.authserver.model.Response;
import com.pickndrop_nepal.auth.authserver.model.SignupRequestDto;
import com.pickndrop_nepal.auth.authserver.repository.AuthorityRepository;
import com.pickndrop_nepal.auth.authserver.repository.UserRepository;
import com.pickndrop_nepal.auth.authserver.service.Authority;
import com.sun.net.httpserver.HttpsParameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.*;

@RestController
@ControllerAdvice
public class UserController {

    @Autowired
    private UserRepository repository;

    @Autowired
    private AuthorityRepository authorityRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private DefaultTokenServices tokenServices;

    @PostMapping("/user")
    public ResponseEntity<String> registerUser(@Valid @RequestBody SignupRequestDto userrequest) {
        if (repository.existsByUsername(userrequest.getUsername())) {
            return new ResponseEntity<String>("Username is already taken", HttpStatus.BAD_REQUEST);
        }
        UsersEntity entity = new UsersEntity();
        entity.setAccountNonExpired(true);
        entity.setAccountNonLocked(true);
        entity.setCredentialsNonExpired(true);
        entity.setEnabled(true);
        entity.setPassword(encoder.encode(userrequest.getPassword()));
        entity.setUsername(userrequest.getUsername());
        String role = "CUSTOMER";
        String role2 = "USER";
        String role3 = "SUPERADMIN";
        String role4 = "OPERATION";
        Set<AuthoritiesEntity> roles = new HashSet<>();
        AuthoritiesEntity authoritiesEntity = new AuthoritiesEntity();
        Set<String> strRoles = new HashSet<>();
        strRoles.add(role);
        strRoles.forEach(rol -> {
            switch (rol) {
                case "ADMIN":
                    authoritiesEntity.setAuthority(Authority.ADMIN);
                    authoritiesEntity.setUser(entity);
                    roles.add(authoritiesEntity);
                    break;
                case "USER": {
                    authoritiesEntity.setAuthority(Authority.USER);
                    authoritiesEntity.setUser(entity);
                    roles.add(authoritiesEntity);
                    break;
                }
                case "CUSTOMER": {
                    authoritiesEntity.setAuthority(Authority.CUSTOMER);
                    authoritiesEntity.setUser(entity);
                    roles.add(authoritiesEntity);
                    break;
                }
                case "SUPERADMIN": {
                    authoritiesEntity.setAuthority(Authority.SUPERADMIN);
                    authoritiesEntity.setUser(entity);
                    roles.add(authoritiesEntity);
                    break;
                }
                case "OPERATION": {
                    authoritiesEntity.setAuthority(Authority.OPERATION);
                    authoritiesEntity.setUser(entity);
                    roles.add(authoritiesEntity);
                }
                case "DELIVERY": {
                    authoritiesEntity.setAuthority(Authority.DELIVERY);
                    authoritiesEntity.setUser(entity);
                    roles.add(authoritiesEntity);
                }
            }
        });
        entity.setAuthorities(roles);
        repository.save(entity);
        return new ResponseEntity<>("User Created Successfully", HttpStatus.CREATED);

    }

    @PostMapping("/user/signin")
    public ResponseEntity<Response> authenticateUser(@Valid @RequestBody SignupRequestDto loginRequestDto) throws Exception {
        Optional<UsersEntity> byUsername = repository.findByUsername(loginRequestDto.getUsername());
        if (byUsername.isPresent()) {
            UsersEntity user = byUsername.get();
            String value = RestTemplateConfiguration.oauth2RestTemplate(loginRequestDto.getUsername(), loginRequestDto.getPassword()).getAccessToken().getValue();
            LoginResponseDto loginResponseDto = new LoginResponseDto();
            loginResponseDto.setUsername(user.getUsername());
            loginResponseDto.setAccessToken(value);

            List<String> roles = new ArrayList<>();
            user.getAuthorities().forEach(authority -> {
                roles.add(authority.getAuthority().name());
            });
            loginResponseDto.setRoles(roles);

            return ResponseEntity.ok(loginResponseDto);
        }
        ErrorResponse errorResponse = new ErrorResponse();
        errorResponse.setStatusCode(HttpStatus.NOT_FOUND.value());
        errorResponse.setMessage("Username or Password mismatch!");
        errorResponse.setDetails("Please provide correct username or password!");
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }
}
