package com.pickndrop_nepal.auth.authserver.service;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.pickndrop_nepal.auth.authserver.enitity.AuthoritiesEntity;
import com.pickndrop_nepal.auth.authserver.enitity.UsersEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


//public class UserPrinciple extends UsersEntity implements UserDetails {
//    private Long id;
//    @JsonIgnore
//    private String password;
//    private String username;
//
//    private List<AuthoritiesEntity> roles;
//
//    private Collection<? extends GrantedAuthority> authorities;
//
//    public UserPrinciple(UsersEntity user) {
//        super(user);
//    }
//
//    public UserPrinciple(Long id,String username,String password, Collection<? extends GrantedAuthority> authorities) {
//        this.id=id;
//        this.username = username;
//        this.password = password;
//        this.authorities = authorities;
//    }
//
//    public static UserPrinciple build(UsersEntity user) {
//        List<GrantedAuthority> authorities = user.getAuthorities()
//                .stream().map(authority ->
//                        new SimpleGrantedAuthority(authority.getAuthority()))
//                .collect(Collectors.toList());
//        return new UserPrinciple(
//                user.getId(),
//                user.getUsername(),
//                user.getPassword(),
//                authorities
//        );
//    }
//
//
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        return super.getAuthorities();
//    }
//
//    @Override
//    public String getPassword() {
//        return password;
//    }
//
//    @Override
//    public String getUsername() {
//        return username;
//    }
//
//    @Override
//    public boolean isAccountNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isAccountNonLocked() {
//        return true;
//    }
//
//    @Override
//    public boolean isCredentialsNonExpired() {
//        return true;
//    }
//
//    @Override
//    public boolean isEnabled() {
//        return true;
//    }
//}
