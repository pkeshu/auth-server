package com.pickndrop_nepal.auth.authserver.service;

import com.pickndrop_nepal.auth.authserver.enitity.AuthoritiesEntity;
import com.pickndrop_nepal.auth.authserver.enitity.UsersEntity;
import com.pickndrop_nepal.auth.authserver.model.Users;
import com.pickndrop_nepal.auth.authserver.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Component("userDetailsService")
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepository usersDao;
    @Override
    public UserDetails loadUserByUsername(String username)  {

        Optional<UsersEntity> user = usersDao.findByUsername(username);

        if (!user.isPresent()) {
            throw new UsernameNotFoundException("user not found.");
        }
        UsersEntity usersEntity=user.get();

        Set<AuthoritiesEntity> roles = usersEntity.getAuthorities();

        Set<GrantedAuthority> authorities = new HashSet<>();

        for (AuthoritiesEntity role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getAuthority().toString()));
        }

        Users users = new Users();
        users.setUsername(usersEntity.getUsername());
        users.setPassword(usersEntity.getPassword());
        users.setAccountNonExpired(usersEntity.isAccountNonExpired());
        users.setCredentialsNonExpired(usersEntity.isCredentialsNonExpired());
        users.setAccountNonLocked(usersEntity.isAccountNonExpired());
        users.setEnabled(usersEntity.isEnabled());
        users.setAuthorities(authorities);
        return users;
    }
}
