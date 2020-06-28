package com.pickndrop_nepal.auth.authserver.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.pickndrop_nepal.auth.authserver.enitity.AuthoritiesEntity;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.io.Serializable;
import java.util.Set;

public class SignupRequestDto implements Serializable {

    private String username;
    private String password;


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
