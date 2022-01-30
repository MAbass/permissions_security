package sn.permissions_security.controller.forms;

import lombok.Getter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

@Getter
public class AuthRequest {
    @NotBlank
    @NotEmpty
    private String username;
    @NotBlank
    @NotEmpty
    private String password;
}
