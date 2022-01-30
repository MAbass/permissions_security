package sn.permissions_security.controller.forms;


import lombok.Getter;

import javax.validation.constraints.NotBlank;
import java.util.List;

@Getter
public class CreateNewUser {
    @NotBlank(message = "The username is required")
    private String username;
    @NotBlank(message = "The password is required")
    private String password;
    private List<String> roles;
}
