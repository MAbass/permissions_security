package sn.permissions_security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import sn.permissions_security.entity.Privilege;
import sn.permissions_security.entity.User;
import sn.permissions_security.services.impl.PrivilegeServiceImpl;
import sn.permissions_security.services.impl.UserServiceImpl;

@SpringBootApplication
public class PermissionsSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(PermissionsSecurityApplication.class, args);
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }
    /*@Bean
    CommandLineRunner run(UserServiceImpl userService, PrivilegeServiceImpl privilegeService) {
        return args -> {
            privilegeService.addPrivilege(new Privilege(null, "USER_CREATE_PRIVILEGE"));
            privilegeService.addPrivilege(new Privilege(null, "USER_READ_PRIVILEGE"));
            privilegeService.addPrivilege(new Privilege(null, "USER_DELETE_PRIVILEGE"));
            privilegeService.addPrivilege(new Privilege(null, "USER_MODIFY_PRIVILEGE"));
            userService.saveUser(new User(null, "abass", "abass", null, null, null, null));
            userService.saveUser(new User(null, "moussa", "moussa", null, null, null, null));
            userService.addRoleToUser("abass", "USER_CREATE_PRIVILEGE");
            userService.addRoleToUser("abass", "USER_DELETE_PRIVILEGE");
            userService.addRoleToUser("abass", "USER_MODIFY_PRIVILEGE");
            userService.addRoleToUser("abass", "USER_READ_PRIVILEGE");
            userService.addRoleToUser("moussa", "USER_READ_PRIVILEGE");
        };
    }*/
}
