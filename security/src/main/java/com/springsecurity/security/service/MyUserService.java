package com.springsecurity.security.service;

import com.springsecurity.security.entity.UserPrincipal;
import com.springsecurity.security.entity.Users;
import com.springsecurity.security.repository.UsersRepository;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;

@Service
public class MyUserService  implements UserDetailsService {

    private final UsersRepository usersRepository;

    public MyUserService(UsersRepository usersRepository) {
        this.usersRepository = usersRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Users user1 = usersRepository.findByUsername(username);

        if(user1 == null){
            System.out.println("User not found");
            throw new UsernameNotFoundException("User not found");
        }
        return new UserPrincipal(user1);
    }
}
