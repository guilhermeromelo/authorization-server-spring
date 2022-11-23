package org.mvtest.authserver.security;

import org.mvtest.authserver.domain.model.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class JPAUserService implements UserDetailsService {

    private final UserRepository userRepository;

    public JPAUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        final var user = userRepository.findByLogin(login)
                .orElseThrow(()-> new UsernameNotFoundException(login));

        final var simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_" + "default");

        return new User(
                user.getEmail(),
                user.getSenha(),
                List.of(simpleGrantedAuthority)
        );
    }
}