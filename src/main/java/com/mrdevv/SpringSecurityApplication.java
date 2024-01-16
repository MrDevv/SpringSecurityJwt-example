package com.mrdevv;

import com.mrdevv.models.ERole;
import com.mrdevv.models.RoleEntity;
import com.mrdevv.models.UserEntity;
import com.mrdevv.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

//	Crear usuarios de prueba

//	@Autowired
//	PasswordEncoder passwordEncoder;
//
//	@Autowired
//	UserRepository userRepository;

//	@Bean
//	CommandLineRunner init(){
//		return args -> {
//			UserEntity userEntity = UserEntity.builder()
//					.email("miguel@gmail.com")
//					.username("santiago")
//					.password(passwordEncoder.encode("1234"))
//					.roles(Set.of(RoleEntity.builder()
//							.name(ERole.valueOf(ERole.ADMIN.name()))
//						.build()))
//					.build();
//
//			UserEntity userEntity2 = UserEntity.builder()
//					.email("oswaldo@gmail.com")
//					.username("oswaldo")
//					.password(passwordEncoder.encode("1234"))
//					.roles(Set.of(RoleEntity.builder()
//							.name(ERole.valueOf(ERole.USER.name()))
//							.build()))
//					.build();
//
//			UserEntity userEntity3 = UserEntity.builder()
//					.email("julio@gmail.com")
//					.username("julio")
//					.password(passwordEncoder.encode("1234"))
//					.roles(Set.of(RoleEntity.builder()
//							.name(ERole.valueOf(ERole.INVITED.name()))
//							.build()))
//					.build();
//
//			userRepository.save(userEntity);
//			userRepository.save(userEntity2);
//			userRepository.save(userEntity3);
//		};
//	}

}
