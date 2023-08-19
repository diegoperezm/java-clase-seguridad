package com.example.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.model.ERole;
import com.example.model.Role;
import com.example.model.User;
import com.example.payload.request.LoginRequest;
import com.example.payload.request.SignupRequest;
import com.example.payload.response.JwtResponse;
import com.example.payload.response.MessageResponse;
import com.example.repo.RoleRepository;
import com.example.repo.UserRepository;
import com.example.security.jwt.JwtUtils;
import com.example.security.services.UserDetailsImpl;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;



	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

	Authentication authentication = authenticationManager.authenticate(
		new	UsernamePasswordAuthenticationToken (
			  loginRequest.getUsername(),
			  loginRequest.getPassword()));

	  SecurityContextHolder
        	  .getContext()
        	  .setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    
    List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());

    return ResponseEntity
    		.ok(new JwtResponse(
                   jwt,
                   userDetails.getId(),
                   userDetails.getUsername(),
                   userDetails.getEmail(),
                   roles));

	}
	
	
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Username ya posee token"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Email ya esta en uso"));
		}

		User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		
	    if (strRoles == null) {
	        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
	            .orElseThrow(() -> new RuntimeException("Role no es valido"));
	        roles.add(userRole);
	      } else {
	        strRoles.forEach(role -> {
	          switch (role) {
	          case "admin":
	            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
	                .orElseThrow(() -> new RuntimeException(" Role no es valido."));
	            roles.add(adminRole);
	            break;

	          case "mod":
	            Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
	                .orElseThrow(() -> new RuntimeException("Role no es  valido"));
	            roles.add(modRole);
	            break;

	          }
	        });
	     
	        user.setRoles(roles);
	        userRepository.save(user);
	        
	        
	      }	
		
	        return ResponseEntity.ok(new MessageResponse("usuario registrado"));
		
	}


}
