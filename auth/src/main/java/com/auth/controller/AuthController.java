package com.auth.controller;

import com.auth.entity.Role;
import com.auth.entity.User;
import com.auth.payload.request.LoginRequest;
import com.auth.payload.request.SignupRequest;
import com.auth.payload.request.RefreshTokenRequest;
import com.auth.payload.response.JwtResponse;
import com.auth.payload.response.MessageResponse;
import com.auth.payload.response.TokenInfoResponse;
import com.auth.repository.RoleRepository;
import com.auth.repository.UserRepository;
import com.auth.security.jwt.JwtUtils;
import com.auth.security.jwt.UserPrincipal;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);
        UserPrincipal userDetails = (UserPrincipal) authentication.getPrincipal();
        String refreshToken = jwtUtils.generateRefreshTokenFromUsername(userDetails.getUsername());
        List<String> roles = userDetails.getAuthorities().stream()
            .map(item -> item.getAuthority())
            .collect(Collectors.toList());

        long accessExp = jwtUtils.getExpirationFromToken(jwt).getTime();
        long refreshExp = jwtUtils.getExpirationFromToken(refreshToken).getTime();

        return ResponseEntity.ok(new JwtResponse(
            jwt,
            refreshToken,
            accessExp,
            refreshExp,
            userDetails.getId(),
            userDetails.getUsername(),
            userDetails.getEmail(),
            roles
        ));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account (phone not provided during signup)
        User user = new User(
            signUpRequest.getUsername(),
            signUpRequest.getEmail(),
            encoder.encode(signUpRequest.getPassword()),
            null
        );

        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                Role foundRole = roleRepository.findByName(role)
                    .orElseThrow(() -> new RuntimeException("Error: Role " + role + " is not found."));
                roles.add(foundRole);
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        if (!jwtUtils.validateJwtToken(refreshToken)) {
            return ResponseEntity.badRequest().body(new MessageResponse("Invalid refresh token"));
        }
        if (jwtUtils.isTokenExpired(refreshToken)) {
            return ResponseEntity.badRequest().body(new MessageResponse("Refresh token expired"));
        }

        String username = jwtUtils.getUserNameFromJwtToken(refreshToken);
        String newAccessToken = jwtUtils.generateJwtTokenFromUsername(username);
        long accessExp = jwtUtils.getExpirationFromToken(newAccessToken).getTime();
        long refreshExp = jwtUtils.getExpirationFromToken(refreshToken).getTime();

        return ResponseEntity.ok(new JwtResponse(
            newAccessToken,
            refreshToken,
            accessExp,
            refreshExp,
            null,
            username,
            null,
            null
        ));
    }

    @GetMapping("/token-info")
    public ResponseEntity<?> tokenInfo(@RequestHeader("Authorization") String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(new MessageResponse("Missing Bearer token"));
        }
        String token = authorizationHeader.substring(7);
        var claims = jwtUtils.getAllClaimsAllowExpired(token);
        var subject = claims.getSubject();
        var issuedAt = claims.getIssuedAt() != null ? claims.getIssuedAt().getTime() : null;
        var expiresAt = claims.getExpiration() != null ? claims.getExpiration().getTime() : null;

        return ResponseEntity.ok(new TokenInfoResponse(subject, issuedAt, expiresAt, claims));
    }
}