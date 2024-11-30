package com.sau.cryptology.Controllers;

import com.sau.cryptology.DTOs.LoginRequest;
import com.sau.cryptology.DTOs.UserDTO;
import com.sau.cryptology.Models.User;
import com.sau.cryptology.Repositories.UserRepository;
import com.sau.cryptology.Security.Services.EmailService;
import com.sau.cryptology.Security.Services.UserDetailsServiceImpl;
import jakarta.persistence.Tuple;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.*;

@Controller
public class HomeController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    @Autowired
    private EmailService emailService;
    @Autowired
    private AuthenticationManager authenticationManager;
    private final UserDetailsServiceImpl userDetailsService;

    private final Map<String, String> verificationStorage = new HashMap<>();
    private Date verificationTime;

    public HomeController(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailService emailService, AuthenticationManager authenticationManager, UserDetailsServiceImpl userDetailsService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
    }

    @GetMapping("/")
    public String getIndex() {
        return "index";
    }

    @GetMapping("/login")
    public String login() {
        if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() != "anonymousUser") {
            return "redirect:/profile";
        }

        return "login";
    }

    @PostMapping("/login")
    public String login(LoginRequest loginRequest) {

        User user = userRepository.findByUsername(loginRequest.getUsername()).get();
        if (passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            var res = sendCode(user.getEmail());
            if (res) {
                return "redirect:/verify?username=" + loginRequest.getUsername();
            }
        }
        return "redirect:/login?error";
    }

    public boolean sendCode(@RequestParam String email) {
        String code = emailService.sendVerificationCode(email);
        verificationStorage.put(email, code);
        verificationTime = new Date();
        return true;
    }

    public boolean verifyCode(@RequestParam String email, @RequestParam String code) {
        String storedCode = verificationStorage.get(email);
        if (new Date().getTime() - verificationTime.getTime() > 10000) {
            return false;
        }
        return storedCode != null && storedCode.equals(code);
    }

    @GetMapping("/verify")
    public String verify(@RequestParam String username, Model model) {
        model.addAttribute("username", username);
        return "verify";
    }

    @PostMapping("/verify")
    public String verify(@RequestParam String code, @RequestParam String username, HttpServletRequest request) {
        Optional<User> user1 = userRepository.findByUsername(username);
        if (verifyCode(user1.get().getEmail(), code)) {

            UserDetails user = userDetailsService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authenticationToken);
            SecurityContextHolder.setContext(context);

            HttpSession session = request.getSession(true);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());

            return "redirect:/profile";

        }
        return "redirect:/error/403.html";
    }


    @PostMapping("/logout")
    public String logout() {
        SecurityContextHolder.getContext().setAuthentication(null);
        return "login";
    }

    @GetMapping("/register")
    public String registerUser() {
        if (SecurityContextHolder.getContext().getAuthentication().getPrincipal() != "anonymousUser") {
            return "redirect:/profile";
        }

        return "register";
    }

    @PostMapping("/register")
    public String registerUser(User newuser) {
        if (userRepository.existsByUsername(newuser.getUsername())) {
            return "redirect:/register?error";
        }

        if (userRepository.existsByEmail(newuser.getEmail())) {
            return "redirect:/register?error";
        }

        User user = new User(newuser.getUsername(),
                newuser.getEmail(),
                passwordEncoder.encode(newuser.getPassword()),
                newuser.getFirstname(),
                newuser.getLastname());

        userRepository.save(user);

        return "redirect:/login";
    }

    @GetMapping("/profile")
    public String getUser(Model model) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        String nameSurname = userRepository.findByUsername(currentPrincipalName).get().getFirstname() + " " + userRepository.findByUsername(currentPrincipalName).get().getLastname();

        String firstName = userRepository.findByUsername(currentPrincipalName).get().getFirstname();
        String lastName = userRepository.findByUsername(currentPrincipalName).get().getLastname();
        String email = userRepository.findByUsername(currentPrincipalName).get().getEmail();
        model.addAttribute("username", currentPrincipalName);
        model.addAttribute("firstname", firstName);
        model.addAttribute("lastname", lastName);
        model.addAttribute("email", email);
        model.addAttribute("namesurname", nameSurname);
        return "profile";
    }

    @PostMapping("/profile/update")
    public String updateUser(User user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        Optional<User> user1 = userRepository.findByUsername(currentPrincipalName);
        if (user.getFirstname() != null) {
            user1.get().setFirstname(user.getFirstname());
        }
        if (user.getLastname() != null) {
            user1.get().setLastname(user.getLastname());
        }
        if (user.getEmail() != null) {
            user1.get().setEmail(user.getEmail());
        }
        userRepository.save(user1.get());
        return "redirect:/profile";
    }


}
