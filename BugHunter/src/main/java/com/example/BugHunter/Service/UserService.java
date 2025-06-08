package com.example.BugHunter.Service;

import com.example.BugHunter.DTO.BugHunterUserDTO;
import com.example.BugHunter.DTO.UserResponseDTO;
import com.example.BugHunter.Exception.CustomException;
import com.example.BugHunter.Model.BugHunterUser;
import com.example.BugHunter.Model.PasswordResetToken;
import com.example.BugHunter.Model.Roles;
import com.example.BugHunter.Repositery.PasswordResetTokenRepository;
import com.example.BugHunter.Repositery.RolesRepository;
import com.example.BugHunter.Repositery.UserRepo;
import com.example.BugHunter.ValidationChecker.ValidateInput;
import com.example.BugHunter.ValidationChecker.generate;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service

public class UserService implements ValidateInput , generate {
    public enum LoginMethod
    {
        Username,Email
    }
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserRepo userRepo;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final JwtService jwtService;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private RolesRepository roleRepository;
    private static final String VERIFICATION_LINK_TEMPLATE = "https://nestaro.in/v1/auth/verify?email=";

    public UserService(AuthenticationManager authenticationManager, EmailService emailService, JwtService jwtService, PasswordResetTokenRepository passwordResetTokenRepository) {
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
    }

    @Transactional
    public BugHunterUser register(@Valid BugHunterUserDTO userDTO) {

        //Validate input
        validateUserRegistrationInput(userDTO);

        //Check for existing email
        checkExistingUser(userDTO);

        //Map DTO to User entity
        BugHunterUser bugHunterUser=mapToEntity(userDTO);

        // Check if password is provided, otherwise keep the old password
        bugHunterUser.setPassword(passwordEncoder.encode(userDTO.getPassword()));

         //Set verification details
        setVerificationDetails(userDTO,bugHunterUser);

        //set username
        bugHunterUser.setUsername(generateUniqueUsername(userDTO));

        //Set default role
        setDefaultUserRole(bugHunterUser);
        return userRepo.save(bugHunterUser);

    }

    private void setDefaultUserRole(BugHunterUser bugHunterUser) {
        Roles defaultRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new CustomException("Default role not found!"));
        bugHunterUser.setRole(defaultRole);
    }

    @Override
    public void validateUserRegistrationInput(BugHunterUserDTO bugHunterUserDTO) {
      if(bugHunterUserDTO.getPassword()==null || bugHunterUserDTO.getPassword().isEmpty())
      {
          throw new CustomException("Password cannot be null or empty");
      }
      if(bugHunterUserDTO.getEmail()==null)
      {
          throw new CustomException("Email must be Provided");
      }
    }

    @Override
    public void checkExistingUser(BugHunterUserDTO userDTO) {
        if (userDTO.getEmail() != null && userRepo.existsByemail(userDTO.getEmail())) {
            throw new CustomException("Email is already registered.");
        }
    }
    private void setVerificationDetails(BugHunterUserDTO userDTO, BugHunterUser user) {

        // Set initial verification status
        user.setVerificationStatus(BugHunterUser.VerificationStatus.Unverified);

        // Determine verification method
        //Using Default Email Method
        BugHunterUser.VerificationMethod verificationMethod =BugHunterUser.VerificationMethod.Email;
        user.setVerificationMethod(verificationMethod);

        // Set contact information
        user.setEmail(userDTO.getEmail());
    }

    @Override
    public String generateUniqueUsername(BugHunterUserDTO userDTO) {
        // Step 1: Truncate or clean the full name
        String baseName = userDTO.getFullname().replaceAll("\\s+", "").length() > 10
                ? userDTO.getFullname().replaceAll("\\s+", "").substring(0, 10)
                : userDTO.getFullname().replaceAll("\\s+", ""); // Remove spaces and limit to 10 characters

        // Step 2: Generate a unique username with a random suffix
        String username;
        do {
            username = baseName + "_" + UUID.randomUUID().toString().substring(0, 6);
        } while (userRepo.existsByUsername(username)); // Check for uniqueness

        // Step 3: Return the unique username
        return username;
    }
    public ResponseEntity<?> notifyUser(BugHunterUser user, boolean isRegistration) {
        String token = GenerateToken(user.getId(), user.getEmail());
        String verificationUrl = "http://bughunter-game.verification.com/v1/verify?email=" +
                user.getEmail() + "&token=" + token;

        if (isRegistration) {
            // Registration scenario
            return ResponseEntity.ok(Map.of(
                    "verificationType", "email",
                    "verificationUrl", verificationUrl,
                    "message", "Welcome to BugHunter – Your Cyber Adventure Begins!",
                    "details", "Your BugHunter account has been created. Please verify to unlock missions, track achievements, and connect with other hunters!",
                    "verificationStatus", "Pending",
                    "Role", user.getRole(),
                    "username", user.getUsername(),
                    "actionRequired", "Verify your email to activate your BugHunter profile.",
                    "benefits", List.of(
                            "Access to exclusive hacking missions",
                            "Earn rewards and climb the leaderboard",
                            "Unlock premium tools and tips",
                            "Track your bug-hunting performance",
                            "Join the elite hunter community"
                    ),
                    "helpMessage", "Need help? Reach out to us at support@bughuntergame.com"
            ));
        } else {
            // Login but not verified
            return ResponseEntity.status(401).body(Map.of(
                    "message", "Your account is not verified yet.",
                    "verificationUrl", verificationUrl,
                    "actionRequired", "Please verify your email to access BugHunter features.",
                    "status", "Verification Pending"
            ));
        }
    }
    private String GenerateToken(Long id, String email) {
        // Generate reset token
        String Token = UUID.randomUUID().toString();
        // Store token in database with expiration
        saveToken(id, Token);
        // Send verification email
        sendVerificationEmail(email, Token);
        return Token;
    }
    @Transactional
    public void updateRoleId(Long newRoleId, String username) {
        BugHunterUser user = userRepo.findByUsername(username);
        if (user == null) {
            throw new CustomException("User not found with username: " + username);
        }
        Long oldRoleId = user.getRole().getId();
        Roles newRole = roleRepository.findById(newRoleId)
                .orElseThrow(() -> new CustomException("Role not found with roleId: " + newRoleId));

        user.setRole(newRole);
        userRepo.save(user);
    }
    @Transactional
    public BugHunterUser updateUser(Long id, BugHunterUserDTO userDTO) {
        BugHunterUser existingUser = userRepo.findById(id)
                .orElseThrow(() -> new CustomException("User not found"));

        // Updating fields from DTO to User entity
        existingUser.setFullname(userDTO.getFullname());
        existingUser.setEmail(userDTO.getEmail());

        // Check if password is provided, otherwise keep the old password
        if (userDTO.getPassword() != null && !userDTO.getPassword().isEmpty()) {
            existingUser.setPassword(passwordEncoder.encode(userDTO.getPassword()));
        }
        return userRepo.save(existingUser);
    }
    private BugHunterUser mapToEntity(BugHunterUserDTO dto) {
        BugHunterUser user = new BugHunterUser();

        user.setEmail(dto.getEmail());
        user.setFullname(dto.getFullname());
        user.setUsername(dto.getUsername());
        user.setPassword(dto.getPassword()); // This will be encoded later
        user.setXp(dto.getXp());
        user.setStreak(dto.getStreak());
        user.setTotalSolved(dto.getTotalSolved());
        user.setLastSolvedDate(dto.getLastSolvedDate());

        user.setStatus(BugHunterUser.UserStatus.Inactive);
        user.setVerificationMethod(BugHunterUser.VerificationMethod.Email); // or Phone based on your logic

        return user;
    }


    /**
     * Get user by ID.
     *
     * @param id the user ID
     * @return the user as DTO
     * @throws CustomException if user not found
     */
    @Transactional(readOnly = true)
    public UserResponseDTO getUserById(Long id) {
        BugHunterUser user = userRepo.findById(id)
                .orElseThrow(() -> new CustomException("User not found"));
        return mapToDTO(user);
    }

    /**
     * Get all users in the system.
     *
     * @return list of all users as DTOs
     */
    @Transactional(readOnly = true)
    public ResponseEntity<List<UserResponseDTO>>getAllUsers() {
        List<BugHunterUser> users = userRepo.findAll();
        List<UserResponseDTO> responseDTO = UserResponseDTO.fromEntityList(users);
        return ResponseEntity.ok(responseDTO);
    }
    public UserResponseDTO mapToDTO(BugHunterUser user) {
       return UserResponseDTO.fromEntity(user);
    }

    @Transactional(readOnly = true)
    public Long getUserIdByUsername(String username) {
        BugHunterUser user = userRepo.findByUsername(username);
        return user != null ? user.getId() : null;
    }
    @Transactional(readOnly = true)
    public BugHunterUser getUserByUsername(String username) {
        return userRepo.findByUsername(username);
    }
    public String generateResetLink(HttpServletRequest request) {
        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
        return baseUrl + "/reset-password-using-token";
    }
    @Override
    public String maskEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "****";
        }

        String[] parts = email.split("@");
        String name = parts[0];
        String domain = parts[1];

        String maskedName;
        if (name.length() <= 2) {
            maskedName = "*".repeat(name.length());
        } else {
            maskedName = name.substring(0, 2) + "*".repeat(name.length() - 2);
        }

        return maskedName + "@" + domain;
    }
    public BugHunterUser authenticateUser(String username, String password, String email, LoginMethod method) {
        BugHunterUser user;

        if (method == LoginMethod.Email) {
            user = loginWithEmail(email);
            username = user.getUsername(); // use this username for authentication
        } else {
            user = userRepo.findByUsername(username);
            if (user == null) {
                throw new AuthenticationException("Invalid username") {};
            }
        }

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        return user;
    }


    @Override
    public boolean isNullOrEmpty(String str) {
        return str == null || str.isEmpty();
    }

    @Override
    public boolean Check(String username, String email,  String password) {
        return
                isNullOrEmpty(username) &&
                isNullOrEmpty(email) &&
                isNullOrEmpty(password);
    }
    @Override
    public BugHunterUser loginWithEmail(String email) {
        BugHunterUser user = userRepo.findByemail(email);
        if (user == null || user.getUsername() == null) {
            throw new AuthenticationException("Invalid email") {};
        }
        return user;
    }
    @Override
    public BugHunterUser findUser(LoginMethod loginMethod, String username, String phoneNumber, String email) {
        if (loginMethod == null) {
            throw new CustomException("Invalid identification method");
        }
        return switch (loginMethod) {
            case Username -> userRepo.findByUsername(username);
            case Email -> userRepo.findByemail(email);
        };
    }


    public boolean ValidateIdentifier(String username, String phoneNumber, String email) {
        return !isNullOrEmpty(username) || !isNullOrEmpty(email) || !isNullOrEmpty(phoneNumber);
    }

    public boolean validateResetMethod(String resetMethod) {
        if (isNullOrEmpty(resetMethod)) {
            return false; // fail if null or empty
        }
        return resetMethod.equals("email") || resetMethod.equals("phone");
    }
    public ResponseEntity<?> handleLoginRequest(String username, String email, String password) {

        // Password Login - needs at least one identifier + password
        if (isNullOrEmpty(password)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Password is required for authentication"));
        }
        if (isNullOrEmpty(username) && isNullOrEmpty(email)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Username, or email is required"));
        }
        String input;
        if (!isNullOrEmpty(username)) {
            input = username;
        } else if (!isNullOrEmpty(email)) {
            input = email;
        }
        LoginMethod loginMethod = determineLoginMethod(username, email);
         BugHunterUser user = authenticateUser(username, email, password,loginMethod);

        if (Objects.equals(user.getStatus(), "Deleted")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Your account has been deleted. Please contact support if you wish to restore it."));
        }
        if (Objects.equals(user.getVerificationStatus(), "Unverified")) {
            return notifyUser(user,false);
        }

        return jwtService.generateAuthResponseForUser(user);
    }


    @Override
    public LoginMethod determineLoginMethod(String username, String email) {
        if (!isNullOrEmpty(username)) {
            return LoginMethod.Username;
        } else
            return LoginMethod.Email;
    }
    private boolean isValidPassword(String password) {
        // Example Password Validation Function
        return password.length() >= 8 && password.matches(".*[A-Z].*") && password.matches(".*\\d.*");
    }
    public Long verifyPasswordResetToken(String token) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token);

        if (resetToken == null) {
            return null; // Token does not exist
        }
        if (resetToken.getExpiryDate().isBefore(Instant.now())) {
            passwordResetTokenRepository.delete(resetToken);
            throw new IllegalStateException("Token has expired. Please request a new one.");
        }
        return resetToken.getUserId();
    }
    @Transactional
    public void verifyUser(String email) {
        BugHunterUser user =userRepo.findByemail(email);
        if (user == null) {
            throw new CustomException("User not found");
        }
        user.setVerificationStatus(BugHunterUser.VerificationStatus.Verified);
        BugHunterUser bugHunterUser = new BugHunterUser();
        bugHunterUser.setId(user.getId());
        userRepo.save(bugHunterUser);
    }
    @Transactional
    public void saveToken(Long userId, String resetToken) {
        // Create expiration time (e.g., 1 hour from now)
        Instant expiryDate = Instant.now().plus(1, ChronoUnit.HOURS);

        // Create and save the token entity
        PasswordResetToken token = new PasswordResetToken();
        token.setToken(resetToken);
        token.setUserId(userId);
        token.setExpiryDate(expiryDate);

        passwordResetTokenRepository.save(token);
    }
    public void sendVerificationEmail(String email, String token) {
        try {
            String verificationLink = VERIFICATION_LINK_TEMPLATE + "?email=" + email;
            String emailBody = "Click the link to verify your account: <a href=\"" + verificationLink + "\">Verify Now</a>"
                    + "<br><br><strong>Note:</strong> Your verification token is <b>" + token + "</b>. "
                    + "Without this token, verification will not be completed.";

            emailService.sendVerificationEmail(email, "Verify your email", emailBody);
        } catch (MessagingException e) {
            throw new CustomException("Failed to send verification email: " + e.getMessage());
        }
    }
}
