package com.ipsec.security.service;

import com.ipsec.security.entity.User;
import com.ipsec.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Set;

/**
 * REAL first-boot credential bootstrap — no hardcoded password ships in the
 * database seed anymore.
 *
 * On startup, if the {@code admin} user does not exist, this component:
 *
 *  1. Generates a strong random password (16 chars, SecureRandom, at least
 *     one of each class) — or uses {@code ADMIN_PASSWORD} from the
 *     environment when the operator supplies one.
 *  2. Stores ONLY the bcrypt hash in the users table.
 *  3. Writes the plaintext once to {@code .admin-credentials} in the working
 *     directory (mode 600 where the OS supports it) so the operator can read
 *     it exactly once, and instructs to delete the file after first login.
 *
 * {@code ADMIN_PASSWORD_FILE} (default: {@code .admin-credentials}) can point
 * elsewhere. With {@code admin.bootstrap-enabled=false} nothing is created
 * (tests set this).
 */
@Component
public class AdminBootstrap implements ApplicationRunner {

    static final String BOOTSTRAP_USERNAME = "admin";
    static final String DEFAULT_CREDENTIALS_FILE = ".admin-credentials";

    private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I/O for readability
    private static final String LOWER = "abcdefghijkmnpqrstuvwxyz"; // no l
    private static final String DIGITS = "23456789";                // no 0/1
    private static final String SYMBOLS = "!@#$%^&*()-_=+";
    private static final String ALL = UPPER + LOWER + DIGITS + SYMBOLS;

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final String credentialsFile;
    private final boolean bootstrapEnabled;

    @Autowired
    public AdminBootstrap(UserRepository userRepository,
                          BCryptPasswordEncoder passwordEncoder,
                          @Value("${admin.credentials-file:" + DEFAULT_CREDENTIALS_FILE + "}") String credentialsFile,
                          @Value("${admin.bootstrap-enabled:true}") boolean bootstrapEnabled) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.credentialsFile = credentialsFile;
        this.bootstrapEnabled = bootstrapEnabled;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!bootstrapEnabled) {
            return;
        }
        try {
            if (userRepository.findByUsername(BOOTSTRAP_USERNAME).isPresent()) {
                return; // existing deployment — operator-managed credentials win
            }
        } catch (Exception ex) {
            System.err.println("[Bootstrap] cannot inspect user store (" + ex.getMessage()
                + ") — skipping admin bootstrap");
            return;
        }

        String password;
        String envPassword = System.getenv("ADMIN_PASSWORD");
        if (envPassword != null && envPassword.length() >= 12) {
            password = envPassword;
        } else {
            password = generatePassword(16);
            if (envPassword != null) {
                System.err.println("[Bootstrap] ADMIN_PASSWORD was set but shorter than 12 chars"
                    + " — a random password was generated instead");
            }
        }

        try {
            User admin = new User();
            admin.setUsername(BOOTSTRAP_USERNAME);
            admin.setPasswordHash(passwordEncoder.encode(password));
            admin.setEmail(System.getenv().getOrDefault("ADMIN_EMAIL", "admin@localhost"));
            admin.setWhitelistedIp("127.0.0.1");
            admin.setDeviceFingerprint("bootstrap");
            userRepository.save(admin);
        } catch (Exception ex) {
            System.err.println("[Bootstrap] could not create admin user: " + ex.getMessage());
            return;
        }

        writeCredentialsFile(password);
        System.out.println("\n============================================================");
        System.out.println("  Created bootstrap user '" + BOOTSTRAP_USERNAME + "'.");
        System.out.println("  Credentials written ONCE to: " + Paths.get(credentialsFile).toAbsolutePath());
        System.out.println("  Read them, log in, then DELETE the file:");
        System.out.println("    rm " + credentialsFile);
        System.out.println("  (or set ADMIN_PASSWORD before first boot to choose your own)");
        System.out.println("============================================================\n");
    }

    /** Writes the plaintext password once, POSIX perms 600 when supported. */
    private void writeCredentialsFile(String password) {
        try {
            Path path = Paths.get(credentialsFile);
            String content = "username: " + BOOTSTRAP_USERNAME + "\n"
                + "password: " + password + "\n"
                + "(delete this file after first login)\n";
            Files.writeString(path, content, StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(path, Set.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
            } catch (UnsupportedOperationException ignored) {
                // Windows: no POSIX perms; the file stays user-private in practice
            }
        } catch (Exception ex) {
            // Still print so the operator is not locked out; console is ephemeral.
            System.err.println("[Bootstrap] could not write " + credentialsFile
                + " (" + ex.getMessage() + ") — password follows:\n  " + password);
        }
    }

    /** Random password guaranteed to contain one char of each class. */
    public static String generatePassword(int length) {
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(length);
        sb.append(UPPER.charAt(rnd.nextInt(UPPER.length())));
        sb.append(LOWER.charAt(rnd.nextInt(LOWER.length())));
        sb.append(DIGITS.charAt(rnd.nextInt(DIGITS.length())));
        sb.append(SYMBOLS.charAt(rnd.nextInt(SYMBOLS.length())));
        for (int i = sb.length(); i < length; i++) {
            sb.append(ALL.charAt(rnd.nextInt(ALL.length())));
        }
        // Fisher-Yates so the guaranteed prefix is not predictable
        for (int i = sb.length() - 1; i > 0; i--) {
            int j = rnd.nextInt(i + 1);
            char tmp = sb.charAt(i);
            sb.setCharAt(i, sb.charAt(j));
            sb.setCharAt(j, tmp);
        }
        return sb.toString();
    }
}
