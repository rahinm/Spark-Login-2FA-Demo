package app.user;

import lombok.*;

//@Value // All fields are private and final. Getters (but not setters) are generated (https://projectlombok.org/features/Value.html)
@AllArgsConstructor
@Setter
@Getter
public class User {
    String username;
    String salt;
    String hashedPassword;
    String sharedSecret;
}
