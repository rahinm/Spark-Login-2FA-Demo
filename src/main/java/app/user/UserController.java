package app.user;

import org.mindrot.jbcrypt.*;

import app.util.AuthNResult;

import static app.Application.userDao;
import static app.util.TotpUtil.*;

public class UserController {

    // Authenticate the user by hashing the inputted password using the stored salt,
    // then comparing the generated hashed password to the stored hashed password
    public static AuthNResult authenticate(String username, String password) {
        if (username.isEmpty() || password.isEmpty()) {
            return AuthNResult.FAILURE;
        }
        User user = userDao.getUserByUsername(username);
        if (user == null) {
            return AuthNResult.FAILURE;
        }
        String hashedPassword = BCrypt.hashpw(password, user.getSalt());
         
        return hashedPassword.equals(user.getHashedPassword()) ? AuthNResult.SUCCESS : AuthNResult.FAILURE;
    }

    
    public static AuthNResult authenticate(String username, String password, String otpcode) {
        if (username.isEmpty() || password.isEmpty()) {
            return AuthNResult.FAILURE;
        }
        User user = userDao.getUserByUsername(username);
        if (user == null) {
            return AuthNResult.FAILURE;
        }
        String hashedPassword = BCrypt.hashpw(password, user.getSalt());
        if (!hashedPassword.equals(user.getHashedPassword())){
        	return AuthNResult.FAILURE;
        }
        if ((otpcode == null || otpcode.isEmpty()) && user.getSharedSecret() == null) {
        	return AuthNResult.OTP_REG_REQUIRED;
        }
        return validateOtp(username, otpcode) ? AuthNResult.SUCCESS : AuthNResult.FAILURE;
    }

    
    public static boolean validateOtp(String username, String otpCode) {
    	User user = userDao.getUserByUsername(username);
    	if (user != null) {
    		return otpVerifier(user.getSharedSecret(), otpCode);
    	}
    	return false;
    	//return "99999".equals(otpCode) ? false : true;
    }
    
    // This method doesn't do anything, it's just included as an example
//    public static void setPassword(String username, String oldPassword, String newPassword) {
//        if (authenticate(username, oldPassword) == AuthNResult.SUCCESS)
//            String newSalt = BCrypt.gensalt();
//            String newHashedPassword = BCrypt.hashpw(newSalt, newPassword);
//            // Update the user salt and password
//        }
//    }
}
