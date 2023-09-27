package app.login;

import app.user.*;
import app.util.*;
import spark.*;
import java.util.*;
import static app.Application.*;
import static app.util.RequestUtil.*;
import static app.util.TotpUtil.*;

public class OtpController {

    public static Route serveOtpPage = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();
        String loginRedirect = removeSessionAttrLoginRedirect(request);
        String currentUser = getSessionCurrentUser(request);
        System.out.println("OTPController.serveOtpPage currentUser:" + currentUser);
        System.out.println("OTPController.serveOtpPage loginRedirect:" + loginRedirect);

        model.put("loggedOut", removeSessionAttrLoggedOut(request));
        model.put("loginRedirect", loginRedirect);

        if (currentUser != null && !currentUser.isEmpty()) {
        	User user = userDao.getUserByUsername(currentUser);
        	if (user != null) {
        		String otpSecret = generateOtpSecret();
        		user.setSharedSecret(otpSecret);
        		String qrCodeDataUri = createQrCodeDataUrl(user.getUsername(), otpSecret, "Spark.Library");
        		model.put("qrCode", qrCodeDataUri);
        	}
        }
        return ViewUtil.render(request, model, Path.Template.OTP);
    };

    public static Route handleOtpPost = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();
        boolean otpResult = UserController.validateOtp(getQueryUsername(request), getQueryOtpcode(request));
        if (otpResult) {
            model.put("authenticationSucceeded", true);
            String currentUser = getQueryUsername(request);
            String loginRedirect = getQueryLoginRedirect(request);
            System.out.println("OtpController.handleOtpPost currentUser: " + currentUser);
            System.out.println("OtpController.handleOtpPost loginRedirect: " + loginRedirect);
            request.session().attribute("currentUser", getQueryUsername(request));
            if (loginRedirect != null) {
                response.redirect(loginRedirect);
            }
            return ViewUtil.render(request, model, Path.Template.LOGIN);
        }
        else {
            model.put("authenticationFailed", true);
            // go back to the main login page
            request.session().attribute("currentUser", null);
            return ViewUtil.render(request, model, Path.Template.LOGIN);
        }
    };


    // The origin of the request (request.pathInfo()) is saved in the session so
    // the user can be redirected back after login
    public static void ensureUserIsLoggedIn(Request request, Response response) {
        if (request.session().attribute("currentUser") == null) {
            //request.session().attribute("loginRedirect", request.pathInfo());
            response.redirect(Path.Web.LOGIN);
        }
    };

}
