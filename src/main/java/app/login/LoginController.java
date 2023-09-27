package app.login;

import app.user.*;
import app.util.*;
import spark.*;
import java.util.*;
import static app.util.RequestUtil.*;

public class LoginController {

    public static Route serveLoginPage = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();
        String loginRedirect = removeSessionAttrLoginRedirect(request);
        System.out.println("LoginController.serveLoginPage loginRedirect:" + loginRedirect);

        model.put("loggedOut", removeSessionAttrLoggedOut(request));
        model.put("loginRedirect", loginRedirect);
        return ViewUtil.render(request, model, Path.Template.LOGIN);
    };

    
    public static Route handleLoginPost = (Request request, Response response) -> {
        Map<String, Object> model = new HashMap<>();
        AuthNResult authResult = UserController.authenticate(getQueryUsername(request), getQueryPassword(request), getQueryOtpcode(request));
        String loginRedirect = getQueryLoginRedirect(request);
        System.out.println("LoginController.handleLoginPost loginRedirect: " + loginRedirect);
        
        switch(authResult) {
        case FAILURE:
            model.put("authenticationFailed", true);
            return ViewUtil.render(request, model, Path.Template.LOGIN);
        case OTP_REG_REQUIRED:
        	request.session().attribute("currentUser", getQueryUsername(request));
        	request.session().attribute("loginRedirect", getQueryLoginRedirect(request));
            response.redirect(Path.Web.OTP);
            return ViewUtil.render(request, model, Path.Template.OTP);
        default:
            model.put("authenticationSucceeded", true);
            request.session().attribute("currentUser", getQueryUsername(request));
            if (loginRedirect != null) {
                response.redirect(loginRedirect);
            }
            return ViewUtil.render(request, model, Path.Template.LOGIN);
        }
    };

    public static Route handleLogoutPost = (Request request, Response response) -> {
        request.session().removeAttribute("currentUser");
        request.session().attribute("loggedOut", true);
        response.redirect(Path.Web.LOGIN);
        return null;
    };

    // The origin of the request (request.pathInfo()) is saved in the session so
    // the user can be redirected back after login
    public static void ensureUserIsLoggedIn(Request request, Response response) {
    	String currentUser = request.session().attribute("currentUser");
    	System.out.println("LoginController.ensureUserIsLoggedIn currentUser: " + currentUser);
//        if (request.session().attribute("currentUser") == null) {
          if (currentUser == null) {
            request.session().attribute("loginRedirect", request.pathInfo());
            response.redirect(Path.Web.LOGIN);
        }
    };

}
