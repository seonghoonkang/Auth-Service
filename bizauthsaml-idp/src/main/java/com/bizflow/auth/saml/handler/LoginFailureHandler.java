package com.bizflow.auth.saml.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;

public class LoginFailureHandler implements AuthenticationFailureHandler {
    protected final Log logger = LogFactory.getLog(getClass());

    private String defaultFailureUrl;
    private boolean forwardToDestination = false;
    private boolean allowSessionCreation = true;
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public LoginFailureHandler (String defaultFailureUrl){
        this.defaultFailureUrl = defaultFailureUrl;
    }
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationException exception)
            throws IOException, ServletException {

        if (defaultFailureUrl == null) {
            logger.debug("No failure URL set, sending 401 Unauthorized error");

            response.sendError(HttpStatus.UNAUTHORIZED.value(),
                    HttpStatus.UNAUTHORIZED.getReasonPhrase());
        }
        else {
            saveException(request, exception);
            request.setAttribute("msg", exception.getMessage());
            if (forwardToDestination) {
                logger.debug("Forwarding to " + defaultFailureUrl);

                request.getRequestDispatcher(defaultFailureUrl)
                        .forward(request, response);
            }
            else {
                logger.debug("Redirecting to " + defaultFailureUrl+ "&msg="+exception.getMessage());
                redirectStrategy.sendRedirect(request, response, defaultFailureUrl + "&msg="+ URLEncoder.encode(exception.getMessage(), "UTF-8"));

            }
        }
    }
    protected final void saveException(HttpServletRequest request,
                                       AuthenticationException exception) {
        if (forwardToDestination) {
            request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
        }
        else {
            HttpSession session = request.getSession(false);

            if (session != null || allowSessionCreation) {
                request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION,
                        exception);
            }
        }
    }
}
