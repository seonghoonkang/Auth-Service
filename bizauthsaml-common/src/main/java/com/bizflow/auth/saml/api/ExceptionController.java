package com.bizflow.auth.saml.api;
@FunctionalInterface
public interface ExceptionController {
    /**
     * Returns the path of the error page.
     * @return the error path
     */
    String getErrorPath();

}
