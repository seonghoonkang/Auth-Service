package com.bizflow.auth.saml;

import com.bizflow.auth.saml.config.WebSecurityConfigurer;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;
import org.springframework.web.servlet.DispatcherServlet;

import javax.servlet.DispatcherType;
import javax.servlet.FilterRegistration;
import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import java.util.EnumSet;

public class SecurityWebApplicationInitializer implements WebApplicationInitializer {
    @Override
    public void onStartup(ServletContext servletContext) {
        AnnotationConfigWebApplicationContext  context = new AnnotationConfigWebApplicationContext();
        context.register(WebSecurityConfigurer.class);
        servletContext.addListener(new ContextLoaderListener(context));

        ServletRegistration.Dynamic dispatcher = servletContext.addServlet("dispatcher", new DispatcherServlet(context));

        dispatcher.setLoadOnStartup(1);
        dispatcher.addMapping("/");
        FilterRegistration securityFilter = servletContext.addFilter("springSecurityFilterChain", DelegatingFilterProxy.class);
        securityFilter.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST, DispatcherType.FORWARD), true, "/*");
    }
}
