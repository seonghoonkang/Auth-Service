package com.bizflow.auth.saml.error;

import com.bizflow.auth.saml.api.model.ResponseVO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@RestController
@RequestMapping("/error")
public class ErrorController extends AbstractErrorController {
    protected final Logger log = LoggerFactory.getLogger(getClass());

    public ErrorController(ErrorAttributes errorAttributes) {
        super(errorAttributes);
    }

    @Value("${spring.profiles}")
    private String serverMode;

    @Override
    public String getErrorPath() {
        return "/error";
    }

    @RequestMapping(produces = MediaType.TEXT_HTML_VALUE)
    public ModelAndView errorHtml(HttpServletRequest request, HttpServletResponse response, ModelMap modelMap) {
        HttpStatus status = getStatus(request);
        Map<String, Object> model = getErrorAttributes(request, serverMode.equalsIgnoreCase("local"));
        log.debug("===> Exception model : {}", model);
        if( (model.get("exception")).equals(IllegalAccessException.class.getCanonicalName()) ){
            status = HttpStatus.FORBIDDEN;
        }
        model.put("siteMessage", "You do not have permission to access.");
        response.setStatus(status.value());
        modelMap.addAttribute("errorModel", model);
        ModelAndView modelAndView = resolveErrorView(request, response, status, model);//move whitePage
        return (modelAndView != null) ? modelAndView : new ModelAndView("/errors/" + status.value(), model);
    }

    @RequestMapping
    public ResponseEntity<ResponseVO<Map>> error(HttpServletRequest aRequest) {
        Map<String, Object> result = getErrorAttributes(aRequest, false);

        HttpStatus statusCode = INTERNAL_SERVER_ERROR;
        Object status = result.get("status");
        if ( status instanceof Integer) {
            statusCode = HttpStatus.valueOf((Integer) status);
        }
        List<Map> elements = Collections.singletonList(result);
        ResponseVO<Map> response = new ResponseVO<>();
        response.getBody().setCount(elements.size());
        response.getBody().setElements(elements);
        response.getHeader().setStatus(statusCode.value());
        return new ResponseEntity<>(response, statusCode);
    }

}
