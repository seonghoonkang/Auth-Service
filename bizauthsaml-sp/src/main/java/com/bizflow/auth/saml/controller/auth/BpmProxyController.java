package com.bizflow.auth.saml.controller.auth;

import com.bizflow.auth.saml.api.model.ResponseVO;
import com.bizflow.auth.saml.controller.MapperRestAPIController;
import com.bizflow.auth.saml.error.SamlSpException;
import com.bizflow.auth.saml.log.PerformanceLog;
import com.bizflow.auth.saml.model.AuthMasterVO;
import com.bizflow.auth.saml.service.BpmDataProvideService;
import com.bizflow.auth.saml.service.ProductRequestManagerService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping(path = "/api")
public class BpmProxyController extends MapperRestAPIController {
    private final BpmDataProvideService bpmDataProvideService;

    public BpmProxyController(ProductRequestManagerService productRequestManagerService, BpmDataProvideService bpmDataProvideService) {
        super(productRequestManagerService);
        this.bpmDataProvideService = bpmDataProvideService;
    }

    @PerformanceLog
    @GetMapping(value = {"/bpm/services/org/department/{tokenHashCode}"})
    public ResponseVO<Map<String, Object>> getSearchDepartment(HttpServletRequest request,
                                                               @PathVariable String tokenHashCode,
                                                               @RequestParam(name = "trust-key") String trustKey,
                                                               @RequestParam(name = "dept-name") String queryString) throws SamlSpException {
        List<Map<String, Object>> result;
        validToken(tokenHashCode, trustKey);
        AuthMasterVO authMaster = (AuthMasterVO) request.getSession().getAttribute("authMaster");
        result = bpmDataProvideService.searchDepartment(authMaster.getBpmSessionInfo(), queryString);
        return makeResponseListData(HttpStatus.OK, result);
    }

    @PerformanceLog
    @GetMapping(value = {"/bpm/services/org/group/{tokenHashCode}"})
    public ResponseVO<Map<String, Object>> getSearchGroup(HttpServletRequest request,
                                                          @PathVariable String tokenHashCode,
                                                          @RequestParam(name = "trust-key") String trustKey,
                                                          @RequestParam(name = "group-name") String queryString) throws SamlSpException {
        List<Map<String, Object>> result;
        validToken(tokenHashCode, trustKey);
        AuthMasterVO authMaster = (AuthMasterVO) request.getSession().getAttribute("authMaster");
        result = bpmDataProvideService.searchGroup(authMaster.getBpmSessionInfo(), queryString);
        return makeResponseListData(HttpStatus.OK, result);
    }

    @PerformanceLog
    @GetMapping(value = {"/bpm/services/org/user/{tokenHashCode}"})
    public ResponseVO<Map<String, Object>> getSearchUser(HttpServletRequest request,
                                                         @PathVariable String tokenHashCode,
                                                         @RequestParam(name = "trust-key") String trustKey,
                                                         @RequestParam(name = "user-name") String queryString) throws SamlSpException {
        List<Map<String, Object>> result;
        validToken(tokenHashCode, trustKey);
        AuthMasterVO authMaster = (AuthMasterVO) request.getSession().getAttribute("authMaster");
        result = bpmDataProvideService.searchUser(authMaster.getBpmSessionInfo(), queryString);
        return makeResponseListData(HttpStatus.OK, result);
    }

}
