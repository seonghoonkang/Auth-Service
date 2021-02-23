package com.bizflow.auth.saml.service;

import com.bizflow.auth.saml.controller.auth.BpmProxyErrorCode;
import com.bizflow.auth.saml.dao.BizFlowBaseApi;
import com.bizflow.auth.saml.error.SamlSpException;
import com.bizflow.auth.saml.model.BPMSessionInfoVO;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Service("BPMDataProvideService")
public class BpmDataProvideService {
    protected final Logger log = LoggerFactory.getLogger(getClass());

    public List<Map<String, Object>> searchDepartment(BPMSessionInfoVO bpmSessionInfo, String queryString) throws SamlSpException {
        try {
            return objectMapping(BizFlowBaseApi.getSearchDepartmentToJson(bpmSessionInfo, queryString));
        } catch (Exception e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_COMMON_ERROR, "BPM Error ::" + e.getMessage());
        }
    }

    public List<Map<String, Object>> searchGroup(BPMSessionInfoVO bpmSessionInfo, String queryString) throws SamlSpException {
        try {
            return objectMapping(BizFlowBaseApi.getSearchGroupToJson(bpmSessionInfo, queryString));
        } catch (Exception e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_COMMON_ERROR, "BPM Error ::" + e.getMessage());
        }
    }

    public List<Map<String, Object>> searchUser(BPMSessionInfoVO bpmSessionInfo, String queryString) throws SamlSpException {
        try {
            return objectMapping(BizFlowBaseApi.getSearchUserToJson(bpmSessionInfo, queryString));
        } catch (Exception e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_COMMON_ERROR, "BPM Error ::" + e.getMessage());
        }
    }

    private List<Map<String, Object>> objectMapping(String jsonDoc) throws SamlSpException {
        ObjectMapper mapper = new ObjectMapper();
        List<Map<String, Object>> objectList;
        try {
            objectList = mapper.readValue(jsonDoc, new TypeReference<List<Map<String, Object>>>(){});
        } catch (IOException e) {
            throw new SamlSpException(BpmProxyErrorCode.BPM_DATA_BINDING_ERROR, "Failure to Binding BPM input data.");
        }
        log.debug(String.valueOf(objectList));
        return objectList;
    }
}
