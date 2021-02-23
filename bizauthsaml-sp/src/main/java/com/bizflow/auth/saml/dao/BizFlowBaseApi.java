package com.bizflow.auth.saml.dao;

import com.bizflow.auth.saml.model.BPMSessionInfoVO;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonGenerator;
import com.hs.bf.web.beans.*;
import com.hs.bf.web.xmlrs.XMLResultSet;
import com.hs.bf.web.xmlrs.XMLResultSetImpl;
import com.hs.frmwk.web.encoding.Cipher01;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;

/**
 * BizFlow Base API
 *
 * @author JB.Kang
 * @version 3.0
 */

//-- TODO: https://medium.com/@yongkyu.jang/spring-%EC%BB%A4%EC%8A%A4%ED%85%80-%EC%96%B4%EB%85%B8%ED%85%8C%EC%9D%B4%EC%85%98-custom-annotation-%EC%9D%84-%ED%99%9C%EC%9A%A9%ED%95%9C-aop%EC%97%90%EC%84%9C%EC%9D%98-%EB%A1%9C%EA%B9%85%EC%B2%98%EB%A6%AC-6f41ceaba091
public class BizFlowBaseApi {
    private static final Logger log = LoggerFactory.getLogger(BizFlowBaseApi.class);
    private final static HWSession hwSession = new HWSessionFactory().newInstance("com.hs.bf.web.beans.HWSessionTCPImpl");

    public static HWSession getHWSession() {
        return hwSession;
    }

    /**
     * Creates HWSessionInfo
     *
     * @param sessionInfoXml a user's BizFlow session info xml
     * @return HWSessionInfo object
     * @since 3.0
     */
    public static HWSessionInfo createHWSessionInfo(String sessionInfoXml) {
        HWSessionInfo hwSessionInfo = new HWSessionInfo();
        hwSessionInfo.setSessionInfo(sessionInfoXml);
        return hwSessionInfo;
    }

    /**
     * Logs in BizFlow
     *
     * @param serverIp   Server IP address
     * @param serverPort server port Number
     * @param loginId    a user's login ID
     * @param password   a user's password
     * @param forceLogin If this account was already logged in, this value specifies whether to log in forcibly or not.
     * @return session info xml
     */
    public static String login(String serverIp, int serverPort, String loginId, String password, boolean forceLogin) throws HWException {
        return hwSession.logIn(serverIp, serverPort, loginId, password, forceLogin);
    }

    public static String loginBySso(String serverIp, int serverPort, String clientIP, String loginId, File certFile) {
        String sessionInfoXml = null;
        try {
            HWString userFilePath = new HWString();
            String lowerLoginID = loginId.toLowerCase();
            String userInfo = lowerLoginID + ((char) 11) + decryptMaterPassword(certFile);
            sessionInfoXml = hwSession.loginBySSO(serverIp
                    , serverPort
                    , clientIP
                    , "BIZFLOWSSO"
                    , userInfo
                    , true
                    , userFilePath);
        } catch (HWException e) {
            e.printStackTrace();
        }

        return sessionInfoXml;
    }

    private static String decryptMaterPassword(File f) {
        String decryptMP = null;
        if (f.exists() && f.canRead()) {
            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(f))) {
                byte[] b = new byte[1024];
                bis.read(b);
                decryptMP = Cipher01.decrypt0(new String(b));
            } catch (Exception ee) {
                ee.printStackTrace();
            }
        } else {
            if (!f.exists()) {
                log.error("BIZFLOWSSO configuration error. Certificate file not found: {}", f.getPath());
            } else if (!f.canRead()) {
                log.error("BIZFLOWSSO configuration error. Certificate file has not read permission");
            }
        }
        return decryptMP;
    }

    public static String getUserGroupToJson(BPMSessionInfoVO sessionInfo) throws Exception {
        HWFilter hwFilter = new HWFilter();
        hwFilter.setName("HWUserGroup");
        hwFilter.addFilter("USERID", "E", sessionInfo.getUserId());
        try (BufferedInputStream is = new BufferedInputStream(hwSession.getGroups(sessionInfo.getSessionInfoXML(), hwFilter.toByteArray()))) {
            return  convertJson(is, "ID");
        }
    }

    public static String getUserInfoToJson(BPMSessionInfoVO sessionInfo) throws Exception {
        HWFilter hwFilter = new HWFilter();
        hwFilter.setName("HWUsers");
        hwFilter.addFilter("ID", "E", sessionInfo.getUserId());
        try (BufferedInputStream is = new BufferedInputStream(hwSession.getUsers(sessionInfo.getSessionInfoXML(), hwFilter.toByteArray()))) {
            return convertJson(is, "");
        }
    }

    public static String getLicenseGroupsToJson(BPMSessionInfoVO sessionInfo) throws Exception {
        HWFilter filter = new HWFilter();
        filter.setName("HWGroupParticipant");
        filter.addFilter("TYPE", "E", "L");
        filter.addFilter("MEMBERID", "E", sessionInfo.getUserId());

        try (BufferedInputStream is = new BufferedInputStream(hwSession.getParticipants(sessionInfo.getSessionInfoXML(), filter.toByteArray()))) {
            return convertJson(is, "USERGROUPID");
        }
    }
    public static String getSearchDepartmentToJson(BPMSessionInfoVO sessionInfo, String queryString) throws Exception {
        HWFilter filter = new HWFilter();
        filter.setName("HWDepartment");
        filter.addFilter("NAME", "LIKE", queryString);
        try (BufferedInputStream is = new BufferedInputStream(hwSession.getDepartments(sessionInfo.getSessionInfoXML(), filter.toByteArray()))) {
            return convertJson(is, "");
        }
    }

    public static String getSearchGroupToJson(BPMSessionInfoVO sessionInfo, String queryString) throws Exception {
        HWFilter filter = new HWFilter();
        filter.setName("HWUserGroup");
        filter.addFilter("NAME", "LIKE", StringUtils.defaultString("%" + queryString, null));
        try (BufferedInputStream is = new BufferedInputStream(hwSession.getGroups(sessionInfo.getSessionInfoXML(), filter.toByteArray()))) {
            return convertJson(is, "");
        }
    }

    public static String getSearchUserToJson(BPMSessionInfoVO sessionInfo, String queryString) throws Exception {
        HWFilter filter = new HWFilter();
        filter.setName("HWUsers");
        filter.addFilter("NAME", "LIKE", queryString);
        try (BufferedInputStream is = new BufferedInputStream(hwSession.getUsers(sessionInfo.getSessionInfoXML(), filter.toByteArray()))) {
            return convertJson(is, "");
        }
    }

    private static String convertJson(BufferedInputStream is, String lookupField) throws Exception {
        Writer writer = new StringWriter();
        XMLResultSet xrs = new XMLResultSetImpl();

        if (!lookupField.trim().equals("")) {
            xrs.setLookupField(lookupField);
        }
        xrs.parse(is);
        JsonFactory jsonFactory = new JsonFactory();
        JsonGenerator jsonGenerator = jsonFactory.createGenerator(writer);
        xrs.toJSON(jsonGenerator, null);
        jsonGenerator.close();
        return writer.toString();
    }

}
