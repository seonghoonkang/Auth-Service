package com.bizflow.auth.saml.model;

import com.hs.bf.web.beans.HWSessionInfo;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;

@Getter
@ToString
public class BPMSessionInfoVO implements Serializable {
    public BPMSessionInfoVO(HWSessionInfo hwSessionInfo){
        this.key = hwSessionInfo.get("KEY");
        this.userId = hwSessionInfo.get("USERID");
        this.detpId = hwSessionInfo.get("DEPTID");
        this.ip = hwSessionInfo.get("IP");
        this.port = Integer.parseInt(hwSessionInfo.get("PORT"));
        this.userType = hwSessionInfo.get("USERTYPE");
        this.version = hwSessionInfo.get("VERSION");
        this.sessionInfoXML = hwSessionInfo.getSessionInfo();
    }
    String sessionInfoXML;
    String key;
    String userId;
    String ip;
    int port;
    String detpId;
    String userType;
    String version;
}
