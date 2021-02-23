package com.bizflow.auth.spclient;

import com.bizflow.auth.spclient.SPClientHelper.TokenAssistant;
import com.bizflow.auth.spclient.SPClientHelper.TokenAssistantBuilder;

import java.net.URL;
import java.net.URLEncoder;
import java.util.Map;

public class Tester {

    public static void main(String[] args) throws Exception {
        String randomKey = "Ea47zexF8dh1Unu0";
        String secretKey = "345ecd210ec4d61e0dd96eb862c95e3b753f23ee5e395367974a271267be7388";
        String encAuthToken = "ZKpO+YHqverUh37m9HJnq1P9sMTjjh98iQwbYSW4SMv7gzjmjvSNxxVFSYRMKukWC/2jZ8eCSJ6N0ktfm12/y8TBcemtMe/S7iZvKBX+mEtaB5pwAqu7mMYjzeF7A5KithbggR0kl6/5zOwEwt55K6Ts8tZ+PKXPQCqeS9SwPLoe7plcQigOHEk2pOStVKzX5VQ1c88aWPscxWn6zY6R34GF4AfTgctTiL2J8i5Mo97mNLPYBWuoemg82sTOblt05uECbb+hI/k5e/YCbSd+DEDmEQcSujqDHcE/zQGHBj6hAWKcx+Gh9z5rWvs088NoAud8P06USXzFpSKilGdnUpSWRHHxJZ8+L4bHQyh0WJBAS3bwo+4hSdBTk1h/iWqplZH3YblCzhtf5zRepOj5ehYoygsAbXiGpHw5+3QmVxIETPCtm+wCD4jRhridz/1pBp2lwd+C9jFvVSKyk1AGaGgAdNakb84zBIRUmm0fb7VQNQBDmGs+EyymO5bNrfmahoDcEDE8Vyp6kI8/DkqmPrKH1DBoafXt8Mgw7IalbpIUdC+h0+Mzw3VX6EZ2UGRSZZREuCgT67XXyomb1/i8YIPDl8WwiHUNCCNZRkqjAadPPVuYE+veVoJDE6pTytYmdlqkBBvBd7Q6LRTI9KkPhPdnqhu5YntnIzrSHad2fD6iYIsL/L76dkWnN1qWGwQqRcUXYoG3DCaVAJ1CCx/HflxJkuZltIJ5T/f+ZtZ1L5SKt9gapibHtNvSnWxrjlcTSle/oTnzt7o6H8qPjkQqxzKCCss/eTMhrCZCsIDTz/3iavdIiKUWhQ26v+ZkSnFQP+iVxDOqHO5lU9Umx7B9BNTAYz6/n1a96AkCnhv/7vWJdGxPE2vAFXsLekQzJv5BrQRK41FiOOKtTWtseDJIYn5tNci5yTO11wU7mLpIMA9bONYmmSAdGL4N/sI1e7u0YyD+bkPsA+1Z3EgAR4IC3Rcaqf9j3Rm6jdM5ZdxqID9L7KVucyPt6W8tg0n7jqDSHxy8E0eBvHy+NXW9Wf9YfPZIcsY8RgGbykTbt2KF8oOp4e74j3tDvb1e1d6PfNZk18obPSyhRwIxZ99qrSuKq7xz/IKYPWwUK7XvfNLRKeCFCqzekD5KCHrsXMlwS5BRVBV7qyQkjaEX7U/MFRKG+q3UTsxlwFOX/WKS883T3tTifbg3lR8EVvYv3E08rp7FJi5wsNY+XYHU2VxMcI+ZghfE5C6YN8MYgf76fly7xzIskTm5dpQoC2mgvJ8tE1EKKj4ZivA4cJ6OqpBL/Y6fpTya7dnopVbFBrL3RK4KzOJHy+Vi2+hA9V6Gy6eapaPw05SHuHQXyyoiIP0pnvdSBJbONSdgy9YfbkS07RvvbLyGnEGzAJu0qVBFqwS2kqk62wSBL3ZY2TWkeqAZGbQcacRteBvAT2gv0ztOLdwNA713x8aZRygIX7rpP/u75FEQ2mDCdS3RhfRekdAzzSdqn5Nh4+f7gCO6S3ZktGO4UyXI4j9Jj9IKVZKBX4E1rDPtfE6RfdtzduRBXfY4/KPpzE5c6BaKXCBkoOlcn3Bhv9YtfpJSTu+DIO7d1kEUocSFgKHCt/wndI1NZ1+bkEZ3FmXquELanBYdyb8InXcUZSdbfcv4lGwMgCTHWm+luhkzFMJjGTVZmivDnUOr61RRdmCUO+iz40+VxjR046EaFiNM15JXbN4WN0apq5VM9Yni4GQZaNT9+1xtfPmfCmXS57JQ9CxXApf6ALiFkhqW7MUs/8ahqR3KemX7nJn2FKi73osXlbssNPcuCckgqv1vL5+wu6sMJRuoEiHupFPvsdEUIj0FseWD0ZHm68vWM3pTe27nqPLDvxQif1mwgbuEs995o2t/XDl6dSENPmTixyZFfZdwlLJrYrJWZjQoa2dlCiVglAX4+2QIMQZs4OUBdWN08vtPOmL4ouW0tMwSvAA=";
        String referer = "";
        URL baseUrl = new URL("http://localhost:9999/bizauthsaml-sp");
        TokenAssistant tokenAssistant = new TokenAssistantBuilder(randomKey, secretKey, encAuthToken)
                .setReferer(referer)
                .setSPModuleBaseUrl(baseUrl)
                .build();

        Map[] lic = tokenAssistant.getUserAuthList();
        Map user = tokenAssistant.getUserInfo();
        Map bpmSessionInfo = tokenAssistant.getBpmSessionInfo();
        for (Map elm : lic) {
            System.out.println(elm.toString());
        }
        System.out.println(user);
        System.out.println(bpmSessionInfo);
        System.out.println(URLEncoder.encode(tokenAssistant.getTrustKey(), "UTF-8"));
        System.out.println(tokenAssistant.getTokenHashCode());
        System.out.println(SPClientHelper.generateInstanceId());
    }
}