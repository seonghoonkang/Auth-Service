package com.bizflow.auth.spclient.utils;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;

public enum OTPProvider {
    TIME_SYNC {
        private String providerUrl;
        private long offsetMilliSecond = -1;

        @Override
        public String generateOtp() throws Exception {
            if(offsetMilliSecond == -1){
                offsetMilliSecond = culOffsetMilliSecond();
            }
            return Long.toString(Instant.now().getEpochSecond() * 1000000 + offsetMilliSecond);
        }

        private long culOffsetMilliSecond() throws IOException {
            StringBuilder textBuilder = new StringBuilder();
            if(providerUrl == null){
                throw new IllegalArgumentException("You must set the sp-module Base URL.");
            }
            HttpGet get = new HttpGet(providerUrl + "/epoch-second");
            HttpClient client = HttpClientBuilder.create().build();
            long start = System.currentTimeMillis() / 1000;
            HttpResponse response = client.execute(get);
            InputStream is = response.getEntity().getContent();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    textBuilder.append(line);
                }
            }
            long end = System.currentTimeMillis() / 1000;
            long delaySecond = (end - start);
            long epochSecond = Long.parseLong(textBuilder.toString().trim()) - delaySecond * 1000000;
            return (epochSecond - Instant.now().getEpochSecond() * 1000000);
        }

        @Override
        public void setOpenApiEndpoint(String spModuleBaseURL)  {
            this.providerUrl = spModuleBaseURL;
        }
    };
    public abstract String generateOtp() throws Exception;
    public abstract void setOpenApiEndpoint(String spModuleBaseURL);

}
