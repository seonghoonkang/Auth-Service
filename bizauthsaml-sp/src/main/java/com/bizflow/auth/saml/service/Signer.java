package com.bizflow.auth.saml.service;

import com.auth0.jwt.algorithms.Algorithm;
import com.bizflow.auth.saml.error.CommonErrorCode;
import com.bizflow.auth.saml.error.SamlSpException;

import java.util.stream.Stream;

public enum Signer {
    JWT;

    enum ALGORITHM {
        SHA256("SHA-256") {
            Algorithm searchSigner(String signer) {
                return Algorithm.HMAC256(signer);
            }
        },
        SHA348("SHA-384") {
            Algorithm searchSigner(String signer) {
                return Algorithm.HMAC384(signer);
            }
        },
        SHA512("SHA-512") {
            Algorithm searchSigner(String signer) {
                return Algorithm.HMAC512(signer);
            }
        };
        private final String hashAlgorithmName;
        ALGORITHM(String hashAlgorithm) {
            this.hashAlgorithmName = hashAlgorithm;
        }
        String getHashAlgorithmName() {return hashAlgorithmName;}
        abstract Algorithm searchSigner(String signer);
    }

    public Algorithm getHashSigner(String algorithmName, String target) throws SamlSpException {
        ALGORITHM elem = Stream.of(ALGORITHM.values())
                .filter(e -> e.getHashAlgorithmName().equals(algorithmName))
                .findFirst().orElse(null);
        if (elem == null) {
            throw new SamlSpException(CommonErrorCode.SERVER_ERROR, "Unsupported Digest Algorithm. :: " + algorithmName);
        }
        return elem.searchSigner(target);
    }

}
