package com.infocus.pdfsigner.model;

public class SignResponse {
    private String signedBase64Pdf;

    public SignResponse(String signedBase64Pdf) {
        this.signedBase64Pdf = signedBase64Pdf;
    }

    public String getSignedBase64Pdf() {
        return signedBase64Pdf;
    }
}
