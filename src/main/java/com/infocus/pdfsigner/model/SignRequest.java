package com.infocus.pdfsigner.model;

import javax.validation.constraints.NotBlank;

public class SignRequest {

    @NotBlank(message = "PDF base64 is required")
    private String base64Pdf;

    public String getBase64Pdf() {
        return base64Pdf;
    }

    public void setBase64Pdf(String base64Pdf) {
        this.base64Pdf = base64Pdf;
    }
}
