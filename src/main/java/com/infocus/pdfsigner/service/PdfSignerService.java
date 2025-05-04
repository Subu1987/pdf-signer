package com.infocus.pdfsigner.service;

import com.infocus.pdfsigner.util.Pkcs11SignerUtil;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.regex.Pattern;

@Service
public class PdfSignerService {

    private final Pkcs11SignerUtil signerUtil;

    public PdfSignerService(Pkcs11SignerUtil signerUtil) {
        this.signerUtil = signerUtil;
    }

    public String signPdf(String base64Pdf) {
        try {
            String cleanedBase64 = cleanBase64String(base64Pdf);
            if (!isValidBase64(cleanedBase64)) {
                throw new IllegalArgumentException("Invalid base64 input: contains illegal characters or bad format");
            }

            byte[] pdfBytes = Base64.getDecoder().decode(cleanedBase64);
            byte[] signedPdfBytes = signerUtil.signPdf(pdfBytes);
            return Base64.getEncoder().encodeToString(signedPdfBytes);

        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Base64 validation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign PDF: " + e.getMessage(), e);
        }
    }

    private String cleanBase64String(String base64String) {
        // Remove newlines, carriage returns, tabs, and spaces
        return base64String.replaceAll("[\\n\\r\\t ]", "");
    }

    private boolean isValidBase64(String base64) {
        // A basic check: only valid Base64 characters and length multiple of 4
        Pattern base64Pattern = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");
        return base64 != null &&
               base64.length() % 4 == 0 &&
               base64Pattern.matcher(base64).matches();
    }
}
