package com.infocus.pdfsigner.controller;

import com.infocus.pdfsigner.model.SignRequest;
import com.infocus.pdfsigner.model.SignResponse;
import com.infocus.pdfsigner.service.PdfSignerService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/pdf")
public class PdfSignerController {

    @Autowired
    private PdfSignerService signerService;

    @PostMapping("/sign")
    public ResponseEntity<SignResponse> signPdf(@Validated @RequestBody SignRequest request) {
        String signedBase64 = signerService.signPdf(request.getBase64Pdf());
        return ResponseEntity.ok(new SignResponse(signedBase64));
    }
}
