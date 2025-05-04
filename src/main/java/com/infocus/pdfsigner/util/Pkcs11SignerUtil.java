package com.infocus.pdfsigner.util;

import com.infocus.pdfsigner.config.TokenConfig;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;

@Component
public class Pkcs11SignerUtil {

    private final TokenConfig tokenConfig;

    public Pkcs11SignerUtil(TokenConfig tokenConfig) {
        this.tokenConfig = tokenConfig;
    }

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public byte[] signPdf(byte[] inputPdf) throws Exception {
        String pkcs11Config = "name=" + tokenConfig.getName() + "\n" +
                "library=" + tokenConfig.getLibrary();

        ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11Config.getBytes());
        Provider pkcs11Provider = new sun.security.pkcs11.SunPKCS11(confStream);
        Security.addProvider(pkcs11Provider);

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            keyStore.load(null, tokenConfig.getPin().toCharArray());

            final String[] selectedAlias = new String[1];
            final PrivateKey[] privateKey = new PrivateKey[1];
            final Certificate[][] chain = new Certificate[1][];

            System.out.println("Available aliases:");
            for (Enumeration<String> aliases = keyStore.aliases(); aliases.hasMoreElements();) {
                String alias = aliases.nextElement();
                System.out.println("Alias: " + alias);

                try {
                    PrivateKey key = (PrivateKey) keyStore.getKey(alias, tokenConfig.getPin().toCharArray());
                    Certificate[] certs = keyStore.getCertificateChain(alias);

                    if (key != null && certs != null && certs.length > 0) {
                        selectedAlias[0] = alias;
                        privateKey[0] = key;
                        chain[0] = certs;
                        break;
                    }
                } catch (Exception ex) {
                    System.out.println("Skipping alias due to error: " + alias + " → " + ex.getMessage());
                }
            }

            if (selectedAlias[0] == null || privateKey[0] == null || chain[0] == null) {
                throw new Exception("No valid private key with certificate chain found in token.");
            }

            // System.out.println("Selected alias: " + selectedAlias[0]);
            // System.out.println("Private Key: " + privateKey[0].getAlgorithm());
            // for (int i = 0; i < chain[0].length; i++) {
            //     System.out.println("Cert " + i + ": " + ((X509Certificate) chain[0][i]).getSubjectX500Principal());
            // }

            try (PDDocument document = PDDocument.load(new ByteArrayInputStream(inputPdf))) {
                PDSignature pdfSignature = new PDSignature();
                pdfSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
                pdfSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
                pdfSignature.setName(((X509Certificate) chain[0][0]).getSubjectX500Principal().getName());
                pdfSignature.setLocation("India");
                pdfSignature.setReason("Digital Approval");
                pdfSignature.setSignDate(Calendar.getInstance());

                SignatureInterface signatureInterface = new SignatureInterface() {
                    @Override
                    public byte[] sign(InputStream content) throws IOException {
                        try {
                            Signature signer = Signature.getInstance("SHA256withRSA");
                            signer.initSign(privateKey[0]);
                            byte[] buffer = new byte[8192];
                            int read;
                            while ((read = content.read(buffer)) > 0) {
                                signer.update(buffer, 0, read);
                            }
                            return signer.sign();
                        } catch (Exception e) {
                            throw new IOException("Error signing PDF", e);
                        }
                    }
                };

                document.addSignature(pdfSignature, signatureInterface);
                ByteArrayOutputStream signedOut = new ByteArrayOutputStream();
                document.saveIncremental(signedOut);
                return signedOut.toByteArray();
            }

        } finally {
            Security.removeProvider(pkcs11Provider.getName());
        }
    }

}
