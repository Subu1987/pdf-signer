package com.infocus.pdfsigner.util;

import com.infocus.pdfsigner.config.TokenConfig;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
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

        // Load provider
        ByteArrayInputStream confStream = new ByteArrayInputStream(pkcs11Config.getBytes());
        Provider pkcs11Provider = new sun.security.pkcs11.SunPKCS11(confStream);
        Security.addProvider(pkcs11Provider);

        try {
            // Load keystore
            KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
            keyStore.load(null, tokenConfig.getPin().toCharArray());

            String alias = getPrivateKeyAlias(keyStore);
            if (alias == null) {
                throw new Exception("No private key alias found on the token.");
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            Certificate[] chain = keyStore.getCertificateChain(alias);

            if (privateKey == null || chain == null || chain.length == 0) {
                throw new Exception("Failed to retrieve private key or certificate chain.");
            }

            return signPdfWithIText(inputPdf, privateKey, chain);
        } finally {
            Security.removeProvider(pkcs11Provider.getName());
        }
    }

    private String getPrivateKeyAlias(KeyStore keyStore) throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (keyStore.isKeyEntry(alias)) {
                return alias;
            }
        }
        return null;
    }

    private byte[] signPdfWithIText(byte[] inputPdf, PrivateKey privateKey, Certificate[] chain)
            throws IOException, DocumentException, GeneralSecurityException {

        PdfReader reader = new PdfReader(new ByteArrayInputStream(inputPdf));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PdfStamper stamper = PdfStamper.createSignature(reader, outputStream, '\0');

        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason("Document Signing");
        appearance.setLocation("India");
        appearance.setVisibleSignature(new Rectangle(420f, 40f, 580f, 130f), 1, "Authorized Signatory");
        appearance.setLayer2Font(new com.itextpdf.text.Font(com.itextpdf.text.Font.FontFamily.HELVETICA, 7));

        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256, "SunPKCS11-Token");

        MakeSignature.signDetached(
                appearance,
                digest,
                signature,
                chain,
                null,
                null,
                null,
                0,
                MakeSignature.CryptoStandard.CMS);

        return outputStream.toByteArray();
    }
}
// This code is a utility class for signing PDF documents using a PKCS#11 token.
// It uses the iText library for PDF manipulation and Bouncy Castle for
// cryptographic operations. The class is annotated with @Component, making it a
// Spring-managed bean. The signPdf method takes a byte array representing the
// input PDF, retrieves the private key and certificate chain from the PKCS#11
// token, and signs the PDF. The signed PDF is returned as a byte array.
// The class also includes methods for initializing the Bouncy Castle provider,
// loading the PKCS#11 keystore, and signing the PDF using iText. The use of
// annotations like @PostConstruct indicates that the init method will be called
// after the bean's properties have been set, ensuring that the Bouncy Castle
// provider is added to the security framework before any signing operations are
// performed.