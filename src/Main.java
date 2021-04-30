import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.apache.commons.ssl.PKCS8Key;


public class Main {

    final static String urlAutentica = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc";
    final static String urlAutenticaAction = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica";

    final static String urlSolicitud = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/SolicitaDescargaService.svc";
    final static String urlSolicitudAction = "http://DescargaMasivaTerceros.sat.gob.mx/ISolicitaDescargaService/SolicitaDescarga";

    final static String urlVerificarSolicitud = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/VerificaSolicitudDescargaService.svc";
    final static String urlVerificarSolicitudAction = "http://DescargaMasivaTerceros.sat.gob.mx/IVerificaSolicitudDescargaService/VerificaSolicitudDescarga";

    final static String urlDescargarSolicitud = "https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc";
    final static String urlDescargarSolicitudAction = "http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar";

    final static char[] pwdPFX = "omgapk29".toCharArray(); // PFX's password
    final static String rfc = "VEPO8408296N4";
    final static String dateStart = "2020-12-01"; // yyyy-MM-dd
    final static String dateEnd = "2020-12-31"; // yyyy-MM-dd

    static X509Certificate certificate = null;
    static PrivateKey privateKey = null;

    public static void main(String[] args) throws Exception {
        String filePath = "/home/ovelasco/Dropbox/Personal/FIEL_VEPO8408296N4_20180124195042/test/vepo840829.pfx";
        File filePFX = new File(filePath);

        // Get certificate and private key from PFX file
        certificate = getCertificate(filePFX);
        privateKey = getPrivateKey(filePFX);
//        certificate = getCert("/home/ovelasco/Dropbox/Personal/FIEL_VEPO8408296N4_20180124195042/test/vepo8408296n4.cer");
//        privateKey = getKey("/home/ovelasco/Dropbox/Personal/FIEL_VEPO8408296N4_20180124195042/test/Claveprivada_FIEL_VEPO8408296N4_20180124_195042.key");

        // Get Token
        String token = "WRAP access_token=\"" + decodeValue(getToken()) + "\"";
        System.out.println("token: " + token);
        // Get idRequest with token obtained
//        String idRequest = getRequest(token);
        String idRequest = "9a783993-3fcd-4c5f-8ff3-350c382d46ee";
        System.out.println("idRequest: " + idRequest);

        // Get idPackages with token and idRequest obtained
        String idPackages = getVerifyRequest(token, idRequest);
        System.out.println("idPackages: " + idPackages);

        // Get package in Base64 with token and idPackages obtained
        String packageString = getDownload(token, idPackages);
        System.out.println("packageString: " + packageString);

        
        createZipFile(packageString);
        System.out.println(packageString);
    }

	private static void createZipFile(String packageString) throws IOException {
		byte[] bytes = Base64.getDecoder().decode(packageString);
		
		FileOutputStream fos = new FileOutputStream("/home/ovelasco/Descargas/vepodic.zip");
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		bos.write(bytes);
		bos.flush();
	}

	private static X509Certificate getCert(String file) throws CertificateException, FileNotFoundException {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream(file));
		certificate.checkValidity();
		return certificate;
	}


    private static PrivateKey getKey(String file) throws FileNotFoundException, GeneralSecurityException, IOException {
		PKCS8Key pkcs8Key = new PKCS8Key(new FileInputStream(file), pwdPFX);
		PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec(pkcs8Key.getDecryptedBytes());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey key = kf.generatePrivate(keysp);
		return key;
	}
	
	/**
     * Get a certificate through a pfx file
     *
     * @param file
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static X509Certificate getCertificate(File file)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(file), pwdPFX);
        String alias = ks.aliases().nextElement();

        return (X509Certificate) ks.getCertificate(alias);
    }
    
    /**
     * Get a private key through a pfx file
     *
     * @param file
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public static PrivateKey getPrivateKey(File file)
            throws KeyStoreException,
            IOException,
            CertificateException,
            NoSuchAlgorithmException,
            UnrecoverableKeyException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(file), pwdPFX);
        String alias = ks.aliases().nextElement();

        return (PrivateKey) ks.getKey(alias, pwdPFX);
    }

    /**
     * Get XML response through SAT's web service and extract token from it
     *
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws CertificateEncodingException
     */
    public static String getToken()
            throws IOException,
            NoSuchAlgorithmException,
            SignatureException,
            InvalidKeyException,
            CertificateEncodingException {
        Authentication authentication = new Authentication(urlAutentica, urlAutenticaAction);
        authentication.generate(certificate, privateKey);

        return authentication.send(null);
    }

    /**
     * Get XML response through SAT's web service and extract idRequest from it
     *
     * @param token
     * @return
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static String getRequest(String token)
            throws CertificateEncodingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            IOException {
        Request request = new Request(urlSolicitud, urlSolicitudAction);
        request.setTypeRequest("CFDI");

        // Send empty in rfcEmisor if you want to get receiver packages
        // or send empty in rfcReceptor if you want to get sender packages
//        request.generate(certificate, privateKey, rfc, "", rfc, dateStart, dateEnd);
        request.generate(certificate, privateKey, "", rfc, rfc, dateStart, dateEnd);

        return request.send(token);
    }

    /**
     * Get XML response through SAT's web service and extract idPackages from it
     *
     * @param token
     * @param idRequest
     * @return
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static String getVerifyRequest(String token, String idRequest)
            throws CertificateEncodingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException,
            IOException {
        VerifyRequest verifyRequest = new VerifyRequest(urlVerificarSolicitud, urlVerificarSolicitudAction);
        verifyRequest.generate(certificate, privateKey, idRequest, rfc);

        return verifyRequest.send(token);
    }

    /**
     * Get XML response through SAT's web service and extract Base64's package from it
     *
     * @param token
     * @param idPackage
     * @return
     * @throws IOException
     * @throws CertificateEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String getDownload(String token, String idPackage)
            throws IOException,
            CertificateEncodingException,
            NoSuchAlgorithmException,
            InvalidKeyException,
            SignatureException {
        Download download = new Download(urlDescargarSolicitud, urlDescargarSolicitudAction);
        download.generate(certificate, privateKey, rfc, idPackage);

        return download.send(token);
    }

    /**
     * Decodes a URL encoded string using `UTF-8`
     *
     * @param value
     * @return
     */
    public static String decodeValue(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException ex) {
            throw new RuntimeException(ex.getCause());
        }
    }
}
