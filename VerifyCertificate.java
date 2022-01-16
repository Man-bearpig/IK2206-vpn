
import java.io.*;
import java.security.*;
import java.security.cert.*;


public class VerifyCertificate {

    public static void main(String[] args) throws CertificateException, FileNotFoundException {

        CertificateFactory certificateFac1 = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFile1 = new FileInputStream (args[0]);
        X509Certificate CA =  (X509Certificate) certificateFac1.generateCertificate(certificateFile1);
        CertificateFactory certificateFac2 = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFile2 = new FileInputStream (args[1]);
        X509Certificate user =  (X509Certificate) certificateFac2.generateCertificate(certificateFile2);
        judgecert(CA,user);
    }

    public static void judgecert(X509Certificate CA, X509Certificate user) {
        boolean flag = false;

        System.out.println(CA.getSubjectX500Principal());
        System.out.println(user.getSubjectX500Principal());
        try {
            CA.verify(CA.getPublicKey());
            flag = true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            System.out.println("Fail.\nCA is not valid.");
        } catch (CertificateException e1) {
            System.out.println("Fail.\nCA CertificateException");
        } catch (InvalidKeyException e2) {
            System.out.println("Fail.\nCA InvalidKey");
        }catch (NoSuchAlgorithmException e3) {
            System.out.println("Fail.\nCA NoSuchAlgorithm");
        }catch (NoSuchProviderException e4) {
            System.out.println("Fail.\nCA NoSuchProvider");
        }catch (SignatureException e5) {
            System.out.println("Fail.\nCA Wrong Signature");
        }

        try {
            user.verify(CA.getPublicKey());
            if (flag) {
                System.out.println("Pass");
            }
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            System.out.println("Fail.\nuser is not valid.");
        } catch (CertificateException e1) {
            System.out.println("Fail.\nuser CertificateException");
        } catch (InvalidKeyException e2) {
            System.out.println("Fail.\nuser InvalidKey");
        }catch (NoSuchAlgorithmException e3) {
            System.out.println("Fail.\nuser NoSuchAlgorithm");
        }catch (NoSuchProviderException e4) {
            System.out.println("Fail.\nuser NoSuchProvider");
        }catch (SignatureException e5) {
            System.out.println("Fail.\nuser Wrong Signature");
        }
    }

}