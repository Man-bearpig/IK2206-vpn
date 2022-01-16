
import java.security.*;

public class HandshakeTester {
    static String PRIVATEKEYFILE = "C:\\Users\\Manbearpig\\IdeaProjects\\2560_project\\src\\com\\company\\client-private.der";
    static String CERTFILE = "C:\\Users\\Manbearpig\\IdeaProjects\\2560_project\\src\\com\\company\\client.pem";
    static String PLAINTEXT = "Time flies like an arrow. Fruit flies like a banana.";
    static String ENCODING = "UTF-8"; /* For converting between strings and byte arrays */

    static public void main(String[] args) throws Exception {

        /* Extract key pair */
        PrivateKey privatekey = HandshakeCrypto.getPrivateKeyFromKeyFile(PRIVATEKEYFILE);
        PublicKey publickey = HandshakeCrypto.getPublicKeyFromCertFile(CERTFILE);


        /* Encode string as bytes */
        byte[] plaininputbytes = PLAINTEXT.getBytes(ENCODING);
        /* Encrypt it */
        byte[] cipher = HandshakeCrypto.encrypt(plaininputbytes, publickey);
        /* Then decrypt back */
        byte[] plainoutputbytes = HandshakeCrypto.decrypt(cipher, privatekey);
        /* Decode bytes into string */
        String plainoutput = new String(plainoutputbytes, ENCODING);
        if (plainoutput.equals(PLAINTEXT)) {
            System.out.println("Pass. Input and output strings are the same: \"" + PLAINTEXT + "\"");
        }
        else {
            System.out.println("Fail. Expected \"" + PLAINTEXT + "\", but got \"" + plainoutput + "\'");
        }
    }
}
