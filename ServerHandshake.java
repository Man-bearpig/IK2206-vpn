
/**
 * Server side of the handshake.
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidParameterSpecException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol.
     */

    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;
    public X509Certificate clientCertificate;
    HandshakeMessage clientHelloMessage;
    HandshakeMessage serverHelloMessage;

    /**
     * Run server handshake protocol on a handshake socket.
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */
    public ServerHandshake(Socket handshakeSocket,String cacert,String serverCert,String serverPrivateKeyFile) throws Exception {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();

        hello(handshakeSocket,cacert,serverCert);
        session(handshakeSocket,serverPrivateKeyFile);
    }

    public static X509Certificate readCertificate (String certificatePath) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFile = new FileInputStream (certificatePath);
        return (X509Certificate) certificateFac.generateCertificate(certificateFile);
    }


    public void hello (Socket socket, String caPath, String userPath) throws Exception {
        clientHelloMessage = new HandshakeMessage();
        clientHelloMessage.recv(socket);
        if (!clientHelloMessage.getParameter("MessageType").equals("ClientHello")) {
            throw new Exception();
            }
        String clientCertificateString = clientHelloMessage.getParameter("Certificate");
        CertificateFactory certificateFacCa = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFileCa = new FileInputStream (caPath);
        X509Certificate caCertificate =  (X509Certificate) certificateFacCa.generateCertificate(certificateFileCa);
        byte[] certificateByte = Base64.getDecoder().decode(clientCertificateString);
        CertificateFactory certificateFacCl = CertificateFactory.getInstance("X.509");
        InputStream inputStream = new ByteArrayInputStream(certificateByte);
        clientCertificate =  (X509Certificate) certificateFacCl.generateCertificate(inputStream);
        VerifyCertificate.judgecert(caCertificate, clientCertificate);

        serverHelloMessage = new HandshakeMessage();
        CertificateFactory certificateFacSe = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFileSe = new FileInputStream (userPath);
        X509Certificate serverCertificate =  (X509Certificate) certificateFacSe.generateCertificate(certificateFileSe);
        String serverCertificateString = Base64.getEncoder().encodeToString(serverCertificate.getEncoded());
        serverHelloMessage.putParameter("MessageType","ServerHello");
        serverHelloMessage.putParameter("Certificate",serverCertificateString);
        serverHelloMessage.send(socket);
        Logger.log("Hello finished");
    }

    public void session (Socket socket,String keyFile) throws Exception {
        HandshakeMessage forwardMessage = new HandshakeMessage();
        forwardMessage.recv(socket);
        if (!forwardMessage.getParameter("MessageType").equals("Forward")) {
            throw new Exception();
        }
        ServerHandshake.targetHost = forwardMessage.getParameter("TargetHost");
        ServerHandshake.targetPort = Integer.parseInt(forwardMessage.getParameter("TargetPort"));
        Logger.log("forwardReceived finished");



        PublicKey clientPublicKey = clientCertificate.getPublicKey();
        SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
        sessionKey = sessionEncrypter.getKeyBytes();
        sessionIV = sessionEncrypter.getIVBytes();
        byte[] encryptedKey =  HandshakeCrypto.encrypt(sessionEncrypter.getKeyBytes(), clientPublicKey);
        byte[] encryptedIV = HandshakeCrypto.encrypt(sessionEncrypter.getIVBytes(), clientPublicKey);

        HandshakeMessage serverSession = new HandshakeMessage();
        serverSession.putParameter("MessageType", "Session");
        serverSession.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedKey));
        serverSession.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIV));
        serverSession.putParameter("SessionHost", sessionHost);
        serverSession.putParameter("SessionPort", Integer.toString(sessionPort));
        serverSession.send(socket);
        Logger.log("Session message sent");

        HandshakeMessage clientFinished = new HandshakeMessage();
        clientFinished.recv(socket);
        if (!clientFinished.getParameter("MessageType").equals("ClientFinished")) {
            throw new Exception("Didn't receive ClientFinished");
        }
        byte[] signature = HandshakeCrypto.decrypt(Base64.getDecoder().decode(clientFinished.getParameter("Signature")),clientPublicKey);
        MessageDigest clientDigest = MessageDigest.getInstance("SHA-256") ;
        clientHelloMessage.updateDigest(clientDigest);
        forwardMessage.updateDigest(clientDigest);
        if (!Arrays.equals(clientDigest.digest(), signature)) {
            throw new Exception("clientDigest verification failed");
        }
        byte[] timeStamp = HandshakeCrypto.decrypt(Base64.getDecoder().decode(clientFinished.getParameter("TimeStamp")),clientPublicKey);
        String dateReceived = new String(timeStamp,"GBK");
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String dateNow = df.format(new Date());
        for(int i = 0;i<16;i++) {
            if (dateNow.charAt(i) != dateReceived.charAt(i)) throw new Exception("clientTime verification failed");
        }
        Logger.log("clientFinished verified");

        PrivateKey serverKey = HandshakeCrypto.getPrivateKeyFromKeyFile(keyFile);
        HandshakeMessage serverFinished = new HandshakeMessage();
        serverFinished.putParameter("MessageType", "ServerFinished");
        serverFinished.putParameter("TargetHost", targetHost);
        serverFinished.putParameter("TargetPort", Integer.toString(targetPort));
        MessageDigest serverDigest = MessageDigest.getInstance("SHA-256") ;
        serverHelloMessage.updateDigest(serverDigest);
        serverSession.updateDigest(serverDigest);
        serverFinished.putParameter("Signature", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(serverDigest.digest(),serverKey)));
        serverFinished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(df.format(new Date()).getBytes(),serverKey)));//StandardCharsets.UTF_8
        serverFinished.send(socket);
        Logger.log("serverFinished sent");

    }

}