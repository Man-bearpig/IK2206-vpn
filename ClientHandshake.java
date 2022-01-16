
/**
 * Client side of the handshake.
 */

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol.
     */

    /* Session host/port  */
    public String sessionHost = "localhost";
    public int sessionPort = 12345;

    /* Security parameters key/iv should also go here. Fill in! */
    public byte[] sessionKey;
    public byte[] sessionIV;
    X509Certificate serverCertificate;
    HandshakeMessage clientHello;
    HandshakeMessage serverHello;

    /**
     * Run client handshake protocol on a handshake socket.
     * Here, we do nothing, for now.
     */
    public ClientHandshake(Socket handshakeSocket,String targetHost,String targetport,String cacert,String usercert,String clientPrivateKey) throws Exception {
        hello(handshakeSocket,cacert,usercert);
        session(handshakeSocket, targetHost, targetport,clientPrivateKey,usercert);
    }

    public void hello (Socket socket, String caPath,String certificatePath) throws Exception {
        clientHello = new HandshakeMessage();
        clientHello.putParameter("MessageType", "ClientHello");
        CertificateFactory certificateFac = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFile = new FileInputStream (certificatePath);
        X509Certificate userc = (X509Certificate) certificateFac.generateCertificate(certificateFile);
        clientHello.putParameter("Certificate", Base64.getEncoder().encodeToString(userc.getEncoded()));
        clientHello.send(socket);

        serverHello = new HandshakeMessage();
        serverHello.recv(socket);
        if (!serverHello.getParameter("MessageType").equals("ServerHello")) {
            throw new Exception("client handshake--hello failed");
        }
        CertificateFactory certificateFacCa = CertificateFactory.getInstance("X.509");
        FileInputStream certificateFileCa = new FileInputStream (caPath);
        String severCertificateString = serverHello.getParameter("Certificate");
        InputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(severCertificateString));
        serverCertificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
        VerifyCertificate.judgecert((X509Certificate) certificateFacCa.generateCertificate(certificateFileCa), serverCertificate);
    }

    public void session (Socket socket, String targetHost, String targetPort,String clientPrivateKey,String certificatePath) throws Exception {
        HandshakeMessage forwardMessage = new HandshakeMessage();
        forwardMessage.putParameter("MessageType", "Forward");
        forwardMessage.putParameter("TargetHost", targetHost);
        forwardMessage.putParameter("TargetPort", targetPort);
        forwardMessage.send(socket);

        HandshakeMessage sessionMessage = new HandshakeMessage();
        sessionMessage.recv(socket);
        if (!sessionMessage.getParameter("MessageType").equals("Session")) {
            throw new Exception("client handshake--session failed");
        }

        PrivateKey clientKey = HandshakeCrypto.getPrivateKeyFromKeyFile(clientPrivateKey);
        HandshakeMessage clientFinished = new HandshakeMessage();
        clientFinished.putParameter("MessageType", "ClientFinished");
        clientFinished.putParameter("TargetHost", targetHost);
        clientFinished.putParameter("TargetPort", targetPort);
        MessageDigest clientDigest = MessageDigest.getInstance("SHA-256") ;
        clientHello.updateDigest(clientDigest);
        forwardMessage.updateDigest(clientDigest);
        clientFinished.putParameter("Signature", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(clientDigest.digest(),clientKey)));
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        clientFinished.putParameter("TimeStamp", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(df.format(new Date()).getBytes(),clientKey)));//StandardCharsets.UTF_8
        clientFinished.send(socket);
        Logger.log("clientFinished sent");

        HandshakeMessage serverFinished = new HandshakeMessage();
        serverFinished.recv(socket);
        if (!serverFinished.getParameter("MessageType").equals("ServerFinished")) {
            throw new Exception("Didn't receive serverFinished");
        }
        PublicKey serverKey = serverCertificate.getPublicKey();
        byte[] signature = HandshakeCrypto.decrypt(Base64.getDecoder().decode(serverFinished.getParameter("Signature")),serverKey);
        MessageDigest serverDigest = MessageDigest.getInstance("SHA-256") ;
        serverHello.updateDigest(serverDigest);
        sessionMessage.updateDigest(serverDigest);
        if (!Arrays.equals(serverDigest.digest(), signature)) {
            throw new Exception("serverDigest verification failed");
        }
        byte[] timeStamp = HandshakeCrypto.decrypt(Base64.getDecoder().decode(serverFinished.getParameter("TimeStamp")),serverKey);
        String dateReceived = new String(timeStamp,"GBK");
        String dateNow = df.format(new Date());
        for(int i = 0;i<16;i++) {
            if (dateNow.charAt(i) != dateReceived.charAt(i)) throw new Exception("serverTime verification failed");
        }
        Logger.log("serverFinished verified");



        sessionPort = Integer.parseInt(sessionMessage.getParameter("SessionPort"));
        sessionHost = sessionMessage.getParameter("SessionHost");
        sessionKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionKey")), clientKey);
        sessionIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sessionMessage.getParameter("SessionIV")), clientKey);

        Logger.log("Client handshake finished");
    }

}
