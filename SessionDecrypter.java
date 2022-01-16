
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionDecrypter {
    private SecretKey key;
    public IvParameterSpec IV = null;
    public Cipher cipher = null;

    SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.key = new SessionKey(keybytes).getSecretKey();
        this.IV = new IvParameterSpec(ivbytes);
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipher.init(Cipher.DECRYPT_MODE, this.key, this.IV);
    }

    CipherInputStream openCipherInputStream(InputStream input)
    {
        return new CipherInputStream(input, this.cipher);
    }
}
