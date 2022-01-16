
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

public class SessionEncrypter {
    private SecretKey key;
    private byte[] IVBytes = null;
    private Cipher cipher = null;

    SessionEncrypter(Integer keylength) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidParameterSpecException {
        this.key = new SessionKey(keylength).getSecretKey();
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipher.init(Cipher.ENCRYPT_MODE, this.key);
        this.IVBytes = this.cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
    }

    SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.key = new SessionKey(keybytes).getSecretKey();
        this.IVBytes = ivbytes;
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        this.cipher.init(Cipher.ENCRYPT_MODE, this.key, new IvParameterSpec(ivbytes));
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        return new CipherOutputStream(output,this.cipher);
    }

    public byte[] getKeyBytes()
    {
        return this.key.getEncoded();
    }

    public byte[] getIVBytes()
    {
        return this.IVBytes;
    }
}
