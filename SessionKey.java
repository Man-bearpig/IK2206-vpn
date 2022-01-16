
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

public class SessionKey {
    SecretKey key;
    byte[] key_b;

    SessionKey(Integer keylength)  {
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(keylength);
            this.key = gen.generateKey();
            this.key_b = this.key.getEncoded();
        }catch(NoSuchAlgorithmException e) {
            System.out.print("SessionKey generation failure \n");
            e.printStackTrace();
        }
    }

    SessionKey(byte[] keybytes){
        this.key = new SecretKeySpec(keybytes,"AES");
        this.key_b = this.key.getEncoded();
    }

    public SecretKey getSecretKey()
    {
        return this.key;
    }


    public byte[] getKeyBytes()
    {
        return this.key_b;
    }
}

