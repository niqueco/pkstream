package ar.com.lichtmaier.pkstream;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Decrypting output stream taking a private key.
 * 
 * @author Nicolás Lichtmaier <nico.lichtmaier@gmail.com>
 *
 */
public class PKDecryptInputStream extends InputStream
{
	final private CipherInputStream cis;

	public PKDecryptInputStream(InputStream in, PrivateKey pk) throws IOException
	{
		try
		{
			Cipher pkCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
			Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			DataInputStream dis = new DataInputStream(in);
			if(dis.readInt() != PKEncryptOutputStream.VERSION)
				throw new RuntimeException("Wrong version");
			
			short len = dis.readShort();
			byte[] encryptedKeyBytes = new byte[len];
			dis.read(encryptedKeyBytes);
			
			pkCipher.init(Cipher.DECRYPT_MODE, pk);
			SecretKey aesKey;
			aesKey = new SecretKeySpec(pkCipher.doFinal(encryptedKeyBytes), "AES");

			aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
			
			cis = new CipherInputStream(in, aesCipher);
		} catch(GeneralSecurityException e)
		{
			throw new RuntimeException(e);
		}
	}

	@Override
	public int read() throws IOException
	{
		return cis.read();
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException
	{
		return cis.read(b, off, len);
	}
	
	@Override
	public int available() throws IOException
	{
		return cis.available();
	}
	
	@Override
	public void close() throws IOException
	{
		cis.close();
	}
}
