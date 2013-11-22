package ar.com.lichtmaier.pkstream;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/** Encrypting output stream taking a public key.
 * 
 * @author Nicolás Lichtmaier <nico.lichtmaier@gmail.com>
 *
 */
public class PKEncryptOutputStream extends OutputStream
{
	public static int VERSION = 265433210;
	
	final private OutputStream out;
	
        private static final int AES_Key_Size = 256;
        private SecretKey aesKey;
	private Cipher aesCipher;

	public PKEncryptOutputStream(OutputStream out, PublicKey pk) throws IOException
	{
		this.out = out;
		
		try
		{
			Cipher pkCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(AES_Key_Size);
			aesKey = kgen.generateKey();
			
			DataOutputStream dos = new DataOutputStream(out);
			dos.writeInt(VERSION);
			
			pkCipher.init(Cipher.ENCRYPT_MODE, pk);
			byte[] encryptedKeyBytes = pkCipher.doFinal(aesKey.getEncoded());
			dos.writeShort(encryptedKeyBytes.length);
			dos.write(encryptedKeyBytes);
			
			aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
		} catch(GeneralSecurityException e)
		{
			throw new RuntimeException(e);
		}

	}

	private byte[] buf;
	
	@Override
	public void write(int oneByte) throws IOException
	{
		if(buf == null)
			buf = new byte[1];
		buf[0] = (byte)oneByte;
		write(buf, 0, 1);
	}

	@Override
	public void write(byte[] buffer, int offset, int count) throws IOException
	{
		final byte[] b = aesCipher.update(buffer, offset, count);
		if(b != null)
			out.write(b);
	}

	@Override
	public void close() throws IOException
	{
		try
		{
			out.write(aesCipher.doFinal());
		} catch(GeneralSecurityException e)
		{
			throw new RuntimeException(e);
		}
	}
}
