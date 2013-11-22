package ar.com.lichtmaier.pkstream;

import java.io.*;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class PKStreamTest
{
	PublicKey pub;
	PrivateKey pvt;

	@Before
	public void setUp() throws Exception
	{
		// openssl genrsa -out pvt.pem 2048
		// openssl rsa -in pvt.pem -out pub -outform der -pubout

		KeySpec ks = new X509EncodedKeySpec(readResource("pub"));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		pub = kf.generatePublic(ks);

		// openssl pkcs8 -in pvt.pem -inform pem -outform pem -nocrypt -topk8 -outform der -out pvt
		
		ks = new PKCS8EncodedKeySpec(readResource("pvt"));		
		pvt = kf.generatePrivate(ks);
	}
	
	byte[] readResource(String resource) throws IOException
	{
		InputStream in = getClass().getResourceAsStream(resource);
		try {
			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			int n;
			byte[] buf = new byte[8192];
			while( (n = in.read(buf, 0, buf.length))!= -1)
				bos.write(buf, 0, n);
			return bos.toByteArray();
		} finally
		{
			in.close();
		}
	}

	@Test
	public void test() throws Exception
	{
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		OutputStreamWriter out = new OutputStreamWriter(new PKEncryptOutputStream(bos, pub));
		String plainText = "Hola, mundo!";
		out.write(plainText);
		out.close();

		InputStreamReader r = new InputStreamReader(new PKDecryptInputStream(new ByteArrayInputStream(bos.toByteArray()), pvt));
		char[] buf = new char[8192];
		int n = r.read(buf);
		r.close();
		String s = new String(buf, 0, n);
		Assert.assertEquals(plainText, s);
	}
}
