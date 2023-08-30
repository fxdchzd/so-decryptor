package symetricks.sodecryptor;

import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.ptr.PointerByReference;
import org.apache.commons.codec.binary.Base64;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: java -jar <pathofdecrypterjarfile> <pathofsoclientjar>");
            return;
        }
        System.out.println("4242s presents ;)");
        byte[] key = Base64.decodeBase64("CAIAABBmAAAgAAAAanwzX9MspnMKo6ru8MM7jUdkSRtRnXvvJXCndqaDEYg=");
        byte[] iv = Base64.decodeBase64("ZY5L+FAj2hvtJNvW3nsiJw==");
        PointerByReference hCryptProv = new PointerByReference();
        PointerByReference hKey = new PointerByReference();

        if (!Wincrypt.INSTANCE.CryptAcquireContextA(hCryptProv, null, Wincrypt.MS_ENH_RSA_AES_PROV_W, Wincrypt.PROV_RSA_AES, Wincrypt.CRYPT_VERIFYCONTEXT)) {
            System.err.println("Error Code: " + Kernel32.INSTANCE.GetLastError() + " Line: " + Thread.currentThread().getStackTrace()[1].getLineNumber());
            return;
        }

        if (!Wincrypt.INSTANCE.CryptImportKey(hCryptProv.getValue(), key, 44, 0, 0, hKey)) {
            System.err.println("Error Code: " + Kernel32.INSTANCE.GetLastError() + " Line: " + Thread.currentThread().getStackTrace()[1].getLineNumber());
            return;
        }

        if (!Wincrypt.INSTANCE.CryptSetKeyParam(hKey.getValue(), Wincrypt.KP_IV, iv, 0)) {
            System.err.println("Error Code: " + Kernel32.INSTANCE.GetLastError() + " Line: " + Thread.currentThread().getStackTrace()[1].getLineNumber());
            return;
        }

        String jarPath = args[0];
        File encryptedJar = new File(jarPath);
        if (!encryptedJar.exists() && !encryptedJar.isFile() && !encryptedJar.getName().endsWith(".jar")) {
            System.err.println("Theres no jar file");
            return;
        }
        JarOutputStream jarOutputStream = new JarOutputStream(new FileOutputStream(encryptedJar.getParentFile().getAbsolutePath() + "\\so_decrypted.jar"));
        JarInputStream jarFile = new JarInputStream(new FileInputStream(encryptedJar), true);
        JarEntry object = null;
        ByteArrayOutputStream outputStream = null;
        while ((object = jarFile.getNextJarEntry()) != null) {
            if (!object.getName().endsWith(".class")) continue;
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while (true) {
                final int qwe = jarFile.read();
                if (qwe == -1) {
                    break;
                }
                baos.write(qwe);
            }
            byte[] jarBytes = baos.toByteArray();
            int[] fileSize = {jarBytes.length};
            System.out.println("Decrypting " + object.getName());
            if (!Wincrypt.INSTANCE.CryptDecrypt(hKey.getValue(), 0, true, 0, jarBytes, fileSize)) {
                System.err.println("Error Code: " + Kernel32.INSTANCE.GetLastError() + " Line: " + Thread.currentThread().getStackTrace()[1].getLineNumber());
                return;
            }
            String Magic_Number = String.format("%02X%02X%02X%02X", jarBytes[0], jarBytes[1], jarBytes[2], jarBytes[3]);
            System.out.println("Magic Number: " + Magic_Number);
            if (!Magic_Number.equals("CAFEBABE")) {
                System.err.println("Error: magic number is wrong" + " Line: " + Thread.currentThread().getStackTrace()[1].getLineNumber());
                return;
            }

            JarEntry decryptedClassEntry = new JarEntry(object.getName());
            jarOutputStream.putNextEntry(decryptedClassEntry);
            jarOutputStream.write(jarBytes);
            baos.close();
        }

        jarFile.close();
        jarOutputStream.close();

        System.out.println("SonOyuncu jar file decrypted successfully");
        System.out.println("Notice: im lazy ass fuck for include pack.png to decrypted.jar file do it yourself bro. - 4242s");
        if (!Wincrypt.INSTANCE.CryptDestroyKey(hKey.getValue())) {
            System.err.println("Error Code: " + Kernel32.INSTANCE.GetLastError() + " Line: " + Thread.currentThread().getStackTrace()[1].getLineNumber());
            return;
        }

        if (!Wincrypt.INSTANCE.CryptReleaseContext(hCryptProv.getValue(), 0)) {
            System.err.println("Error Code: " + Kernel32.INSTANCE.GetLastError() + " Line: " + Thread.currentThread().getStackTrace()[1].getLineNumber());
            return;
        }
    }
}
