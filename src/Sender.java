/* Import the following libraries */
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.io.*;
import java.security.*;
import static java.nio.charset.StandardCharsets.UTF_8;

public class Sender {

    /* This function generates the Private and Public keys*/
    private static void generatePair() throws Exception{
        //Create a key generator object
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        //Create a KeyPair object
        KeyPair kpair = kpg.genKeyPair();

        //Retreive the public key and write to a file
        byte[] publicKeyBytes = kpair.getPublic().getEncoded();
        System.out.println("Generating Public Key . . .");
        FileOutputStream fos = new FileOutputStream("publicKeyA");
        fos.write(publicKeyBytes);
        fos.close();

        //Retreive the private key and write to a file
        byte[] privateKeyBytes = kpair.getPrivate().getEncoded();
        System.out.println("Generating Private Key. . .");
        fos = new FileOutputStream("privateKeyA");
        fos.write(privateKeyBytes);
        fos.close();
    }

    /*This method does the MAC authentication */
    private static void generateMAC() throws Exception {
        //Read the MAC key file
        byte[] keyb = Files.readAllBytes(Paths.get("MAC Key"));
        //Create the key
        SecretKey skey = new SecretKeySpec(keyb, "HmacSHA256" );

        //Initializing the Mac object
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(skey);

        //Read in the key file
        try (FileInputStream in = new FileInputStream("MAC Key")) {
            //Process and create the MAC
            byte[] macb = processFile(mac, in);
            Base64.Encoder encoder = Base64.getMimeEncoder();

            //System.out.println("MAC Key" + ": " + encoder.encodeToString(macb));
            String macString = encoder.encodeToString((macb));

            //Run the method to verify MAC
            verifyMAC("MAC Output B", macString);
        }

    }

    /*Function to verify the two MAC*/
    private static void verifyMAC(String fileName, String MACstring) throws Exception {
        //Reads in the Mac inside of the given MAC output file
        FileReader macFile = new FileReader(fileName);
        char [] macText = new char[2048];
        macFile.read(macText);
        String macString = new String(macText);

        //Compares the two MAC
        if (macString.trim().equals(MACstring)){
            System.out.println("MAC Matched!");
        }
        else
        {
            System.out.println("MAC Mismatched!");
        }

    }

    /*Function to create a MAC key for the encrypted message*/
    private static void createMACKey () throws Exception {
        //Creating a KeyGenerator object
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");

        //Creating a SecureRandom object
        SecureRandom secRandom = new SecureRandom();

        //Initializing the KeyGenerator
        keyGen.init(secRandom);

        //Creating/Generating a key
        Key macKey = keyGen.generateKey();

        //Write the MAC key to a file
        try (FileOutputStream out = new FileOutputStream("MAC Key")) {
            out.write(macKey.getEncoded());
        }

        //Initializing the Mac object
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);

        try (FileInputStream in = new FileInputStream("MAC Key")) {
            //Create the MAC for the message
            byte[] macb = processFile(mac, in);
            Base64.Encoder encoder = Base64.getMimeEncoder();
            String macResult = encoder.encodeToString(macb);
            //System.out.println(macResult);

            //Write the MAC result to a file
            FileWriter macOut = new FileWriter("MAC Output A");
            macOut.write(macResult);
            macOut.close();
        }

        System.out.println("MAC Output created \n");
    }

    /*Method that will process the MAC*/
    private static byte[] processFile(Mac mac, FileInputStream in) throws java.io.IOException {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            mac.update(ibuf, 0, len);
        }
        return mac.doFinal();
    }

    /*Function to get the public key for initialization*/
    private static PublicKey getPubKeyFromFile(String fileName) throws Exception{
        //System.out.println("Getting Public Key...");
        //instantiate a key
        PublicKey pk = null;
        File f = new File(fileName);

        //Read the file into bytes
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        //Retrieve the key with the specs
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        pk = kf.generatePublic(spec);
        //System.out.println("Done...");
        return pk;
    }

    private static PrivateKey getPrivKeyFromFile(String fileName) throws Exception{
        //System.out.println("Getting Private Key...");
        //instantiate a key
        PrivateKey pk = null;
        File f = new File(fileName);

        //Read the file into bytes
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        //Retrieve the key with the specs
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        pk = kf.generatePrivate(spec);
        //System.out.println("Done...");
        return pk;
    }

    /*Function that encrypts the message using AES*/
    private static void AESencrypt() throws Exception {
        System.out.print("Enter Message: ");
        message = input.nextLine();
        System.out.print("Enter secret key: ");
        secretKey = input.nextLine();

        //Pass message and secret key to AES class encrypt method
        String encryptMessage = AES.encrypt(message, secretKey);
        //Print to file
        FileWriter fos = new FileWriter("MessageA");
        fos.write(encryptMessage);
        fos.close();
    }

    /*Function that encrypts the secret key with RSA*/
    private static String RSAencrypt(String secretKey, PublicKey publicKey) throws Exception {
        //Create a cipher object
        Cipher encryptCipher = Cipher.getInstance("RSA");
        //initialize the cipher to encrypt with public key
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        //Initialize byte array to the secret key
        byte[] cipherText = encryptCipher.doFinal(secretKey.getBytes(UTF_8));

        //Return the cipher secret key as a string
        return Base64.getMimeEncoder().withoutPadding().encodeToString(cipherText);
    }

    /*Function the decrypts the secret key with RSA*/
    private static String RSAdecrypt(String cipherKey, PrivateKey privateKey) throws Exception {
        //Initialize byte array to the ciphered secret key
        byte[] bytes = Base64.getMimeDecoder().decode(cipherKey);

        //Create cipher object
        Cipher decryptCipher = Cipher.getInstance("RSA");
        //Initialize the cipher to decrypt with private key
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        //Return the decrypted key as a string
        return new String(decryptCipher.doFinal(bytes), UTF_8);
    }

    /*Function that decrypt the message with AES*/
    private static void AESdecrypt () throws Exception {
        //Read in the message from file and set to String
        FileReader fis = new FileReader("MessageB");
        char [] text = new char [4096];
        fis.read(text);
        String readMessage = new String(text);
        //System.out.println(readMessage);

        //Initialize string after running decrypt() from AES class
        String decryptMessage = AES.decrypt(readMessage, givenKey);
        System.out.println(decryptMessage);

        //Write the deciphered message aka original message out
        FileWriter fos = new FileWriter("OutputMessageB");
        fos.write(decryptMessage);
        fos.close();
    }

    /*Main function*/
    public static void main(String[] args) throws Exception{
        //User input for switch case
        int choice = 0;
        System.out.println("Options: \n" +
                "1) Generate a new pair of Keys \n" +
                "2) Send a message \n" +
                "3) Read a message \n" +
                "-1) Quit");
        //Continue to run until -1 is entered
        while(choice != -1){
            System.out.print ("Enter an option: ");
            choice = input.nextInt();
            input.nextLine();

            //Initialized all the keys from the files
            publicKeyA = getPubKeyFromFile("publicKeyA");
            publicKeyB = getPubKeyFromFile("publicKeyB");
            privateKeyA = getPrivKeyFromFile("privateKeyA");
            switch (choice){
                case 1:
                    //Generate new keys
                    generatePair();
                    break;
                case 2:
                    AESencrypt();
                    //Write the Secret key to file
                    FileWriter fos = new FileWriter ("SecretKey");
                    fos.write(RSAencrypt(secretKey, publicKeyB));
                    fos.close();
                    createMACKey();
                    break;
                case 3:
                    /* This will read and decrypt the given secret Key*/
                    FileReader fin = new FileReader("SecretKey");
                    char [] text = new char[2048];
                    fin.read(text);
                    String readKey = new String(text);
                    givenKey = RSAdecrypt(readKey, privateKeyA);
                    //System.out.println("RSAdecrypt = " + givenKey);
                    AESdecrypt();

                    //Read the Original Message and verify the MAC
                    fin = new FileReader("OutputMessageA");
                    char [] MACtext = new char[4096];
                    fin.read(MACtext);
                    //String readOut = new String(MACtext);
                    //System.out.println(readOut);
                    generateMAC();
                    break;
                case -1:
                    //Ends the program
                    System.out.println("Quitting. . .");
                    break;
                default:
                    //If an integer is entered that isn't one of the cases, result to default message
                    System.out.println("Invalid Choice");
                    break;


            }
        }

    }

    /*Global Variables needed for the program*/
    static Scanner input = new Scanner(System.in);
    static protected PublicKey publicKeyA;
    static protected PublicKey publicKeyB;
    static protected PrivateKey privateKeyA;
    static protected String secretKey;
    static protected String givenKey;
    static protected String message;
}